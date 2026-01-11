import os
import time
import json
import base64
import hmac
import hashlib
import sqlite3
import requests

from flask import Flask, jsonify, request, Response, g
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

DB_PATH = "app.db"

def create_app():
    app = Flask(__name__)

    # --------------------------------------------------
    # CORS
    # --------------------------------------------------
    @app.after_request
    def add_cors(resp):
        origin = request.headers.get("Origin")
        allowed = os.getenv("FRONTEND_ORIGIN", "").strip()

        if allowed == "*":
            resp.headers["Access-Control-Allow-Origin"] = origin or "*"
        elif allowed:
            resp.headers["Access-Control-Allow-Origin"] = allowed
        else:
            if origin and origin.startswith("http://localhost:"):
                resp.headers["Access-Control-Allow-Origin"] = origin

        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    @app.route("/health")
    def health():
        return {"ok": True}

    # --------------------------------------------------
    # Database
    # --------------------------------------------------
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_):
        db = g.pop("db", None)
        if db:
            db.close()

    def init_db():
        db = sqlite3.connect(DB_PATH)
        db.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id TEXT NOT NULL,
            paypal_order_id TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
        """)
        db.commit()
        db.close()

    init_db()

    # --------------------------------------------------
    # R2 / S3 Client
    # --------------------------------------------------
    s3 = boto3.client(
        "s3",
        endpoint_url=os.environ.get("R2_ENDPOINT"),
        aws_access_key_id=os.environ.get("R2_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("R2_SECRET_ACCESS_KEY"),
        config=Config(signature_version="s3v4"),
        region_name="auto",
    )

    BUCKET_ORIGINALS = (
        os.environ.get("R2_BUCKET_PRIVATE")
        or os.environ.get("R2_BUCKET_ORIGINALS")
        or "galerie-originals"
    )

    # --------------------------------------------------
    # PayPal Config
    # --------------------------------------------------
    PAYPAL_MODE = os.getenv("PAYPAL_MODE", "live").strip()
    PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "").strip()
    PAYPAL_SECRET = os.getenv("PAYPAL_SECRET", "").strip()

    PAYPAL_BASE = (
        "https://api-m.paypal.com"
        if PAYPAL_MODE == "live"
        else "https://api-m.sandbox.paypal.com"
    )

    def paypal_access_token():
        if not PAYPAL_CLIENT_ID or not PAYPAL_SECRET:
            raise RuntimeError("PayPal credentials missing")

        r = requests.post(
            f"{PAYPAL_BASE}/v1/oauth2/token",
            auth=(PAYPAL_CLIENT_ID, PAYPAL_SECRET),
            headers={"Accept": "application/json"},
            data={"grant_type": "client_credentials"},
            timeout=20
        )
        r.raise_for_status()
        return r.json()["access_token"]

    # --------------------------------------------------
    # Stateless Token (HMAC)
    # --------------------------------------------------
    TOKEN_SECRET = os.getenv("TOKEN_SECRET", "").strip()
    TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", str(30 * 24 * 60 * 60)))

    def _b64url_encode(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    def _b64url_decode(s: str) -> bytes:
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode((s + pad).encode())

    def mint_download_token(product_id: str, key: str) -> str:
        now = int(time.time())
        payload = {
            "pid": product_id,
            "key": key,
            "exp": now + TOKEN_TTL_SECONDS
        }
        payload_b = json.dumps(payload, separators=(",", ":")).encode()
        payload_b64 = _b64url_encode(payload_b)

        sig = hmac.new(
            TOKEN_SECRET.encode(),
            payload_b64.encode(),
            hashlib.sha256
        ).digest()

        return f"{payload_b64}.{_b64url_encode(sig)}"

    def verify_download_token(token: str, product_id: str, key: str):
        try:
            payload_b64, sig_b64 = token.split(".", 1)
        except ValueError:
            return False, "bad format"

        expected_sig = hmac.new(
            TOKEN_SECRET.encode(),
            payload_b64.encode(),
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(_b64url_encode(expected_sig), sig_b64):
            return False, "bad signature"

        payload = json.loads(_b64url_decode(payload_b64))
        if payload["exp"] < int(time.time()):
            return False, "expired"

        if payload["pid"] != product_id or payload["key"] != key:
            return False, "mismatch"

        return True, payload

    # --------------------------------------------------
    # PayPal: CREATE ORDER
    # --------------------------------------------------
    @app.route("/api/paypal/create-order", methods=["POST", "OPTIONS"])
    def paypal_create_order():
        if request.method == "OPTIONS":
            return ("", 204)

        data = request.get_json(force=True)
        product_id = data.get("product_id")
        amount = data.get("amount")
        currency = data.get("currency", "EUR")

        token = paypal_access_token()

        payload = {
            "intent": "CAPTURE",
            "purchase_units": [{
                "reference_id": product_id,
                "amount": {
                    "currency_code": currency,
                    "value": str(amount)
                }
            }]
        }

        r = requests.post(
            f"{PAYPAL_BASE}/v2/checkout/orders",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            data=json.dumps(payload),
            timeout=25
        )
        r.raise_for_status()

        order = r.json()
        paypal_order_id = order["id"]

        now = int(time.time())
        db = get_db()
        db.execute(
            "INSERT OR IGNORE INTO orders (product_id, paypal_order_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (product_id, paypal_order_id, "CREATED", now, now)
        )
        db.commit()

        return jsonify({"orderID": paypal_order_id})

    # --------------------------------------------------
    # PayPal: CAPTURE ORDER
    # --------------------------------------------------
    @app.route("/api/paypal/capture-order", methods=["POST", "OPTIONS"])
    def paypal_capture_order():
        if request.method == "OPTIONS":
            return ("", 204)

        data = request.get_json(force=True)
        order_id = data.get("orderID")
        key = data.get("key")

        token = paypal_access_token()

        r = requests.post(
            f"{PAYPAL_BASE}/v2/checkout/orders/{order_id}/capture",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            timeout=25
        )
        r.raise_for_status()

        result = r.json()
        if result.get("status") != "COMPLETED":
            return jsonify({"error": "not completed"}), 400

        product_id = result["purchase_units"][0]["reference_id"]
        dl_token = mint_download_token(product_id, key)

        now = int(time.time())
        db = get_db()
        db.execute(
            "UPDATE orders SET status=?, updated_at=? WHERE paypal_order_id=?",
            ("COMPLETED", now, order_id)
        )
        db.commit()

        return jsonify({
            "status": "COMPLETED",
            "product_id": product_id,
            "token": dl_token
        })

    # --------------------------------------------------
    # 🔁 BACKWARD COMPATIBILITY (WICHTIG!)
    # --------------------------------------------------
    @app.route("/create-order", methods=["POST", "OPTIONS"])
    def legacy_create_order():
        return paypal_create_order()

    @app.route("/capture-order", methods=["POST", "OPTIONS"])
    def legacy_capture_order():
        return paypal_capture_order()

    # --------------------------------------------------
    # DOWNLOAD
    # --------------------------------------------------
    @app.route("/api/download", methods=["GET", "OPTIONS"])
    def download():
        if request.method == "OPTIONS":
            return ("", 204)

        token = request.args.get("token")
        product_id = request.args.get("product_id")
        key = request.args.get("key")

        ok, _ = verify_download_token(token, product_id, key)
        if not ok:
            return jsonify({"error": "invalid token"}), 403

        obj = s3.get_object(Bucket=BUCKET_ORIGINALS, Key=key)

        def stream():
            while True:
                chunk = obj["Body"].read(1024 * 512)
                if not chunk:
                    break
                yield chunk

        return Response(
            stream(),
            headers={
                "Content-Type": obj.get("ContentType", "application/octet-stream"),
                "Content-Disposition": f'attachment; filename="{key}"',
                "Cache-Control": "no-store"
            }
        )

    return app

app = create_app()
