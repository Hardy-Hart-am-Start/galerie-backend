import os
import time
import json
import base64
import hmac
import hashlib
import secrets
import sqlite3
import requests

from flask import Flask, jsonify, request, Response, g
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

DB_PATH = "app.db"

def create_app():
    app = Flask(__name__)

    # ---------- CORS ----------
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

    # ---------- Database (nur noch Orders; Tokens sind stateless) ----------
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

    # ---------- R2 Client ----------
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

    # ---------- PayPal Config ----------
    PAYPAL_MODE = os.getenv("PAYPAL_MODE", "live").strip()
    PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "").strip()
    PAYPAL_SECRET = os.getenv("PAYPAL_SECRET", "").strip()
    PAYPAL_BASE = "https://api-m.paypal.com" if PAYPAL_MODE == "live" else "https://api-m.sandbox.paypal.com"

    def paypal_access_token() -> str:
        if not PAYPAL_CLIENT_ID or not PAYPAL_SECRET:
            raise RuntimeError("PayPal credentials missing")
        r = requests.post(
            f"{PAYPAL_BASE}/v1/oauth2/token",
            auth=(PAYPAL_CLIENT_ID, PAYPAL_SECRET),
            headers={"Accept": "application/json", "Accept-Language": "en_US"},
            data={"grant_type": "client_credentials"},
            timeout=20
        )
        r.raise_for_status()
        return r.json()["access_token"]

    # ---------- Stateless Token (HMAC) ----------
    TOKEN_SECRET = os.getenv("TOKEN_SECRET", "").strip()
    if not TOKEN_SECRET:
        # Hard fail would break deployments; we allow start but downloads will error clearly.
        app.logger.warning("TOKEN_SECRET missing! Set TOKEN_SECRET env var to enable stateless tokens.")

    TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", str(30 * 24 * 60 * 60)))  # default 30 Tage

    def _b64url_encode(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("utf-8")

    def _b64url_decode(s: str) -> bytes:
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

    def mint_download_token(product_id: str, key: str) -> str:
        if not TOKEN_SECRET:
            raise RuntimeError("TOKEN_SECRET missing")
        now = int(time.time())
        payload = {
            "pid": str(product_id),
            "key": str(key),
            "exp": now + TOKEN_TTL_SECONDS
        }
        payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        payload_b64 = _b64url_encode(payload_bytes)
        sig = hmac.new(TOKEN_SECRET.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).digest()
        sig_b64 = _b64url_encode(sig)
        return f"{payload_b64}.{sig_b64}"

    def verify_download_token(token: str, product_id: str, key: str):
        if not TOKEN_SECRET:
            return False, "TOKEN_SECRET missing"
        try:
            payload_b64, sig_b64 = token.split(".", 1)
        except ValueError:
            return False, "bad token format"

        expected_sig = hmac.new(
            TOKEN_SECRET.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256
        ).digest()
        expected_sig_b64 = _b64url_encode(expected_sig)

        if not hmac.compare_digest(expected_sig_b64, sig_b64):
            return False, "bad signature"

        try:
            payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        except Exception:
            return False, "bad payload"

        exp = int(payload.get("exp") or 0)
        if exp <= int(time.time()):
            return False, "expired"

        if str(payload.get("pid")) != str(product_id):
            return False, "product mismatch"

        if str(payload.get("key")) != str(key):
            return False, "key mismatch"

        return True, payload

    # Optional: Product-Katalog prüfen (wenn products.json im Backend liegt)
    # Damit verhindert man, dass jemand für ein bezahltes Produkt eine andere Key errät.
    PRODUCT_KEY_MAP = {}
    try:
        # Wenn du auf Render ein products.json im Repo hast, wird es hier eingelesen.
        with open("products.json", "r", encoding="utf-8") as f:
            raw = json.load(f)
        # Erwartung: { "buy_001": { "originalKey": "..."} , ... }
        for pid, obj in (raw or {}).items():
            ok = (obj or {}).get("originalKey")
            if ok:
                PRODUCT_KEY_MAP[str(pid)] = str(ok)
    except Exception:
        PRODUCT_KEY_MAP = {}

    # ---------- PayPal: Create Order ----------
    @app.route("/api/paypal/create-order", methods=["POST", "OPTIONS"])
    def paypal_create_order():
        if request.method == "OPTIONS":
            return ("", 204)

        data = request.get_json(force=True)
        product_id = (data.get("product_id") or "").strip()
        amount = data.get("amount")
        currency = (data.get("currency") or "EUR").strip()

        if not product_id or amount is None:
            return jsonify({"error": "product_id and amount required"}), 400

        token = paypal_access_token()

        payload = {
            "intent": "CAPTURE",
            "purchase_units": [{
                "reference_id": product_id,
                "amount": {"currency_code": currency, "value": str(amount)}
            }],
            "application_context": {"user_action": "PAY_NOW"}
        }

        r = requests.post(
            f"{PAYPAL_BASE}/v2/checkout/orders",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            data=json.dumps(payload),
            timeout=25
        )
        r.raise_for_status()
        order = r.json()
        paypal_order_id = order["id"]

        now = int(time.time())
        db = get_db()
        db.execute(
            "INSERT OR IGNORE INTO orders(product_id, paypal_order_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (product_id, paypal_order_id, "CREATED", now, now)
        )
        db.commit()

        return jsonify({"orderID": paypal_order_id})

    # ---------- PayPal: Capture Order ----------
    @app.route("/api/paypal/capture-order", methods=["POST", "OPTIONS"])
    def paypal_capture_order():
        if request.method == "OPTIONS":
            return ("", 204)

        data = request.get_json(force=True)
        paypal_order_id = (data.get("orderID") or "").strip()
        key = (data.get("key") or "").strip()  # ✅ kommt vom Frontend (p.originalKey)

        if not paypal_order_id:
            return jsonify({"error": "orderID required"}), 400
        if not key:
            return jsonify({"error": "key required"}), 400

        token = paypal_access_token()
        r = requests.post(
            f"{PAYPAL_BASE}/v2/checkout/orders/{paypal_order_id}/capture",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            timeout=25
        )
        r.raise_for_status()
        result = r.json()

        if result.get("status") != "COMPLETED":
            return jsonify({"error": "not completed", "details": result}), 400

        product_id = result.get("purchase_units", [{}])[0].get("reference_id")
        if not product_id:
            return jsonify({"error": "missing reference_id"}), 500

        # Optional: wenn products.json vorhanden, Key gegen Katalog prüfen
        expected_key = PRODUCT_KEY_MAP.get(str(product_id))
        if expected_key and expected_key != key:
            return jsonify({"error": "key not allowed for product"}), 400

        # ✅ Stateless Token signieren (bindet product_id + key + exp)
        try:
            dl_token = mint_download_token(product_id, key)
        except Exception as e:
            return jsonify({"error": "token mint failed", "details": str(e)}), 500

        now = int(time.time())
        db = get_db()
        db.execute(
            "UPDATE orders SET status=?, updated_at=? WHERE paypal_order_id=?",
            ("COMPLETED", now, paypal_order_id)
        )
        db.commit()

        return jsonify({"status": "COMPLETED", "product_id": product_id, "token": dl_token})

    # ---------- Download / View ----------
    @app.route("/api/download", methods=["GET", "OPTIONS"])
    def download():
        if request.method == "OPTIONS":
            return ("", 204)

        token = (request.args.get("token") or "").strip()
        product_id = (request.args.get("product_id") or "").strip()
        key = (request.args.get("key") or "").strip()
        inline = (request.args.get("inline") or "").strip() == "1"

        if not token or not product_id or not key:
            return jsonify({"error": "missing params"}), 400

        # Optional: wenn Katalog vorhanden, Key prüfen
        expected_key = PRODUCT_KEY_MAP.get(str(product_id))
        if expected_key and expected_key != key:
            return jsonify({"error": "key not allowed for product"}), 403

        ok, info = verify_download_token(token, product_id, key)
        if not ok:
            return jsonify({"error": "invalid token", "details": info}), 403

        try:
            obj = s3.get_object(Bucket=BUCKET_ORIGINALS, Key=key)
        except ClientError:
            return jsonify({"error": "file not found"}), 404

        def stream():
            while True:
                chunk = obj["Body"].read(1024 * 512)
                if not chunk:
                    break
                yield chunk

        disposition = "inline" if inline else "attachment"

        # ✅ Safari-Fix: inline=1 -> Content-Type sicher image/*
        content_type = obj.get("ContentType") or "application/octet-stream"
        if inline and (not content_type.startswith("image/")):
            k = key.lower()
            if k.endswith(".jpg") or k.endswith(".jpeg"):
                content_type = "image/jpeg"
            elif k.endswith(".png"):
                content_type = "image/png"
            elif k.endswith(".webp"):
                content_type = "image/webp"
            elif k.endswith(".gif"):
                content_type = "image/gif"

        return Response(
            stream(),
            headers={
                "Content-Disposition": f'{disposition}; filename="{key}"',
                "Content-Type": content_type,
                "Cache-Control": "no-store"
            }
        )

    return app

app = create_app()
