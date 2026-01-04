import os
import time
import json
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

    # ---------- Database ----------
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
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            product_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        )
        """)
        db.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id TEXT NOT NULL,
            paypal_order_id TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            token TEXT,
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

    # ✅ Bucket-Fix: akzeptiert R2_BUCKET_PRIVATE (neu) oder R2_BUCKET_ORIGINALS (alt)
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

    # ✅ Frontend Base URL (für PayPal return_url/cancel_url)
    # (bleibt drin, auch wenn wir return/cancel jetzt nicht mehr setzen)
    FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "").strip() or os.getenv("FRONTEND_ORIGIN", "").strip()

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

        # ✅ KORREKTUR:
        # Für PayPal JS-SDK Buttons (Safari In-Context Checkout) lassen wir
        # return_url / cancel_url weg, damit PayPal nicht unnötig in Redirect/App-Switch geht.
        payload = {
            "intent": "CAPTURE",
            "purchase_units": [{
                "reference_id": product_id,
                "amount": {"currency_code": currency, "value": str(amount)}
            }],
            "application_context": {
                "user_action": "PAY_NOW"
            }
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
            "INSERT OR IGNORE INTO orders(product_id, paypal_order_id, status, token, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (product_id, paypal_order_id, "CREATED", None, now, now)
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
        if not paypal_order_id:
            return jsonify({"error": "orderID required"}), 400

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

        db = get_db()
        row = db.execute("SELECT token FROM orders WHERE paypal_order_id = ?", (paypal_order_id,)).fetchone()
        now = int(time.time())

        if row and row["token"]:
            return jsonify({"status": "COMPLETED", "product_id": product_id, "token": row["token"]})

        access_token = secrets.token_urlsafe(24)
        db.execute(
            "INSERT INTO tokens(token, product_id, created_at, revoked) VALUES (?, ?, ?, 0)",
            (access_token, product_id, now)
        )
        db.execute(
            "UPDATE orders SET status=?, token=?, updated_at=? WHERE paypal_order_id=?",
            ("COMPLETED", access_token, now, paypal_order_id)
        )
        db.commit()

        return jsonify({"status": "COMPLETED", "product_id": product_id, "token": access_token})

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

        db = get_db()
        row = db.execute(
            "SELECT * FROM tokens WHERE token=? AND product_id=? AND revoked=0",
            (token, product_id)
        ).fetchone()
        if not row:
            return jsonify({"error": "invalid token"}), 403

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
        return Response(
            stream(),
            headers={
                "Content-Disposition": f'{disposition}; filename="{key}"',
                "Content-Type": obj.get("ContentType", "application/octet-stream"),
                "Cache-Control": "no-store"
            }
        )

    return app

app = create_app()
