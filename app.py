import os
import time
import secrets
import sqlite3
from flask import Flask, jsonify, request, Response, g
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

DB_PATH = "app.db"

def create_app():
    app = Flask(__name__)

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
        region_name="auto"
    )

    BUCKET = os.environ.get("R2_BUCKET_ORIGINALS")

    # ---------- Routes ----------
    @app.route("/health")
    def health():
        return {"ok": True}

    @app.route("/api/dev/grant", methods=["POST"])
    def grant():
        data = request.get_json(force=True)
        product_id = data.get("product_id")
        if not product_id:
            return {"error": "product_id missing"}, 400

        token = secrets.token_urlsafe(24)
        db = get_db()
        db.execute(
            "INSERT INTO tokens (token, product_id, created_at) VALUES (?, ?, ?)",
            (token, product_id, int(time.time()))
        )
        db.commit()
        return {"token": token}

    @app.route("/api/download")
    def download():
        token = request.args.get("token")
        product_id = request.args.get("product_id")
        key = request.args.get("key")

        if not token or not product_id or not key:
            return {"error": "missing params"}, 400

        db = get_db()
        row = db.execute(
            "SELECT * FROM tokens WHERE token=? AND product_id=? AND revoked=0",
            (token, product_id)
        ).fetchone()

        if not row:
            return {"error": "invalid token"}, 403

        try:
            obj = s3.get_object(Bucket=BUCKET, Key=key)
        except ClientError:
            return {"error": "file not found"}, 404

        def stream():
            while True:
                chunk = obj["Body"].read(1024 * 512)
                if not chunk:
                    break
                yield chunk

        return Response(
            stream(),
            headers={
                "Content-Disposition": f'attachment; filename="{key}"',
                "Content-Type": obj.get("ContentType", "application/octet-stream")
            }
        )

    return app

app = create_app()
