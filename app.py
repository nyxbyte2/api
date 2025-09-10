import os, re
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)

# ── Config via env vars ─────────────────────────────────────────────
AUTH_TOKEN   = os.getenv("AUTH_TOKEN", "")  # shared secret for both endpoints
ALLOWED_IPS  = set([s.strip() for s in os.getenv("ALLOWED_IPS", "").split(",") if s.strip()])
DATABASE_URL = os.getenv("DATABASE_URL")  # Neon connection string (postgresql://...)

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# ── DB bootstrap ────────────────────────────────────────────────────
with engine.begin() as conn:
    conn.execute(text("""
    CREATE TABLE IF NOT EXISTS sms_messages (
        id SERIAL PRIMARY KEY,
        sms_id TEXT,
        sender TEXT,
        recipient TEXT,
        message TEXT,
        norm_recipient TEXT,
        received_at TIMESTAMPTZ DEFAULT NOW()
    );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_norm_recipient ON sms_messages(norm_recipient);"))

def normalize_msisdn(s: str) -> str:
    if not s: return ""
    digits = "".join(ch for ch in s if ch.isdigit())
    if digits.startswith("00"):
        digits = digits[2:]
    return digits

def client_ip(req):
    # Render/most PaaS put original IP in X-Forwarded-For
    xff = (req.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return xff or req.remote_addr or ""

def require_token(req):
    tok = req.args.get("token") or req.headers.get("X-Auth-Token") or ""
    return (AUTH_TOKEN == "" and tok == "") or (tok == AUTH_TOKEN)

@app.route("/health", methods=["GET"])
def health():
    return "OK", 200

# ── Provider webhook: POST/GET /sms/incoming ────────────────────────
@app.route("/sms/incoming", methods=["POST", "GET"])
def sms_incoming():
    if not require_token(request):
        return "Forbidden", 403

    src = client_ip(request)
    if ALLOWED_IPS and src not in ALLOWED_IPS:
        return "Forbidden", 403

    payload = request.form.to_dict() or request.args.to_dict() or (request.get_json(silent=True) or {})
    sender  = (payload.get("from") or "").strip()
    to      = (payload.get("to") or "").strip()
    message = (payload.get("message") or "").strip()
    sms_id  = (payload.get("sms_id") or "").strip()

    if not to or not message:
        return "Bad Request", 400

    norm = normalize_msisdn(to)
    with engine.begin() as conn:
        conn.execute(
            text("""INSERT INTO sms_messages (sms_id, sender, recipient, message, norm_recipient)
                    VALUES (:sms_id, :sender, :recipient, :message, :norm)"""),
            dict(sms_id=sms_id, sender=sender, recipient=to, message=message, norm=norm)
        )
    return "OK", 200

# ── Your bot can read latest SMS for a number: GET /sms/latest?to= ──
@app.route("/sms/latest", methods=["GET"])
def sms_latest():
    if not require_token(request):
        return jsonify({"error": "forbidden"}), 403

    to = (request.args.get("to") or "").strip()
    norm = normalize_msisdn(to)
    if not norm:
        return jsonify({"found": False, "message": None})

    with engine.begin() as conn:
        row = conn.execute(
            text("""SELECT message FROM sms_messages
                   WHERE norm_recipient = :norm
                   ORDER BY id DESC LIMIT 1"""),
            {"norm": norm}
        ).fetchone()

    return jsonify({"to": to, "found": bool(row), "message": row[0] if row else None})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "3000")))
