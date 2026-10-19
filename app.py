import os
import bcrypt
from flask import Flask, request, session, jsonify, send_file, after_this_request
from db import get_conn, init_db

import uuid
from functools import wraps
from werkzeug.utils import secure_filename
from crypto_core import encrypt_file, decrypt_file

import json

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "ganti-ini-saat-deploy")
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024














os.makedirs("storage", exist_ok=True)
os.makedirs("tmp", exist_ok=True)
init_db()


ALGOS = [("AES", "OFB"), ("DES", "OFB"), ("RC4", "NONE")]
KINDS = {"KTM", "DOCUMENT", "VIDEO"}


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify(error="Silakan login dulu"), 401
        return f(*args, **kwargs)
    return wrapper


def password_is_valid(user_id, password):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    return bool(row) and bcrypt.checkpw(password.encode("utf-8"), row["password_hash"])


def save_encrypted(user_id, kind, original_name, src_path, password):
    token = uuid.uuid4().hex
    enc_paths = []
    try:
        for algo, mode in ALGOS:
            out = os.path.join("storage", f"{token}.{algo.lower()}.enc")
            encrypt_file(src_path, out, password, algo, mode)
            enc_paths.append((algo, mode, out))

        with get_conn() as conn:
            cur = conn.execute(
                "INSERT INTO items (user_id, kind, original_name) VALUES (?, ?, ?)",
                (user_id, kind, original_name),
            )
            item_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO item_copies (item_id, algorithm, mode, enc_path) VALUES (?, ?, ?, ?)",
                [(item_id, a, m, p) for a, m, p in enc_paths],
            )
        return item_id
    except Exception:
        for _, _, p in enc_paths:
            if os.path.exists(p):
                os.remove(p)
        raise

















@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if len(username) < 3 or len(password) < 8:
        return jsonify(error="Username min 3 karakter, password min 8 karakter"), 400

    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    with get_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pw_hash),
            )
        except Exception:
            return jsonify(error="Username sudah dipakai"), 409

    return jsonify(message="Registrasi berhasil"), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

    if not row or not bcrypt.checkpw(password.encode("utf-8"), row["password_hash"]):
        return jsonify(error="Username atau password salah"), 401

    session["user_id"] = row["id"]
    return jsonify(message="Login berhasil")


@app.post("/logout")
def logout():
    session.clear()
    return jsonify(message="Logout berhasil")




@app.post("/upload")
@login_required
def upload():
    kind = (request.form.get("kind") or "").upper()
    password = request.form.get("password") or ""
    file = request.files.get("file")

    if kind not in KINDS or not file or not file.filename:
        return jsonify(error="kind (KTM/DOCUMENT/VIDEO) dan file wajib diisi"), 400
    if not password_is_valid(session["user_id"], password):
        return jsonify(error="Password salah"), 401

    token = uuid.uuid4().hex
    tmp_path = os.path.join("tmp", token)
    file.save(tmp_path)

    enc_paths = []
    try:
        for algo, mode in ALGOS:
            out = os.path.join("storage", f"{token}.{algo.lower()}.enc")
            encrypt_file(tmp_path, out, password, algo, mode)
            enc_paths.append((algo, mode, out))

        with get_conn() as conn:
            cur = conn.execute(
                "INSERT INTO items (user_id, kind, original_name) VALUES (?, ?, ?)",
                (session["user_id"], kind, secure_filename(file.filename)),
            )
            item_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO item_copies (item_id, algorithm, mode, enc_path) VALUES (?, ?, ?, ?)",
                [(item_id, a, m, p) for a, m, p in enc_paths],
            )
    except Exception:
        for _, _, p in enc_paths:
            if os.path.exists(p):
                os.remove(p)
        raise
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    return jsonify(message="Upload & enkripsi berhasil", item_id=item_id), 201






@app.post("/download/<int:item_id>/<algo>")
@login_required
def download(item_id, algo):
    algo = algo.upper()
    password = request.form.get("password") or ""

    if algo not in {"AES", "DES", "RC4"}:
        return jsonify(error="Algoritma harus AES, DES, atau RC4"), 400
    if not password_is_valid(session["user_id"], password):
        return jsonify(error="Password salah"), 401

    with get_conn() as conn:
        row = conn.execute(
            """SELECT i.original_name, c.enc_path
               FROM items i JOIN item_copies c ON c.item_id = i.id
               WHERE i.id = ? AND i.user_id = ? AND c.algorithm = ?""",
            (item_id, session["user_id"], algo),
        ).fetchone()

    if not row:
        return jsonify(error="Data tidak ditemukan"), 404

    out_path = os.path.join("tmp", uuid.uuid4().hex)
    try:
        decrypt_file(row["enc_path"], out_path, password)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    @after_this_request
    def cleanup(response):
        if os.path.exists(out_path):
            os.remove(out_path)
        return response

    return send_file(out_path, as_attachment=True,
                     download_name=row["original_name"])






PROFILE_FIELDS = ["nama_lengkap", "nrp", "no_hp", "riwayat_medis", "domisili"]


@app.post("/profile")
@login_required
def save_profile():
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""

    if not password_is_valid(session["user_id"], password):
        return jsonify(error="Password salah"), 401

    profile = {k: (data.get(k) or "").strip() for k in PROFILE_FIELDS}
    if not profile["nama_lengkap"] or not profile["nrp"]:
        return jsonify(error="nama_lengkap dan nrp wajib diisi"), 400

    tmp_path = os.path.join("tmp", uuid.uuid4().hex)
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(profile, f, ensure_ascii=False)
        item_id = save_encrypted(session["user_id"], "PROFILE",
                                 "profile.json", tmp_path, password)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    return jsonify(message="Data pribadi tersimpan terenkripsi", item_id=item_id), 201




@app.get("/items")
@login_required
def list_items():
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT i.id, i.kind, i.original_name, i.created_at,
                      GROUP_CONCAT(c.algorithm) AS algorithms
               FROM items i JOIN item_copies c ON c.item_id = i.id
               WHERE i.user_id = ?
               GROUP BY i.id ORDER BY i.id""",
            (session["user_id"],),
        ).fetchall()
    return jsonify(items=[dict(r) for r in rows])


@app.post("/profile/<int:item_id>/<algo>")
@login_required
def read_profile(item_id, algo):
    algo = algo.upper()
    password = request.form.get("password") or ""

    if algo not in {"AES", "DES", "RC4"}:
        return jsonify(error="Algoritma harus AES, DES, atau RC4"), 400
    if not password_is_valid(session["user_id"], password):
        return jsonify(error="Password salah"), 401

    with get_conn() as conn:
        row = conn.execute(
            """SELECT c.enc_path
               FROM items i JOIN item_copies c ON c.item_id = i.id
               WHERE i.id = ? AND i.user_id = ? AND i.kind = 'PROFILE'
                     AND c.algorithm = ?""",
            (item_id, session["user_id"], algo),
        ).fetchone()
    if not row:
        return jsonify(error="Data tidak ditemukan"), 404

    out_path = os.path.join("tmp", uuid.uuid4().hex)
    try:
        decrypt_file(row["enc_path"], out_path, password)
        with open(out_path, "r", encoding="utf-8") as f:
            profile = json.load(f)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    finally:
        if os.path.exists(out_path):
            os.remove(out_path)

    return jsonify(profile=profile)










if __name__ == "__main__":
    app.run(debug=True)


