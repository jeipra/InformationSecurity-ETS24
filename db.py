import sqlite3

DB_PATH = "oprec.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,          -- bcrypt
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS items (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    kind          TEXT NOT NULL CHECK (kind IN ('PROFILE','KTM','DOCUMENT','VIDEO')),
    original_name TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS item_copies (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id   INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    algorithm TEXT NOT NULL CHECK (algorithm IN ('AES','DES','RC4')),
    mode      TEXT NOT NULL,              -- OFB / CFB / NONE
    enc_path  TEXT NOT NULL,              -- lokasi file .enc di storage/
    UNIQUE (item_id, algorithm)
);

CREATE TABLE IF NOT EXISTS access_requests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id  INTEGER NOT NULL REFERENCES users(id),
    owner_id      INTEGER NOT NULL REFERENCES users(id),
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','approved','rejected')),
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (requester_id, owner_id)
);

-- Created when the owner approves a request (requirement 2). The random
-- symmetric key itself is NOT stored here: only its SHA-256 fingerprint.
-- Wrapping the key with asymmetric encryption (req. 3) and storing it
-- securely (req. 4) are done elsewhere.
CREATE TABLE IF NOT EXISTS shares (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id      INTEGER NOT NULL UNIQUE
                    REFERENCES access_requests(id) ON DELETE CASCADE,
    key_fingerprint TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One copy of each of the owner's items, encrypted under the share key.
CREATE TABLE IF NOT EXISTS share_items (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id  INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    item_id   INTEGER NOT NULL REFERENCES items(id),
    enc_path  TEXT NOT NULL,
    UNIQUE (share_id, item_id)
);
"""

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)
