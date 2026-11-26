"""
Features
  * AES-256, DES, RC4 encrypt/decrypt as modular functions
  * Block-cipher modes: CFB (8-bit segments) and OFB  -> no padding needed
  * Random IV per file, stored in the file header
  * Streaming (chunked) processing -> constant RAM, safe for big videos
  * PBKDF2-HMAC-SHA256 key derivation with a random per-file salt
  * HMAC-SHA256 tag (encrypt-then-MAC) so corruption / wrong password
    is detected instead of silently producing garbage
  * RSA-OAEP key wrapping, so a file's symmetric key can be handed to
    another user over an insecure channel (email, WA) without exposing
    it or the password

Install:  pip install pycryptodome
"""

import hashlib
import hmac
import os
import struct
import time

from Crypto.Cipher import AES, DES, ARC4, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
MAGIC = b"OPRC"                 # identifies our encrypted files
VERSION = 1
CHUNK_SIZE = 1024 * 1024        # 1 MiB per read -> RAM stays tiny
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
TAG_SIZE = 32                   # HMAC-SHA256 output

ALGORITHM_IDS = {"AES": 1, "DES": 2, "RC4": 3}
MODE_IDS = {"NONE": 0, "CFB": 1, "OFB": 2}
ID_TO_ALGORITHM = {v: k for k, v in ALGORITHM_IDS.items()}
ID_TO_MODE = {v: k for k, v in MODE_IDS.items()}

KEY_SIZE = {"AES": 32, "DES": 8, "RC4": 16}   # bytes
IV_SIZE = {"AES": 16, "DES": 8, "RC4": 0}     # bytes (RC4 has no IV)


# ----------------------------------------------------------------------
# 1. Key management
# ----------------------------------------------------------------------
def derive_keys(password, salt, iterations, key_len):
    """
    Stretch a password into TWO independent keys using PBKDF2:
      - enc_key : used by the cipher
      - mac_key : used by HMAC (never reuse the same key for both jobs)
    """
    material = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations,
        dklen=key_len + 32,
    )
    return material[:key_len], material[key_len:]


# ----------------------------------------------------------------------
# 2. Cipher factory (the modular algorithm functions)
# ----------------------------------------------------------------------
def make_cipher(algorithm, mode, key, iv):
    """Return a PyCryptodome cipher object for (algorithm, mode)."""
    if algorithm == "RC4":
        return ARC4.new(key)

    module = AES if algorithm == "AES" else DES

    if mode == "CFB":
        # segment_size=8 means CFB-8: works on any number of bytes,
        # so chunk sizes never have to be multiples of the block size.
        return module.new(key, module.MODE_CFB, iv=iv, segment_size=8)
    if mode == "OFB":
        return module.new(key, module.MODE_OFB, iv=iv)
    raise ValueError("Mode must be CFB or OFB for AES/DES")


def _validate(algorithm, mode):
    if algorithm not in ALGORITHM_IDS:
        raise ValueError("Algorithm must be AES, DES, or RC4")
    if algorithm == "RC4":
        return "NONE"           # stream cipher: no mode
    if mode not in ("CFB", "OFB"):
        raise ValueError("Mode must be CFB or OFB")
    return mode


# ----------------------------------------------------------------------
# 3. File header (stores everything needed to decrypt except password)
# ----------------------------------------------------------------------
def _build_header(algorithm, mode, iterations, salt, iv):
    return (
        MAGIC
        + struct.pack(">BBBI", VERSION, ALGORITHM_IDS[algorithm],
                      MODE_IDS[mode], iterations)
        + salt
        + struct.pack(">B", len(iv))
        + iv
    )


def _read_header(f):
    if f.read(4) != MAGIC:
        raise ValueError("Not an OPREC encrypted file")
    version, alg_id, mode_id, iterations = struct.unpack(">BBBI", f.read(7))
    if version != VERSION:
        raise ValueError("Unsupported file version")
    salt = f.read(SALT_SIZE)
    iv_len = struct.unpack(">B", f.read(1))[0]
    iv = f.read(iv_len)
    algorithm = ID_TO_ALGORITHM[alg_id]
    mode = ID_TO_MODE[mode_id]
    header = _build_header(algorithm, mode, iterations, salt, iv)
    return algorithm, mode, iterations, salt, iv, header


# ----------------------------------------------------------------------
# 4. Streaming encrypt / decrypt
# ----------------------------------------------------------------------
def encrypt_file(in_path, out_path, password, algorithm="AES", mode="OFB",
                 chunk_size=CHUNK_SIZE, iterations=PBKDF2_ITERATIONS):
    """
    Encrypt in_path -> out_path, one chunk at a time.
    File layout:  [header][ciphertext ...][HMAC tag]
    """
    algorithm = algorithm.upper()
    mode = _validate(algorithm, mode.upper())

    salt = get_random_bytes(SALT_SIZE)
    iv = get_random_bytes(IV_SIZE[algorithm]) if IV_SIZE[algorithm] else b""
    enc_key, mac_key = derive_keys(password, salt, iterations,
                                   KEY_SIZE[algorithm])

    cipher = make_cipher(algorithm, mode, enc_key, iv)
    header = _build_header(algorithm, mode, iterations, salt, iv)
    mac = hmac.new(mac_key, header, hashlib.sha256)   # header is authenticated too

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(header)
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            encrypted = cipher.encrypt(chunk)
            mac.update(encrypted)
            fout.write(encrypted)
        fout.write(mac.digest())


def _decrypt_core(in_path, out_path, enc_key, mac_key, chunk_size):
    """
    Shared by decrypt_file() and decrypt_file_with_key(): both already have
    the two keys in hand, one derived from a password, the other unwrapped
    from an RSA-encrypted blob. Writes to a temp file first and only renames
    it after the HMAC tag verifies, so a wrong key or a corrupted file never
    leaves a broken output behind.
    """
    tmp_path = out_path + ".tmp"
    total_size = os.path.getsize(in_path)

    with open(in_path, "rb") as fin:
        algorithm, mode, iterations, salt, iv, header = _read_header(fin)
        cipher = make_cipher(algorithm, mode, enc_key, iv)
        mac = hmac.new(mac_key, header, hashlib.sha256)

        remaining = total_size - len(header) - TAG_SIZE   # ciphertext bytes
        if remaining < 0:
            raise ValueError("File is too short / corrupted")

        with open(tmp_path, "wb") as fout:
            while remaining > 0:
                chunk = fin.read(min(chunk_size, remaining))
                remaining -= len(chunk)
                mac.update(chunk)
                fout.write(cipher.decrypt(chunk))

        stored_tag = fin.read(TAG_SIZE)

    if not hmac.compare_digest(mac.digest(), stored_tag):
        os.remove(tmp_path)
        raise ValueError("Wrong key or file was modified/corrupted")

    os.replace(tmp_path, out_path)


def decrypt_file(in_path, out_path, password, chunk_size=CHUNK_SIZE):
    """Decrypt in_path -> out_path using a key derived from a password."""
    with open(in_path, "rb") as fin:
        algorithm, _, iterations, salt, _, _ = _read_header(fin)
    enc_key, mac_key = derive_keys(password, salt, iterations, KEY_SIZE[algorithm])
    try:
        _decrypt_core(in_path, out_path, enc_key, mac_key, chunk_size)
    except ValueError as e:
        if str(e) == "Wrong key or file was modified/corrupted":
            raise ValueError("Wrong password or file was modified/corrupted")
        raise


def decrypt_file_with_key(in_path, out_path, key_material, chunk_size=CHUNK_SIZE):
    """
    Decrypt in_path -> out_path using key material directly, instead of a
    password. Used for the asymmetric key-sharing flow: the requesting user
    never had the password, they unwrapped this key material from an
    RSA-encrypted blob sent to them over email/WA (see unwrap_key_material).
    """
    with open(in_path, "rb") as fin:
        algorithm, *_ = _read_header(fin)
    key_len = KEY_SIZE[algorithm]
    enc_key, mac_key = key_material[:key_len], key_material[key_len:key_len + 32]
    _decrypt_core(in_path, out_path, enc_key, mac_key, chunk_size)


def get_key_material(enc_path, password):
    """
    Read only the header of an encrypted file and derive the same
    (enc_key + mac_key) bytes decrypt_file() would use, without touching the
    ciphertext body. This is what gets wrapped with a recipient's RSA public
    key for the sharing feature: the recipient ends up with the exact key
    material needed to decrypt this one file, nothing more.
    """
    with open(enc_path, "rb") as f:
        algorithm, _, iterations, salt, _, _ = _read_header(f)
    enc_key, mac_key = derive_keys(password, salt, iterations, KEY_SIZE[algorithm])
    return enc_key + mac_key


# ----------------------------------------------------------------------
# 5. Key sharing: wrap the symmetric key with RSA for out-of-band delivery
# ----------------------------------------------------------------------
# The idea: the symmetric key (or here, the PBKDF2-derived key material) is
# what actually has to reach the requesting user, but it still has to travel
# over an insecure channel (email, WhatsApp, whatever the owner has on
# hand). RSA-OAEP wraps it so only the holder of the matching private key
# can recover it; the ciphertext itself is safe to paste into an email body.
RSA_KEY_BITS = 2048


def generate_rsa_keypair():
    """Generate a fresh RSA-2048 keypair. Returns (public_pem, private_pem)."""
    key = RSA.generate(RSA_KEY_BITS)
    return key.publickey().export_key(), key.export_key()


def wrap_key_material(key_material, public_key_pem):
    """
    Encrypt key_material (bytes, at most 64 bytes for AES here) with the
    recipient's RSA public key using OAEP. RSA-2048-OAEP-SHA256 can wrap up
    to 190 bytes, well above anything this app ever derives, so the key
    material always fits in a single RSA operation (no chunking needed).
    """
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    return cipher.encrypt(key_material)


def unwrap_key_material(wrapped, private_key_pem):
    """Reverse of wrap_key_material(), using the recipient's private key."""
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    try:
        return cipher.decrypt(wrapped)
    except ValueError:
        raise ValueError("Wrong private key or the shared key was corrupted")


# ----------------------------------------------------------------------
# 6. Benchmark (for the analysis report)
# ----------------------------------------------------------------------
def benchmark(path, password="benchmark-pass", iterations=1000):
    """
    Compare AES / DES / RC4 on one file. We use a LOW iteration count
    here so PBKDF2 time doesn't hide the cipher speed.
    """
    size_mb = os.path.getsize(path) / (1024 * 1024)
    configs = [("AES", "CFB"), ("AES", "OFB"), ("DES", "CFB"),
               ("DES", "OFB"), ("RC4", "NONE")]

    print(f"File size: {size_mb:.2f} MB")
    print(f"{'Algorithm':<10}{'Mode':<6}{'Encrypt (s)':>12}{'MB/s':>10}")
    for algorithm, mode in configs:
        enc, dec = path + ".enc", path + ".dec"
        start = time.perf_counter()
        encrypt_file(path, enc, password, algorithm, mode or "OFB",
                     iterations=iterations)
        elapsed = time.perf_counter() - start
        decrypt_file(enc, dec, password)

        with open(path, "rb") as a, open(dec, "rb") as b:    # integrity check
            same = hashlib.sha256(a.read()).digest() == hashlib.sha256(b.read()).digest()
        print(f"{algorithm:<10}{mode:<6}{elapsed:>12.3f}{size_mb / elapsed:>10.1f}"
              f"{'' if same else '   MISMATCH!'}")
        os.remove(enc)
        os.remove(dec)


# ----------------------------------------------------------------------
# Quick self-test:  python crypto_core.py <some_file>
# ----------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python crypto_core.py <file_to_test>")
        sys.exit(1)
    benchmark(sys.argv[1])
