| Name | NRP |
|---|---|
| Fathiya Nayla Husna Wibowo | 5025241204 |
| Mahirah Yasmin Aulia Mawahib | 5025241095 |
| Jeihan Shawmy Prasetya | 5025241132 |
| Alif Muflih Jauhary | 5025241003 |

# OPREC Portal

A small Flask web app we built for the Information Security ETS (midterm) assignment: a committee open-recruitment (OPREC) portal where applicants submit personal data, an ID card photo, supporting documents and an introduction video, each encrypted with AES-256, DES and RC4 before it touches the disk.

## 1. Scenario

Campus organizations run recruitment ("oprec") periods through Google Forms or shared spreadsheets, where applicants hand over full name, student ID, phone number, domicile, and often medical history (allergies, conditions the logistics team needs to know), plus an ID card photo and CV. None of that is normally encrypted, so a leaked link or folder exposes everyone's personal and medical data with nothing in the way.

This project assumes that scenario: an internal portal that still collects the same information, but encrypts every submission on arrival. Even if the server's storage or database is copied, the content stays unreadable without the applicant's password, which is never stored. Accounts and a login exist for the same reason; without them, anyone with a link could read anyone else's submission.

## 2. Analysis performed

Since the assignment asks for a comparison between the three ciphers, the analysis we ran is a throughput benchmark (MB/s) of AES-256-OFB, DES-OFB and RC4, plus an integrity check confirming decryption reproduces the original bytes exactly (`crypto_core.py`, `benchmark()`).

We used throughput rather than a purely theoretical comparison because the app handles very different file sizes in practice, from a few hundred bytes of profile JSON up to a 190 MB video, so speed at realistic sizes is what actually matters for the user experience. The benchmark deliberately uses a low PBKDF2 iteration count, since at the real 600,000 iterations key derivation time would dominate the measurement and hide the cipher speed difference.

Results matched what is generally documented: RC4 fastest (lightweight stream cipher, no block overhead), AES next (hardware-accelerated on most CPUs), DES slowest (small block, older design). This does not change which cipher the app recommends: RC4's keystream biases got it dropped from TLS, and DES's 56-bit key is brute-forceable today, so AES-256 is what the interface suggests, with the other two kept available so the comparison can be reproduced live instead of only from a script.

## 3. Design decisions

**OFB mode for AES and DES.** Both are stream constructions, so no padding is needed and ciphertext length always matches plaintext length, which keeps streaming simple across tiny and very large files alike. OFB was picked over CFB because its keystream depends only on key and IV, not ciphertext, so a corrupted byte in a stored file only corrupts the matching plaintext byte instead of propagating. AES-GCM was skipped since the assignment is scoped around comparing these classical ciphers and modes, not AEAD; integrity is added manually instead (next point).

**Encrypt-then-MAC, self-describing files.** Each `.enc` file stores its own header (algorithm, mode, iteration count, salt, IV) plus an HMAC-SHA256 tag over header and ciphertext. Decryption checks the tag before returning anything, so a wrong password or corrupted file is caught immediately, and `decrypt_file()` writes to a temp path and only renames it once the tag verifies, so a failed decrypt never leaves a broken file behind.

**Key handling.** `derive_keys()` runs PBKDF2-HMAC-SHA256 (random salt, 600,000 iterations) and splits the output into a separate cipher key and HMAC key, since reusing one key for both purposes is a known weakness. This is independent from login: `bcrypt` hashes the account password for authentication, while the file-encryption key is derived fresh from the password typed at encrypt/decrypt time and never stored, so even full server access does not decrypt a file without that password.

**Streaming in 1 MiB chunks.** Needed since uploads go up to 190 MB; reading a whole video into memory per request would not scale if several applicants uploaded around the same time. OFB and RC4 both support incremental processing naturally.

**Three stored copies per submission.** Each item is encrypted and saved once per cipher instead of once overall, which is not how a normal app would be built, but it lets the vault decrypt the same submission with any of the three and get identical content back, so the comparison can be verified against the live app rather than taken on faith. The cost is triple storage, acceptable for a single organization's recruitment period.

**Metadata/ciphertext split.** SQLite holds only metadata (users, items, algorithm/path per copy); the encrypted bytes live under `storage/` under random filenames unrelated to the original name. A database leak alone does not expose file content, and the encrypted files stay portable on their own.

**Plain Flask, vanilla JS.** No frontend framework or ORM, since the point of the project is the cryptography, not the stack.

## 4. Running it locally

```bash
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000/`. `oprec.db`, `storage/` and `tmp/` are created automatically and are git-ignored, since they hold real user data once used. Set a real `SECRET_KEY` environment variable before deploying beyond localhost; the fallback in `app.py` is for local development only.

## 5. Project structure

```
app.py            Flask routes: auth, profile, upload, download
crypto_core.py     AES/DES/RC4 encryption, PBKDF2, HMAC, benchmark()
db.py              SQLite schema and connection helper
static/            Frontend: index.html, app.js, style.css
```
