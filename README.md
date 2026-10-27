| Name | NRP |
|---|---|
| Fathiya Nayla Husna Wibowo | 5025241204 |
| Mahirah Yasmin Aulia Mawahib | 5025241095 |
| Jeihan Shawmy Prasetya | 5025241132 |
| Alif Muflih Jauhary | 5025241003 |

# OPREC Portal

A small Flask web app we built for the Information Security assignment. It is a committee open-recruitment (OPREC) portal where applicants submit personal data, an ID card photo, supporting documents and an introduction video. Every piece of data is encrypted with three different ciphers (AES-256, DES, RC4) before it touches the disk, so the assignment's cipher comparison is backed by a working system instead of a standalone script.

## 1. Scenario

Campus organizations in Indonesia run open recruitment ("oprec") periods every semester where dozens to hundreds of students apply through a form. In practice this form is usually a Google Form or a spreadsheet that the whole committee can open, and it routinely asks for things that should not sit around in plaintext: full name, student ID (NRP), phone number, domicile, and often medical history (for example allergies or conditions the event's logistics team needs to know about). An ID card photo and a CV are attached on top of that.

If that spreadsheet or folder leaks, gets shared with the wrong link, or is accessed by someone outside the committee after the recruitment period ends, applicants' personal and medical data is exposed with nothing in the way. This project assumes that scenario: a small internal web app that still lets the committee collect the same information and files, but encrypts every submission the moment it arrives, so that even if the server's storage or database is copied, the content is unreadable without the applicant's password. The password is never stored, so decrypting a record always needs the person who submitted it (or someone they gave the password to) to type it in again.

This is also why the app has accounts and a login instead of being a bare upload form: without authentication, anyone with a link could read anyone else's submission, which defeats the purpose of encrypting it in the first place.

## 2. Analysis performed

The assignment asks for a comparison between the three ciphers, so the analysis we ran is a throughput benchmark (MB/s) of AES-256-OFB, DES-OFB and RC4 on representative files, plus an integrity check that decrypting the ciphertext reproduces the original bytes exactly (`crypto_core.py`, the `benchmark()` function at the bottom of the file).

We picked throughput over, say, a theoretical complexity comparison because the app itself has to deal with files of very different sizes in practice: a profile record is a few hundred bytes of JSON, while an introduction video can be close to 190 MB. Speed at realistic sizes is the metric that actually decides whether a user sits and waits for an upload to finish, so it is the more useful analysis for this scenario than a purely academic one. The benchmark uses a low PBKDF2 iteration count on purpose, since at the default 600,000 iterations the key derivation time dominates the measurement and hides the actual cipher speed difference; this was a deliberate choice, not an oversight.

The results (consistent with what is generally documented about these ciphers) show RC4 as the fastest since it is a lightweight stream cipher with no block or mode overhead, AES next thanks to hardware acceleration on most modern CPUs, and DES the slowest of the three because of its small 64-bit block and older design. None of this changes which cipher the app treats as "the recommended one": RC4 has known keystream biases and was dropped from TLS, and DES's 56-bit effective key is brute-forceable with commodity hardware today, so AES-256 is the one actually suggested to the user in the interface, with the two legacy ciphers kept available specifically so the comparison required by the assignment can be reproduced live from the deployed app and not just from an offline script.

## 3. Design decisions

### Why OFB mode for AES and DES

`crypto_core.py` implements both CFB-8 and OFB, but the web app itself only ever uses OFB for AES and DES. Both are stream-cipher constructions, which matters because the files handled here range from a tiny JSON profile to a large video: a stream mode avoids padding entirely and the ciphertext length always equals the plaintext length, which keeps the streaming implementation simple. OFB specifically was chosen over CFB for the live app because an OFB keystream depends only on the key and IV, not on the ciphertext, so a single corrupted byte in a stored `.enc` file only corrupts the corresponding plaintext byte on decrypt instead of propagating into following blocks. Since these files sit on disk for the whole recruitment period, that resistance to isolated storage corruption felt like the right trade-off. RC4 needs no mode since it is already a stream cipher.

AES-GCM or a similar AEAD mode was deliberately not used, since the assignment is scoped around comparing the classical AES/DES/RC4 ciphers and their modes, not modern authenticated encryption. Integrity and tamper detection are instead added manually with HMAC-SHA256 (see below), which keeps the required cipher/mode comparison intact while still getting the same practical protection.

### Key handling

The encryption key is never the raw password. `derive_keys()` runs PBKDF2-HMAC-SHA256 with a random 16-byte salt and 600,000 iterations (in line with current OWASP guidance for PBKDF2-SHA256) and derives enough output to split into two independent keys: one for the cipher and one for HMAC. These are kept separate on purpose, since reusing one key for both encryption and authentication is a known way to weaken a construction; deriving two unrelated keys from the same password removes that risk for basically no extra cost.

Login password hashing is completely separate from this. `bcrypt` hashes and checks the account password for authentication, while PBKDF2 derives file encryption keys from the password the user types at encrypt/decrypt time. The two never touch: the account's password hash in the `users` table cannot be used to decrypt anything, and the plaintext password used for encryption is never written to disk or the database, only held in the browser tab's memory for the session and sent per request. This means that even with full access to the server and database, decrypting a specific file still requires that applicant's password.

### Encrypt-then-MAC and the file format

Every encrypted file is self-describing: it starts with a small header (magic bytes, version, algorithm id, mode id, iteration count, salt, IV) followed by the ciphertext and ends with a 32-byte HMAC-SHA256 tag computed over the header and ciphertext together. This was chosen so a `.enc` file never depends on the database for the parameters needed to decrypt it, only on the password; the database only needs to know which file belongs to which algorithm. On decrypt, the tag is checked before anything is handed back to the user, so a wrong password or a corrupted file is caught immediately instead of silently returning garbage bytes, and `decrypt_file()` writes to a temporary path and only renames it to the final output once the tag has verified, so a failed decrypt never leaves a half-written or corrupted file behind.

### Streaming instead of reading whole files into memory

Both encryption and decryption process files in 1 MiB chunks rather than loading the whole file into memory first. Given that uploads can be up to 190 MB (the video field), reading the entire file into RAM for every request would be wasteful and would not scale if several applicants uploaded videos around the same time. OFB and RC4 both support incremental processing naturally, so streaming does not cost anything in terms of implementation complexity.

### Three stored copies per submission

Each uploaded item is encrypted and stored three times, once per cipher, instead of once with a single chosen algorithm. This is not how a normal production app would be built, but it directly serves the assignment's requirement to compare the three ciphers: the vault page lets the user decrypt the exact same submission with any of the three and get identical content back, so the comparison in the report can be verified against the live app rather than taken on faith. The trade-off is triple the storage per submission, which is acceptable here since the dataset is one organization's recruitment period, not a long-term, large-scale file store.

### Storage and database split

Only metadata lives in SQLite (`users`, `items`, `item_copies`): usernames, bcrypt hashes, item kind, original filename, and the path and algorithm of each encrypted copy. The actual encrypted bytes live as separate files under `storage/`, named with a random token rather than the original filename, so a database leak alone does not expose file contents and a filename leak does not reveal what the original file was. Splitting metadata from ciphertext also means the encrypted files on disk are portable; they can be moved, backed up or inspected independently of the database as long as the password is known.

### Plain Flask and vanilla JS

The backend is Flask with no additional framework, and the frontend is plain HTML/CSS/JS with no build step. For a project whose point is the cryptography, pulling in a frontend framework or an ORM would add dependencies and moving parts without adding anything to what is actually being graded, so we kept the stack as small as it could reasonably be while still having a real login flow, file upload with progress, and a usable vault view.

## 4. Running it locally

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://localhost:5000/`. SQLite (`oprec.db`), the encrypted files (`storage/`) and temporary files (`tmp/`) are created automatically on first run and are git-ignored, since they hold real user data once the app is actually used.

Set a real `SECRET_KEY` environment variable before deploying anywhere beyond localhost; the fallback in `app.py` is only meant for local development.

## 5. Project structure

```
app.py            Flask routes: auth, profile, upload, download
crypto_core.py     AES/DES/RC4 encryption, PBKDF2, HMAC, benchmark()
db.py              SQLite schema and connection helper
static/            Frontend: index.html, app.js, style.css
```
