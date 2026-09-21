# TOTP 101

A "hello world" for Time-based One-Time Passwords (RFC 6238), built for
classroom demos. Two parts, use whichever fits the lesson:

1. **`totp_from_scratch.py`** -- a single file, zero dependencies, that
   implements the TOTP algorithm by hand (HMAC-SHA1 + truncation) and
   prints every intermediate value. Best for explaining *how the math
   works*.
2. **`webapp/`** -- a tiny Flask site that simulates enrolling in 2FA
   (scan a QR code) and then logging in with a code, like a real site
   would. Best for showing *what the authentication flow looks like*.

## Quick start: the algorithm

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r qrcode
python3 totp_from_scratch.py
```

Optionally `pip install qrcode` first so it can print a scannable QR code
in the terminal. It prints the secret, walks through one code computation
step by step, then live-updates the code every 30 seconds so students can
watch it change in sync with an authenticator app.

## Quick start: the web app

```bash
cd webapp
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000, scan the QR code with Google Authenticator
/ Authy / any TOTP app, and log in at `/login` with the code it shows.

### Or with Docker

```bash
cd webapp
docker compose up --build -d
# uses port 8088
```

## What to point out in class

- **The secret is the only thing that ever gets shared, and only once**
  (at enrollment, via the QR code). After that, no network round-trip is
  needed to log in -- both sides just agree because they both know the
  secret and the time.
- **Time is part of the credential.** If a phone's clock drifts too far,
  codes stop matching -- this is why `valid_window` exists in the login
  check (a small tolerance for clock skew).
- **A code is a moving target.** Unlike a password, a leaked TOTP code is
  only useful for ~30-60 seconds, which is the whole point of "something
  you have" (the phone with the secret) as a second factor.
- **This demo is intentionally insecure for a real app**: one global
  in-memory secret, no HTTPS, no rate limiting on `/login`, and a
  `/current-code` endpoint that leaks the secret's output for
  demonstration purposes. Good discussion prompt: *what's missing before
  this could go live?* (Answers: per-user secrets in encrypted storage,
  HTTPS, brute-force/rate limiting, secret delivered over a channel the
  user already authenticated on, backup codes, etc.)
