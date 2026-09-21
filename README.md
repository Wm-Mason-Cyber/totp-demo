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

Then open http://localhost:5000. It's built to feel like a normal website
(students should already be comfortable with the signup/login/save-password
flow from the GPM demo), so there's no lesson text in the way:

1. **Sign up** with a username and password, letting Google Password
   Manager (or the student's own password manager) suggest and save it.
2. **Set up two-factor**: scan the QR code, then type the first code to
   finish. This page has iPhone / Android advice and other app suggestions.
3. **Log in** with the password, then the current 6-digit code.

The "what just happened" explanation appears on the success page, after
students have done the real flow. For a student with no phone handy, add
`?teacher=1` to the code page's URL (`/login/code?teacher=1`) to reveal a
live-code toggle.

Each student gets their own account and secret. Users live in memory and
reset whenever the app restarts.

**Phones:** students need to reach the site from their phone (same Wi-Fi,
using your computer's IP address, e.g. `http://192.168.1.20:5000`).

- **iPhone**: the built-in **Passwords** app is the native TOTP app. It
  attaches the code to a *saved login*, which is why the demo has a real
  signup step: tap **Save** when iOS offers, then scan the QR code with the
  Camera app and pick that saved login. Google Authenticator (App Store)
  also works if a student prefers it -- scan from *inside* that app.
- **Android**: Google Authenticator (Play Store), scanning from inside the app.
- The enroll page lists other apps too (Microsoft Authenticator, Authy,
  2FAS, Aegis, Bitwarden, 1Password).

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
- **Two factors, two steps.** Password alone never gets you in -- the
  server only creates a full session after the code also matches.
- **This demo is intentionally insecure for a real app**: in-memory users,
  secrets stored in plaintext, no HTTPS, no rate limiting on the login
  steps, and a `/current-code` endpoint that leaks the code for
  demonstration purposes. Good discussion prompt: *what's missing before
  this could go live?* (Answers: secrets in encrypted storage, HTTPS,
  brute-force/rate limiting, backup/recovery codes, rejecting a code
  that was already used, etc.)
