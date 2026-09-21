"""
TOTP "hello world" web app.

Behaves like a real site with two-factor login, so students can practice
with their phone's *native* password manager / authenticator:

  1. Sign up (/signup):  pick a username + password. Browsers and phone
     password managers (iOS Passwords, Google Password Manager) offer to
     save this login -- on iPhone, that saved login is what the TOTP code
     gets attached to in the next step.

  2. Enroll (/enroll):  the server generates a per-user secret and shows it
     as a QR code. The student scans it into an authenticator (iOS
     Passwords, Google Authenticator, etc.) and proves it worked by typing
     the first code. From here, server and phone both know the secret and
     can independently compute the same code.

  3. Login (/login, then /login/code):  password first, then the current
     6-digit code. The server recomputes the code from the shared secret +
     current time -- the code itself is never transmitted or stored ahead
     of time.

This is a teaching demo, not production code: in-memory users that vanish
on restart, secrets stored in plaintext, no HTTPS, no rate limiting. Good
discussion prompt for class: "what would you add before this could go live?"
"""

import base64
import io
import time

import pyotp
import qrcode
from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "classroom-demo-secret-key-not-for-production"

ISSUER = "Mason Comet Cybersecurity"

# username -> {"password_hash": str, "secret": str, "totp_enabled": bool}
users: dict[str, dict] = {}


def qr_data_uri(otpauth_uri: str) -> str:
    img = qrcode.make(otpauth_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def code_is_valid(user: dict, submitted: str) -> bool:
    # valid_window=1 tolerates +/-30s of clock drift, same as real apps do.
    return pyotp.TOTP(user["secret"]).verify(submitted.strip(), valid_window=1)


def password_verified_user():
    """The user who has passed the password step (but maybe not the code step)."""
    name = session.get("pw_user")
    return name, users.get(name)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("new-password", "")
        confirm = request.form.get("confirm-password", "")

        if not username or not password:
            error = "Username and password are required."
        elif password != confirm:
            error = "Passwords don't match."
        elif username in users:
            error = "That username is taken -- pick another, or log in."
        else:
            users[username] = {
                "password_hash": generate_password_hash(password),
                "secret": pyotp.random_base32(),
                "totp_enabled": False,
            }
            session.clear()
            session["pw_user"] = username
            return redirect(url_for("enroll"))
    return render_template("signup.html", error=error)


@app.route("/enroll", methods=["GET", "POST"])
def enroll():
    username, user = password_verified_user()
    if not user:
        return redirect(url_for("login"))
    if user["totp_enabled"]:
        return redirect(url_for("login_code"))

    error = None
    if request.method == "POST":
        if code_is_valid(user, request.form.get("code", "")):
            user["totp_enabled"] = True
            session.clear()
            session["user"] = username
            return redirect(url_for("success"))
        error = "That isn't the current code. Check your app and try again."

    uri = pyotp.TOTP(user["secret"]).provisioning_uri(name=username, issuer_name=ISSUER)
    return render_template(
        "enroll.html",
        username=username,
        secret=user["secret"],
        qr=qr_data_uri(uri),
        error=error,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("current-password", "")
        user = users.get(username)
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["pw_user"] = username
            if user["totp_enabled"]:
                return redirect(url_for("login_code"))
            return redirect(url_for("enroll"))
        error = "Incorrect username or password."
    return render_template("login.html", error=error)


@app.route("/login/code", methods=["GET", "POST"])
def login_code():
    username, user = password_verified_user()
    if not user:
        return redirect(url_for("login"))
    if not user["totp_enabled"]:
        return redirect(url_for("enroll"))

    error = None
    if request.method == "POST":
        submitted = request.form.get("code", "").strip()
        if code_is_valid(user, submitted):
            session.clear()
            session["user"] = username
            return redirect(url_for("success"))
        error = f"'{submitted}' is not the current code (or it already expired). Try again."
    return render_template(
        "login_code.html",
        username=username,
        error=error,
        teacher=request.args.get("teacher") == "1",
    )


@app.route("/success")
def success():
    username = session.get("user")
    if username not in users:
        return redirect(url_for("login"))
    return render_template("success.html", username=username)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/current-code")
def current_code():
    """
    Debug/teacher endpoint (needs ?teacher=1): shows the live code + countdown
    for the user who just passed the password step, so the class can watch
    the server-side value tick over when someone has no phone handy. A real login page would
    never expose this.
    """
    _, user = password_verified_user()
    if not user or request.args.get("teacher") != "1":
        return {"error": "not available"}, 403
    return {
        "code": pyotp.TOTP(user["secret"]).now(),
        "seconds_remaining": 30 - int(time.time()) % 30,
    }


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
