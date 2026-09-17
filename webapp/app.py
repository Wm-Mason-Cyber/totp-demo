"""
TOTP "hello world" web app.

Simulates the two moments where TOTP shows up in a real login system:

  1. Enrollment (/):  the server generates a secret and shows it as a QR
     code. The student scans it into an authenticator app (Google
     Authenticator, Authy, etc). From this point on, server and phone
     both know the secret and can independently compute the same code.

  2. Login (/login):  the student types the 6-digit code their app is
     currently showing. The server recomputes the code itself from the
     shared secret + current time and checks they match -- the code
     itself never needed to be transmitted or stored anywhere in advance.

This is a teaching demo, not production code: one global in-memory user,
no HTTPS, no rate limiting, no persistence. Good discussion prompt for
class: "what would you add before this could go live?"
"""

import base64
import io
import time

import pyotp
import qrcode
from flask import Flask, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = "classroom-demo-secret-key-not-for-production"

DEMO_USERNAME = "student"
DEMO_SECRET = pyotp.random_base32()  # generated fresh each time the app starts


def qr_data_uri(otpauth_uri: str) -> str:
    img = qrcode.make(otpauth_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


@app.route("/")
def index():
    totp = pyotp.TOTP(DEMO_SECRET)
    uri = totp.provisioning_uri(name=DEMO_USERNAME, issuer_name="Mason Comet Cybersecurity")
    return render_template(
        "index.html",
        username=DEMO_USERNAME,
        secret=DEMO_SECRET,
        qr=qr_data_uri(uri),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        submitted_code = request.form.get("code", "").strip()
        totp = pyotp.TOTP(DEMO_SECRET)
        # valid_window=1 tolerates +/-30s of clock drift, same as real apps do.
        if totp.verify(submitted_code, valid_window=1):
            session["authed"] = True
            return redirect(url_for("success"))
        error = f"'{submitted_code}' is not the current code (or it already expired). Try again."
    return render_template("login.html", error=error)


@app.route("/success")
def success():
    if not session.get("authed"):
        return redirect(url_for("login"))
    return render_template("success.html", username=DEMO_USERNAME)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/current-code")
def current_code():
    """
    Debug/teacher endpoint: exposes the live code + countdown so the class
    can watch the server-side value tick over, e.g. when demoing without
    everyone having a phone handy. A real login page would never expose this.
    """
    totp = pyotp.TOTP(DEMO_SECRET)
    return {
        "code": totp.now(),
        "seconds_remaining": 30 - int(time.time()) % 30,
    }


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
