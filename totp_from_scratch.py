#!/usr/bin/env python3
"""
TOTP "hello world" -- the algorithm itself, with no library doing the magic.

Time-based One-Time Password (RFC 6238) is built on HOTP (RFC 4226):

    1. Server and client agree on a secret key once, at enrollment time
       (this is the QR code / "setup key" you scan into an authenticator app).
    2. Both sides independently compute a "counter" from the current time:
           counter = floor(unix_time / time_step)     # time_step is usually 30s
    3. Both sides compute HMAC-SHA1(secret, counter) -- a keyed hash.
    4. "Dynamic truncation" picks 4 bytes out of that hash and turns them
       into a number, which is reduced to N digits (usually 6).
    5. Because both sides know the secret and both sides know the time,
       both sides land on the same 6-digit code without ever sending it
       over the network during setup -- that's the whole trick.

Run this, then scan the printed otpauth:// URI (or type the secret in
manually) into Google Authenticator / Authy / any TOTP app, and watch your
phone and this terminal always agree.
"""

import base64
import hashlib
import hmac
import os
import struct
import sys
import time
from urllib.parse import quote

TIME_STEP = 30
DIGITS = 6


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226 HOTP: one code for one counter value."""
    counter_bytes = struct.pack(">Q", counter)  # 8-byte big-endian counter
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Dynamic truncation (RFC 4226 section 5.3): the low nibble of the last
    # byte picks a starting offset into the 20-byte HMAC digest.
    offset = digest[-1] & 0x0F
    chunk = digest[offset : offset + 4]
    code_int = int.from_bytes(chunk, "big") & 0x7FFFFFFF  # clear top bit
    return str(code_int % (10**digits)).zfill(digits)


def totp(key: bytes, when: float | None = None, digits: int = DIGITS) -> str:
    """RFC 6238 TOTP: HOTP where the counter comes from wall-clock time."""
    when = time.time() if when is None else when
    counter = int(when // TIME_STEP)
    return hotp(key, counter, digits)


def explain_one_computation(key: bytes) -> None:
    """Walk through a single code computation with all the intermediate values."""
    now = time.time()
    counter = int(now // TIME_STEP)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    chunk = digest[offset : offset + 4]
    code_int = int.from_bytes(chunk, "big") & 0x7FFFFFFF
    code = str(code_int % (10**DIGITS)).zfill(DIGITS)

    print("=" * 60)
    print("ONE CODE, STEP BY STEP")
    print("=" * 60)
    print(f"shared secret (hex)     : {key.hex()}")
    print(f"unix time now           : {now:.0f}")
    print(f"time step               : {TIME_STEP}s")
    print(f"counter = time // step  : {counter}")
    print(f"counter as 8 bytes      : {counter_bytes.hex()}")
    print(f"HMAC-SHA1(secret,ctr)   : {digest.hex()}")
    print(f"low nibble of last byte : {digest[-1] & 0x0F} -> truncation offset")
    print(f"4 bytes at that offset  : {chunk.hex()}")
    print(f"as a 31-bit integer     : {code_int}")
    print(f"mod 10^{DIGITS}                : {code}")
    print("=" * 60)
    print()


def main() -> None:
    # A fresh random secret every run. In real enrollment this is generated
    # once by the server and never changes for that user/device pairing.
    key = os.urandom(20)  # 160 bits, the size SHA-1's HMAC wants
    b32_secret = base64.b32encode(key).decode().rstrip("=")

    account = "student@totp-demo"
    issuer = "Mason Comet Cybersecurity"
    otpauth_uri = (
        f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={b32_secret}"
        f"&issuer={quote(issuer)}&digits={DIGITS}&period={TIME_STEP}"
    )

    print(f"\nSecret (base32, type this into an authenticator app): {b32_secret}")
    print(f"Same secret, as a setup URI:\n  {otpauth_uri}\n")

    try:
        import qrcode  # optional; pip install qrcode

        qr = qrcode.QRCode(border=1)
        qr.add_data(otpauth_uri)
        qr.make()
        qr.print_ascii(invert=True)
        print()
    except ImportError:
        print("(install `qrcode` -- pip install qrcode -- to print a scannable QR here)\n")

    explain_one_computation(key)

    print("Now watching the code update live. Compare it to your authenticator app.")
    print("Press Ctrl+C to stop.\n")
    try:
        last = None
        while True:
            code = totp(key)
            remaining = TIME_STEP - int(time.time()) % TIME_STEP
            if code != last:
                print(f"code: {code}   (valid for {remaining}s)")
                last = code
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nbye")
        sys.exit(0)


if __name__ == "__main__":
    main()
