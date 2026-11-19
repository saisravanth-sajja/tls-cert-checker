#!/usr/bin/env python3
"""Check TLS certificates for a list of hosts.

For each host it prints the status, days left, expiry date, issuer,
key type and the TLS version the server negotiated. Exits with 1 if
anything needs attention, so it can run from cron or a CI job.
"""

import argparse
import csv
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

DEFAULT_PORT = 443
CURVES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}


@dataclass
class Result:
    target: str
    status: str = "ERROR"
    days_left: int | None = None
    expires: str = ""
    subject: str = ""
    issuer: str = ""
    key: str = ""
    tls_version: str = ""
    note: str = ""


def parse_target(raw):
    """Turn 'host', 'host:port' or 'https://host/path' into (host, port)."""
    t = raw.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    if t.startswith("["):  # IPv6, e.g. [::1]:8443
        host, _, rest = t[1:].partition("]")
        return host, int(rest.lstrip(":") or DEFAULT_PORT)
    if t.count(":") == 1:
        host, port = t.split(":")
        return host, int(port)
    return t, DEFAULT_PORT


def read_targets(path):
    targets = []
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                targets.append(line)
    return targets


def fetch_cert(host, port, timeout, cafile=None, verify=True):
    ctx = ssl.create_default_context(cafile=cafile)
    # Python 3.13 turned on strict X.509 checks by default. Browsers don't
    # use them, so leaving them on flags plenty of normal certs as broken.
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True), tls.version()


def describe_key(cert):
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA {CURVES.get(key.curve.name, key.curve.name)}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    return type(key).__name__


def short_name(name):
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return attrs[0].value
    return name.rfc4514_string()


def error_text(err):
    return getattr(err, "strerror", None) or str(err) or type(err).__name__


def check_target(raw, warn_days=30, timeout=5.0, cafile=None):
    res = Result(target=raw.strip())
    try:
        host, port = parse_target(raw)
    except ValueError:
        res.note = "could not parse host/port"
        return res

    verify_error = ""
    try:
        der, version = fetch_cert(host, port, timeout, cafile)
    except ssl.SSLCertVerificationError as e:
        # Not trusted, expired or wrong name. Connect again without
        # verification so we can still show what the server is sending.
        verify_error = e.verify_message or str(e)
        try:
            der, version = fetch_cert(host, port, timeout, verify=False)
        except OSError as e2:
            res.note = error_text(e2)
            return res
    except OSError as e:  # refused, timeout, DNS, handshake failure...
        res.note = error_text(e)
        return res

    cert = x509.load_der_x509_certificate(der)
    expires = cert.not_valid_after_utc
    days = (expires - datetime.now(timezone.utc)).days

    res.days_left = days
    res.expires = expires.strftime("%Y-%m-%d")
    res.subject = short_name(cert.subject)
    res.issuer = short_name(cert.issuer)
    res.key = describe_key(cert)
    res.tls_version = version

    if days < 0:
        res.status = "EXPIRED"
    elif verify_error:
        res.status, res.note = "INVALID", verify_error
    elif days <= warn_days:
        res.status = "EXPIRING"
    else:
        res.status = "OK"
    return res


COLUMNS = [
    ("HOST", "target"),
    ("STATUS", "status"),
    ("DAYS", "days_left"),
    ("EXPIRES", "expires"),
    ("ISSUER", "issuer"),
    ("KEY", "key"),
    ("TLS", "tls_version"),
]


def print_table(results, out=None):
    out = out or sys.stdout
    headers = [h for h, _ in COLUMNS]
    rows = []
    for r in results:
        row = []
        for _, attr in COLUMNS:
            value = getattr(r, attr)
            value = "" if value is None else str(value)
            if attr == "issuer" and len(value) > 30:
                value = value[:29] + "~"
            row.append(value)
        rows.append(row)

    widths = [max([len(h)] + [len(row[i]) for row in rows]) for i, h in enumerate(headers)]
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip(), file=out)
    for row in rows:
        print("  ".join(v.ljust(w) for v, w in zip(row, widths)).rstrip(), file=out)

    notes = [r for r in results if r.note]
    if notes:
        print(file=out)
        for r in notes:
            print(f"{r.target}: {r.note}", file=out)


def write_csv(results, path):
    names = [f.name for f in fields(Result)]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=names)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))


def main(argv=None):
    p = argparse.ArgumentParser(description="Check TLS certificates for a list of hosts.")
    p.add_argument("hosts", nargs="*", help="host, host:port or https:// URL")
    p.add_argument("-f", "--file", help="file with one host per line (# starts a comment)")
    p.add_argument("-w", "--warn-days", type=int, default=30,
                   help="flag certs that expire within this many days (default: 30)")
    p.add_argument("-t", "--timeout", type=float, default=5.0,
                   help="connection timeout in seconds (default: 5)")
    p.add_argument("--cafile", help="CA bundle to trust instead of the system store (internal CAs)")
    p.add_argument("--csv", metavar="PATH", help="also save the results to a CSV file")
    p.add_argument("-j", "--workers", type=int, default=10,
                   help="how many hosts to check at once (default: 10)")
    args = p.parse_args(argv)

    targets = list(args.hosts)
    if args.file:
        targets += read_targets(args.file)
    if not targets:
        p.error("give at least one host, or a file with -f")

    def check(t):
        return check_target(t, args.warn_days, args.timeout, args.cafile)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(check, targets))

    print_table(results)
    if args.csv:
        write_csv(results, args.csv)
    return 0 if all(r.status == "OK" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
