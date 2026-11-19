import datetime as dt
import ipaddress
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import certcheck


def key_usage(**on):
    flags = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                 data_encipherment=False, key_agreement=False, key_cert_sign=False,
                 crl_sign=False, encipher_only=False, decipher_only=False)
    flags.update(on)
    return x509.KeyUsage(**flags)


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=60))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(key_usage(digital_signature=True, key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_server_cert(ca_key, ca_cert, days_valid):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=30))
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage(digital_signature=True, key_encipherment=True), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


@pytest.fixture
def tls_server(tmp_path):
    """Starts a local TLS server whose cert expires in `days_valid` days.
    Returns (port, path to the CA that signed it)."""
    running = []

    def start(days_valid):
        ca_key, ca_cert = make_ca()
        key, cert = make_server_cert(ca_key, ca_cert, days_valid)
        cert_file, key_file, ca_file = tmp_path / "cert.pem", tmp_path / "key.pem", tmp_path / "ca.pem"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        ca_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.TraditionalOpenSSL,
                                               serialization.NoEncryption()))

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        sock.settimeout(0.2)
        stop = threading.Event()

        def serve():
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                except OSError:
                    continue
                conn.settimeout(5)
                try:
                    with ctx.wrap_socket(conn, server_side=True):
                        pass
                except OSError:  # client rejected our cert, that's expected in some tests
                    pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        running.append((stop, thread, sock))
        return sock.getsockname()[1], str(ca_file)

    yield start
    for stop, thread, sock in running:
        stop.set()
        thread.join(timeout=2)
        sock.close()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.parametrize("raw, expected", [
    ("example.com", ("example.com", 443)),
    ("example.com:8443", ("example.com", 8443)),
    ("https://example.com/login", ("example.com", 443)),
    ("https://example.com:8443/", ("example.com", 8443)),
    ("[::1]:8443", ("::1", 8443)),
    ("  example.com  ", ("example.com", 443)),
])
def test_parse_target(raw, expected):
    assert certcheck.parse_target(raw) == expected


def test_read_targets_skips_comments(tmp_path):
    f = tmp_path / "hosts.txt"
    f.write_text("# prod\nexample.com\n\nexample.org:8443  # api\n")
    assert certcheck.read_targets(f) == ["example.com", "example.org:8443"]


def test_healthy_cert(tls_server):
    port, ca = tls_server(days_valid=200)
    r = certcheck.check_target(f"localhost:{port}", warn_days=30, cafile=ca)
    assert r.status == "OK"
    assert r.issuer == "Test CA"
    assert r.subject == "localhost"
    assert r.key == "RSA-2048"
    assert r.tls_version in ("TLSv1.2", "TLSv1.3")


def test_cert_expiring_soon(tls_server):
    port, ca = tls_server(days_valid=10)
    r = certcheck.check_target(f"localhost:{port}", warn_days=30, cafile=ca)
    assert r.status == "EXPIRING"
    assert 9 <= r.days_left <= 10


def test_expired_cert(tls_server):
    port, ca = tls_server(days_valid=-5)
    r = certcheck.check_target(f"localhost:{port}", cafile=ca)
    assert r.status == "EXPIRED"
    assert r.days_left < 0


def test_untrusted_cert_still_shows_details(tls_server):
    port, _ = tls_server(days_valid=200)
    r = certcheck.check_target(f"localhost:{port}")  # system store doesn't know Test CA
    assert r.status == "INVALID"
    assert "certificate" in r.note
    assert r.key == "RSA-2048"


def test_nothing_listening():
    r = certcheck.check_target(f"127.0.0.1:{free_port()}", timeout=2)
    assert r.status == "ERROR"
    assert r.note


def test_bad_port():
    r = certcheck.check_target("example.com:https")
    assert r.status == "ERROR"
    assert "parse" in r.note


def test_main_exit_code_and_csv(tls_server, tmp_path, capsys):
    port, ca = tls_server(days_valid=200)
    report = tmp_path / "report.csv"
    code = certcheck.main([f"localhost:{port}", "--cafile", ca, "--csv", str(report)])
    assert code == 0
    assert "OK" in capsys.readouterr().out
    assert "localhost" in report.read_text()


def test_main_fails_when_something_is_wrong(capsys):
    code = certcheck.main([f"127.0.0.1:{free_port()}", "-t", "2"])
    assert code == 1
    assert "ERROR" in capsys.readouterr().out
