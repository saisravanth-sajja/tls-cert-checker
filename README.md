# tls-cert-checker

Checks the TLS certificates on a list of hosts and tells you which ones are expired, about to expire, or not trusted.

I wanted something quicker than running `openssl s_client` against hosts one at a time. Give it hostnames, or a file of them, and it prints one line per host:

```
$ python certcheck.py app.example.com shop.example.com old.example.com intranet.example.com
HOST                  STATUS    DAYS  EXPIRES     ISSUER                KEY          TLS
app.example.com       OK        74    2027-02-01  Example Issuing CA    RSA-2048     TLSv1.3
shop.example.com      EXPIRING  12    2026-12-01  Example Issuing CA    ECDSA P-256  TLSv1.3
old.example.com       EXPIRED   -3    2026-11-16  Example Issuing CA    RSA-2048     TLSv1.3
intranet.example.com  INVALID   355   2027-11-09  intranet.example.com  RSA-2048     TLSv1.3

intranet.example.com: self-signed certificate
```

That sample is from a local test setup, so the names and dates are made up.

## Statuses

| Status   | Meaning |
|----------|---------|
| OK       | Trusted and not expiring within the warning window |
| EXPIRING | Trusted, but expires within `--warn-days` (30 by default) |
| EXPIRED  | Past its expiry date |
| INVALID  | Failed verification: self-signed, unknown CA, wrong hostname. The reason is printed under the table |
| ERROR    | Couldn't connect or finish the handshake: DNS, connection refused, timeout |

When a cert fails verification, the script connects a second time with checks turned off, so you still see who issued it and when it expires.

## Setup

Python 3.10 or newer.

```
pip install -r requirements.txt
python certcheck.py example.com
```

## Usage

```
python certcheck.py example.com api.example.com:8443
python certcheck.py -f hosts.txt --warn-days 14
python certcheck.py -f hosts.txt --csv report.csv
python certcheck.py internal.corp:443 --cafile corp-root-ca.pem
```

The hosts file takes one host per line, and `#` starts a comment. See `hosts.example.txt`.

```
  -f, --file FILE       file with one host per line (# starts a comment)
  -w, --warn-days WARN_DAYS
                        flag certs that expire within this many days (default: 30)
  -t, --timeout TIMEOUT
                        connection timeout in seconds (default: 5)
  --cafile CAFILE       CA bundle to trust instead of the system store (internal CAs)
  --csv PATH            also save the results to a CSV file
  -j, --workers WORKERS
                        how many hosts to check at once (default: 10)
```

## Running it on a schedule

The exit code is 0 only when every host is OK, and 1 otherwise. That means cron or a CI job can act on it without parsing the output:

```
# every Monday at 8am
0 8 * * 1  cd /opt/tls-cert-checker && python3 certcheck.py -f hosts.txt --csv /var/log/cert-report.csv
```

## Things to know

- `--cafile` replaces the system trust store rather than adding to it. If you mix public and internal hosts, check them in separate runs.
- Days left are rounded down.
- It only looks at the server's own certificate. It doesn't check revocation (OCSP/CRL) or walk the rest of the chain.
- Python 3.13 turned on strict X.509 checks by default. The script turns them off so results match what browsers accept.

## Tests

```
pip install pytest
pytest
```

The tests start local TLS servers with throwaway certificates (healthy, expiring, expired, untrusted), so they don't need internet access.

## Ideas for later

- flag weak keys and old TLS versions
- show the full chain
- post results to Slack

## License

MIT
