# tls-scan

CLI tool to scan IP addresses for TLS/SSL certificates. Outputs results in JSONL format. Useful for detecting software such as VMWare.

Installation:

```bash
pip install tls-scan
```

Usage:

```bash
# show help
$ tls-scan -h

# scan whole internet
$ tls-scan -v -a 0.0.0.0/0
```
