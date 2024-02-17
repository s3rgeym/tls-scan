# tls-scan

CLI tool to scan IP addresses for TLS/SSL certificates. Outputs results in JSONL format. Useful for detecting software such as VMWare.

Installation:

```bash
pip install tls-scan
```

> This tool does not use third-party dependencies and can be run as a script.

Usage:

```bash
$ tls-scan -h
```

Example #1: scan whole internet:

```bash
$ tls-scan -v -a 0.0.0.0/0
```

Output sample:

```json
{"ip": "193.201.66.1", "port": 443, "port_name": "https", "cert": {"subject": {"countryName": "LV", "localityName": "Rīga", "organizationName": "AS PrivatBank", "commonName": "*.privatbank.lv"}, "issuer": {"countryName": "US", "organizationName": "DigiCert Inc", "commonName": "DigiCert TLS RSA SHA256 2020 CA1"}, "version": 3, "serialNumber": "0CE443B97F070F5500D008EEDFB11F88", "notBefore": "Aug 12 00:00:00 2022 GMT", "notAfter": "Aug 24 23:59:59 2023 GMT", "subjectAltName": [["DNS", "*.privatbank.lv"], ["DNS", "www.privatbank.lv"], ["DNS", "ibank.privatbank.lv"], ["DNS", "b2a2.privatbank.lv"], ["DNS", "open.privatbank.lv"], ["DNS", "sof.privatbank.lv"]], "OCSP": ["http://ocsp.digicert.com"], "caIssuers": ["http://cacerts.digicert.com/DigiCertTLSRSASHA2562020CA1-1.crt"], "crlDistributionPoints": ["http://crl3.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl", "http://crl4.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl"]}, "hostname": "b2a2.privatbank.lv"}
```

You can specify the port using `-p`. Instead of a port number or port range, you can use an alias: `smtp`, `imap`, `pop`, `https`, `ldap`, `rdp`, `ftp`, `telnet`, `cpanel`, `whm`, `kuber`, `portainer`, `proxmox`, `webmin`, `redis`, `activemq`. Specify `all` to scan all listed ports and `common` for the most common ones.

Example #2: extract domains from certificate using [jq](https://jqlang.github.io/jq/):

```bash
$ tls-scan -a ... -p https smtp | jq -r '.cert.commonName, ( .cert.subjectAltName?[] | select(.[0]=="DNS")[1] ), .hostname | select(.)
...
*.privatbank.lv
www.privatbank.lv
ibank.privatbank.lv
b2a2.privatbank.lv
open.privatbank.lv
sof.privatbank.lv
b2a2.privatbank.lv
...
```
