#!/usr/bin/env python
"""Scan IP addresses for TLS/SSL certificates"""
import argparse
import ipaddress
import itertools
import json
import logging
import os
import queue
import socket
import ssl
import sys
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache, partial
from ipaddress import IPv4Network, IPv6Network
from threading import Thread
from typing import Any, Iterable, TextIO

try:
    from collections import Sequence
except ImportError:
    from typing import Sequence

try:
    from itertools import batched
except ImportError:

    def batched(iterable: Iterable, n: int) -> Iterable[tuple]:
        it = iter(iterable)
        while batch := tuple(itertools.islice(it, n)):
            yield batch


__version__ = "0.1.4"
__maintainer__ = "Sergey M"

RESET = "\x1b[m"

BLACK = "\x1b[30m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
MAGENTA = "\x1b[35m"
CYAN = "\x1b[36m"
WHITE = "\x1b[37m"

# Основные я бпвл отсюда:
# https://www.globalsign.com/en-sg/blog/securing-internet-connection-all-about-ssl-port-or-secured-ports
# Но SSH не имеет никакого отношения к SSL/TSL
PORT_NAMES = {
    # Базовые
    465: "smtp",
    587: "smtp",
    993: "imap",
    995: "pop",
    # vmware и многий другой софт висит на 443 и 8443 портах
    # https://kb.vmware.com/s/article/2039095
    # так же на нем cisco, zabbix
    443: "https",
    # на этом порту висит админка Plesk
    8443: "https",
    # удаленный доступ к рабочему столу
    # виртуалки и/или samba
    636: "ldap",  # ldaps
    3389: "rdp",
    # 989: "ftp",
    990: "ftp",
    992: "telnet",
    # в Windows docker висит на порту
    2376: "docker",
    # админки
    # https://docs.cpanel.net/knowledge-base/general-systems-administration/how-to-configure-your-firewall-for-cpanel-services/
    2083: "cpanel",
    2087: "whm",
    2222: "direct-admin",
    # https://kubernetes.io/docs/concepts/security/controlling-access/
    6443: "kuber",
    9443: "portainer",
    # https://pve.proxmox.com/wiki/Ports
    8006: "proxmox",
    # https://www.howtoforge.com/tutorial/securing-ispconfig-3-with-a-free-lets-encrypt-ssl-certificate/
    8080: "ispconfig",  # + всякие vpn/прокси
    8083: "vesta",
    # аналог cpanel
    # https://subscription.packtpub.com/book/cloud-and-networking/9781849515849/1/ch01lvl1sec12/connecting-to-webmin#:~:text=Webmin%20uses%20port%2010000%20by,in%20on%20any%20network%20interface.
    10000: "webmin",
    5000: "docker-registry",
    # много разных приожений висит на этом порту
    9000: "any",
    # очереди
    6379: "redis",
    # в документации указывают этот порт, значит все хомячки будут его использовать
    61616: "activemq",
}

PORTS_BY_NAME = defaultdict(list)
for k, v in PORT_NAMES.items():
    PORTS_BY_NAME[v] += [k]
PORTS_BY_NAME["all"] = sorted(PORT_NAMES)
# https://docs.digicert.com/en/certcentral/certificate-tools/discovery-user-guide/set-up-and-run-a-scan.html#:~:text=Use%20Default%20to%20include%20ports,%2C%20465%2C%208443%2C%203389.&text=If%20you%20are%20using%20Server,max%2010%20ports%20per%20server
PORTS_BY_NAME["common"] = sorted(
    PORTS_BY_NAME["smtp"]
    + PORTS_BY_NAME["imap"]
    + PORTS_BY_NAME["pop"]
    + PORTS_BY_NAME["https"]
    + PORTS_BY_NAME["ldap"]
    + PORTS_BY_NAME["rdp"]
)

# Можно выбрать и получше
# for font in $(ls -1 /usr/share/figlet/ | sed -r '/_/d; s/\..*//'); do echo $font; toilet -f "$font" "tls-scan"; done
BANNER = r"""
   __  __
  / /_/ /____      ______________ _____
 / __/ / ___/_____/ ___/ ___/ __ `/ __ \
/ /_/ (__  )_____(__  ) /__/ /_/ / / / /
\__/_/____/     /____/\___/\__,_/_/ /_/
"""

print_err = partial(print, file=sys.stderr)


def print_banner() -> None:
    print_err(BANNER)


class ColorHandler(logging.StreamHandler):
    _log_colors = {
        logging.DEBUG: CYAN,
        logging.INFO: GREEN,
        logging.WARNING: RED,
        logging.ERROR: RED,
        logging.CRITICAL: RED,
    }

    _fmt = logging.Formatter("[%(levelname).1s] %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        message = self._fmt.format(record)
        return f"{self._log_colors[record.levelno]}{message}{RESET}"


class NameSpace(argparse.Namespace):
    input: TextIO
    output: TextIO
    addresses: list[str]
    ports: list[int | list[int]]
    workers_num: int
    timeout: float
    batch_size: int
    verbosity: int
    banner: bool
    help: bool


def parse_port(x: str) -> int | list[int]:
    if x.isdigit():
        return int(x)
    try:
        first, last = map(int, x.split("-"))
        return list(range(first, last))
    except ValueError:
        pass
    try:
        return PORTS_BY_NAME[x]
    except IndexError:
        raise ValueError(
            f"invalid port number, port range, or port name: {x!r}"
        )


def flatten(iterable: Iterable) -> Iterable:
    for x in iterable:
        if isinstance(x, Iterable) and not isinstance(x, (str, bytes)):
            yield from flatten(x)
        else:
            yield x


def parse_networks(addresses: list[str]) -> Iterable[IPv4Network | IPv6Network]:
    for addr in addresses:
        try:
            first, last = map(ipaddress.ip_address, addr.split("-"))
            yield from ipaddress.summarize_address_range(first, last)
        except ValueError:
            yield ipaddress.ip_network(addr)


def expand_ips(networks: Sequence[IPv4Network | IPv6Network]) -> Iterable[str]:
    yield from map(
        str,
        itertools.chain.from_iterable(networks),
    )


def get_cert_info(ip: str, port: int) -> dict:
    try:
        cert_data = ssl.get_server_certificate((ip, port))
    except (socket.timeout, socket.error):
        # logging.warning("socket error: %s", ip)
        return {}
    with tempfile.NamedTemporaryFile("w+", delete=False) as temp:
        temp.write(cert_data)
        cert_file = temp.name
    try:
        return ssl._ssl._test_decode_cert(cert_file)
    finally:
        os.unlink(cert_file)


# Если на каком-то сервере несколько портов с TLS, то нет смысла выполнять более одного раза запрос к DNS
@lru_cache(maxsize=1024)
def reverse_dns_lookup(
    addr: str,
) -> tuple[str, list[str], list[str]] | tuple[None, None, None]:
    try:
        return socket.gethostbyaddr(addr)
    except socket.herror:
        return None, None, None


class Queue(queue.Queue):
    def __init__(self, maxsize: int = 0) -> None:
        super().__init__(maxsize)
        self.total = 0

    def put(
        self, item: Any, block: bool = True, timeout: float | None = None
    ) -> None:
        super().put(item, block, timeout)
        self.total += 1


def check_tls_cert(
    ip: str,
    port: int,
    result_queue: Queue,
) -> None:
    logging.debug("check %s:%d", ip, port)
    if not (cert_dict := get_cert_info(ip, port)):
        return
    # logging.info(cert_dict)
    # {'subject': ((('organizationalUnitName', 'PVE Cluster Node'),), (('organizationName', 'Proxmox Virtual Environment'),), (('commonName', 'Pascal'),)), 'issuer': ((('commonName', 'Proxmox Virtual Environment'),), (('organizationalUnitName', '5c02d8c6-7c8d-4b2e-a4b5-8f06c0e380fd'),), (('organizationName', 'PVE Cluster Manager CA'),)), 'version': 3, 'serialNumber': '02', 'notBefore': 'Jan 23 15:26:13 2024 GMT', 'notAfter': 'Jan 22 15:26:13 2026 GMT', 'subjectAltName': (('IP Address', '127.0.0.1'), ('IP Address', '0:0:0:0:0:0:0:1'), ('DNS', 'localhost'), ('IP Address', '31.131.251.85'), ('DNS', 'Pascal'))}
    logging.info("found tls/ssl cert: %s:%d", ip, port)
    # for key in set(cert) & {"issuer", "subject"}:
    #     cert_dict[key] = dict(x[0] for x in cert_dict[key])

    res = {
        "ip": ip,
        "port": port,
        "port_name": PORT_NAMES.get(port, "unknown"),
        "cert": {
            # extensions?
            k: dict(x[0] for x in v) if k in ["issuer", "subject"] else v
            for k, v in cert_dict.items()
        },
    }

    # Reverse Domain Name Service (RDNS) records are also known as pointer (PTR) records.
    # Для почты PTR обязателен. Это один из способов узнать домен по айпи по-мимо имен в сертификате на 443 порту
    reverse_name, _, _ = reverse_dns_lookup(ip)

    if reverse_name:
        # hostname or domain
        res |= {"hostname": reverse_name}

    result_queue.put(res)


def write_results(
    output: TextIO,
    result_queue: Queue,
) -> None:
    while True:
        try:
            res = result_queue.get()
            if res is None:
                break
            json.dump(res, output, ensure_ascii=False)
            output.write(os.linesep)
            output.flush()
        finally:
            result_queue.task_done()


def parse_args(
    argv: list[str] | None,
) -> tuple[argparse.ArgumentParser, NameSpace]:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False,
    )
    parser.add_argument(
        "-a",
        "--address",
        dest="addresses",
        nargs="*",
        help="IP address, FIRST_IP-LAST-IP or CIDR",
    )
    parser.add_argument(
        "-p",
        "--port",
        dest="ports",
        nargs="*",
        type=parse_port,
        default=PORTS_BY_NAME["common"],
        help="port, FIRST_PORT-LAST_PORT or port name (e.g., https, smtp, common or all for all known)",
    )
    parser.add_argument(
        "-i",
        "--input",
        type=argparse.FileType(),
        default="-",
        help="input file containing list of IP addresses each on a new line",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=argparse.FileType("w"),
        default="-",
        help="output file with results in JSONL format",
    )
    parser.add_argument(
        "-w",
        "--workers",
        dest="workers_num",
        type=int,
        default=50,
        help="maximum number of worker threads",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="socket timeout in seconds",
    )
    parser.add_argument(
        "-b",
        "--batch-size",
        default=1024,
        type=int,
        help="batch size",
    )
    parser.add_argument(
        "--banner",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="show banner",
    )
    parser.add_argument(
        "-v",
        "--verbosity",
        action="count",
        default=0,
        help="increase verbosity level",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument("-h", "--help", action="store_true", help="show help")
    return parser, parser.parse_args(argv, NameSpace())


def main(argv: list[str] | None = None) -> None:
    tm = -time.monotonic()
    parser, args = parse_args(argv)

    if args.help:
        parser.print_help(sys.stderr)
        return 1

    addresses = list(args.addresses or [])

    if not args.input.isatty():
        addresses.extend(filter(None, map(str.strip, args.input)))

    try:
        networks = set(parse_networks(addresses))
    except ValueError as ex:
        parser.error(ex)

    ports = set(flatten(args.ports))

    if not networks or not ports:
        parser.error("nothing to scan")

    # if 1 > args.batch_size:
    #     parser.error("invalid batch size")

    logging_level = max(
        logging.DEBUG, logging.WARNING - args.verbosity * logging.DEBUG
    )

    logging.basicConfig(level=logging_level, handlers=[ColorHandler()])

    # адресов может быть миллиард, если их всех в массив загнать, то не хватит памяти
    ips = expand_ips(networks)

    if args.banner:
        print_banner()

    result_queue = Queue()

    # тупо не придумал для него тайпхинт
    # count_results = type("counter", (), {"val": 0})
    writer_thread = Thread(
        target=write_results, args=(args.output, result_queue)
    )
    writer_thread.start()

    # по умолчанию ждет 60 секунд соединения!
    socket.setdefaulttimeout(args.timeout)
    workers_num = min(max(args.workers_num, 1), 1024)
    batch_size = min(max(args.batch_size, workers_num), 1024 * 1024)
    ips_num = sum(net.num_addresses for net in networks)
    ports_num = len(ports)
    logging.info(f"{workers_num=}, {batch_size=}, {ips_num=}, {ports_num=}")
    processed_tasks = 0
    with ThreadPoolExecutor(workers_num) as pool:
        # количество заданий тоже ограничено
        for batch in batched(
            itertools.product(ips, ports),
            batch_size,
        ):
            logging.info("process batch")
            tasks = [
                pool.submit(check_tls_cert, ip, port, result_queue)
                for ip, port in batch
            ]
            for task in as_completed(tasks):
                try:
                    task.result()
                except BaseException as ex:
                    logging.exception(ex)
                finally:
                    task.cancel()
            processed_tasks += len(tasks)

    result_queue.put_nowait(None)
    writer_thread.join()

    tm += time.monotonic()
    logging.info(
        "finished at %.3fs; processed: %d; total results: %d.",
        tm,
        processed_tasks,
        result_queue.total - 1,  # None
    )


if __name__ == "__main__":
    sys.exit(main())
