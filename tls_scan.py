#!/usr/bin/env python
"""Scan IP addresses for TLS/SSL certificates"""
import argparse
import ipaddress
import itertools
import json
import logging
import os
import socket
import ssl
import sys
import tempfile
import typing
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network
from queue import Queue
from threading import Thread

RESET = "\x1b[m"

BLACK = "\x1b[30m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
MAGENTA = "\x1b[35m"
CYAN = "\x1b[36m"
WHITE = "\x1b[37m"

SERVICE_NAMES = {
    # Базовые
    465: "smtp",
    587: "smtp",
    993: "imap",
    995: "pop",
    # vmware и многий другой софт висит на 443 и 8443 портах
    443: "https",
    8443: "https",
    # Далее пошли различные интересные приложения
    # удаленный доступ к рабочему столу
    636: "ldap",
    3389: "rdp",
    # https://docs.cpanel.net/knowledge-base/general-systems-administration/how-to-configure-your-firewall-for-cpanel-services/
    2083: "cpanel",
    2087: "whm",
    6443: "kuber",
    9443: "portainer",
    # https://pve.proxmox.com/wiki/Ports
    8006: "proxmox",
    # аналог cpanel
    # https://subscription.packtpub.com/book/cloud-and-networking/9781849515849/1/ch01lvl1sec12/connecting-to-webmin#:~:text=Webmin%20uses%20port%2010000%20by,in%20on%20any%20network%20interface.
    10000: "webmin",
}


BANNER = rf"""{GREEN}
   __  __
  / /_/ /____      ______________ _____
 / __/ / ___/_____/ ___/ ___/ __ `/ __ \
/ /_/ (__  )_____(__  ) /__/ /_/ / / / /
\__/_/____/     /____/\___/\__,_/_/ /_/
{RESET}"""


def print_banner() -> None:
    print(BANNER, file=sys.stderr)


class ColorHandler(logging.StreamHandler):
    LOG_COLORS = {
        logging.DEBUG: CYAN,
        logging.INFO: GREEN,
        logging.WARNING: RED,
        logging.ERROR: RED,
        logging.CRITICAL: RED,
    }

    _fmt = logging.Formatter("[%(levelname).1s] %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        message = self._fmt.format(record)
        return f"{self.LOG_COLORS[record.levelno]}{message}{RESET}"


class NameSpace(argparse.Namespace):
    input: typing.TextIO
    output: typing.TextIO
    addresses: list[str]
    ports: list[int | range]
    workers_num: int
    timeout: float
    verbosity: int
    banner: bool
    help: bool


def port_type(x: str) -> int | range:
    try:
        first, last = map(int, x.split("-"))
        return range(first, last)
    except ValueError:
        return int(x)


def flatten(iterable: typing.Iterable) -> typing.Iterable:
    for x in iterable:
        if isinstance(x, typing.Iterable) and not isinstance(x, typing.AnyStr):
            yield from flatten(x)
        else:
            yield x


def parse_networks(addr: str) -> typing.Iterable[IPv4Network | IPv6Network]:
    try:
        first, last = map(ipaddress.ip_address, addr.split("-"))
        yield from ipaddress.summarize_address_range(first, last)
    except ValueError:
        yield ipaddress.ip_network(addr)


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


def reverse_dns_lookup(
    addr: str,
) -> tuple[str, list[str], list[str]] | tuple[None, None, None]:
    try:
        return socket.gethostbyaddr(addr)
    except socket.herror:
        return None, None, None


def check_tls(
    ip: str,
    port: int,
    result_queue: Queue,
) -> None:
    logging.debug("check %s:%d", ip, port)
    if not (cert_dict := get_cert_info(ip, port)):
        return
    # logging.info(cert_dict)
    # {'subject': ((('organizationalUnitName', 'PVE Cluster Node'),), (('organizationName', 'Proxmox Virtual Environment'),), (('commonName', 'Pascal'),)), 'issuer': ((('commonName', 'Proxmox Virtual Environment'),), (('organizationalUnitName', '5c02d8c6-7c8d-4b2e-a4b5-8f06c0e380fd'),), (('organizationName', 'PVE Cluster Manager CA'),)), 'version': 3, 'serialNumber': '02', 'notBefore': 'Jan 23 15:26:13 2024 GMT', 'notAfter': 'Jan 22 15:26:13 2026 GMT', 'subjectAltName': (('IP Address', '127.0.0.1'), ('IP Address', '0:0:0:0:0:0:0:1'), ('DNS', 'localhost'), ('IP Address', '31.131.251.85'), ('DNS', 'Pascal'))}
    service_name = SERVICE_NAMES.get(port, "unknown")
    logging.info("found tls/ssl cert: %s:%d (%s)", ip, port, service_name)
    # for key in set(cert) & {"issuer", "subject"}:
    #     cert_dict[key] = dict(x[0] for x in cert_dict[key])

    res = {
        "ip": ip,
        "port": port,
        "service_name": service_name,
        "cert": {
            # extensions?
            k: dict(x[0] for x in v) if k in ["issuer", "subject"] else v
            for k, v in cert_dict.items()
        },
    }

    # Reverse Domain Name Service (RDNS) records are also known as pointer (PTR) records.
    reverse_name, _, _ = reverse_dns_lookup(ip)

    if reverse_name:
        # hostname or domain
        res |= {"hostname": reverse_name}

    result_queue.put(res)


@dataclass
class Counter:
    val: int = 0


def write_results(
    output: typing.TextIO,
    result_queue: Queue,
    count_results: Counter,
) -> None:
    while True:
        try:
            res = result_queue.get()
            if res is None:
                break
            json.dump(
                res,
                output,
                ensure_ascii=False,
            )
            output.write(os.linesep)
            output.flush()
            count_results.val += 1
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
        type=port_type,
        default=list(sorted(SERVICE_NAMES)),
        help="port or FIRST_PORT-LAST_PORT",
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
    parser.add_argument("-h", "--help", action="store_true", help="show help")
    return parser, parser.parse_args(argv, NameSpace())


def main(argv: list[str] | None = None) -> None:
    parser, args = parse_args(argv)

    if args.help:
        parser.print_help(sys.stderr)
        return 1

    if args.banner:
        print_banner()

    logging_level = max(
        logging.DEBUG, logging.WARNING - args.verbosity * logging.DEBUG
    )

    logging.basicConfig(level=logging_level, handlers=[ColorHandler()])

    addresses = list(args.addresses or [])
    ports = list(flatten(args.ports))

    if not args.input.isatty():
        addresses.extend(filter(None, map(str.strip, args.input)))

    addresses = list(
        map(
            str,
            itertools.chain.from_iterable(*map(parse_networks, addresses)),
        )
    )

    result_queue = Queue()
    # тупо не придумал для него тайпхинт
    # count_results = type("counter", (), {"val": 0})
    count_results = Counter()
    count_results.val
    output_thread = Thread(
        target=write_results, args=(args.output, result_queue, count_results)
    )
    output_thread.start()

    # по умолчанию ждет 60 секунд соединения!
    socket.setdefaulttimeout(args.timeout)
    with ThreadPoolExecutor(args.workers_num) as pool:
        tasks = [
            pool.submit(check_tls, ip, port, result_queue)
            for ip, port in itertools.product(addresses, ports)
        ]

    for task in as_completed(tasks):
        try:
            task.result()
        except BaseException as ex:
            logging.warning(ex)
        finally:
            task.cancel()

    result_queue.put_nowait(None)
    output_thread.join()

    logging.info(
        "Finished! Tasks: %d; Results: %d",
        len(tasks),
        count_results.val,
    )


if __name__ == "__main__":
    sys.exit(main())
