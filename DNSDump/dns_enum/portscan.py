"""TCP port scanner — checks common ports on discovered hosts."""

import concurrent.futures
import socket
from dataclasses import dataclass
from typing import List, Callable, Optional


@dataclass
class PortHit:
    host: str
    port: int
    service: str
    banner: str


# Common ports with service names
COMMON_PORTS: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    111:   "RPCbind",
    135:   "MSRPC",
    139:   "NetBIOS",
    143:   "IMAP",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    587:   "SMTP/Sub",
    636:   "LDAPS",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1521:  "Oracle",
    2181:  "Zookeeper",
    2375:  "Docker",
    2376:  "Docker TLS",
    3000:  "Dev/Grafana",
    3306:  "MySQL",
    3389:  "RDP",
    4444:  "Metasploit",
    5000:  "Flask/UPnP",
    5432:  "PostgreSQL",
    5601:  "Kibana",
    5672:  "RabbitMQ",
    6379:  "Redis",
    6443:  "Kubernetes",
    7070:  "AJP/Dev",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "Jupyter",
    9000:  "PHP-FPM/SonarQube",
    9090:  "Prometheus",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch",
    11211: "Memcached",
    15672: "RabbitMQ Mgmt",
    27017: "MongoDB",
    27018: "MongoDB",
    50000: "Jenkins",
}

BUILTIN_PORT_LIST = sorted(COMMON_PORTS.keys())


def _grab_banner(sock: socket.socket) -> str:
    try:
        sock.settimeout(1.5)
        data = sock.recv(256)
        return data.decode("utf-8", errors="replace").strip()[:120]
    except Exception:
        return ""


def _check_port(host: str, port: int, timeout: float) -> Optional[PortHit]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = _grab_banner(sock)
            service = COMMON_PORTS.get(port, "unknown")
            return PortHit(host=host, port=port, service=service, banner=banner)
    except Exception:
        return None


def scan_ports(
    hosts: List[str],
    ports: Optional[List[int]] = None,
    threads: int = 100,
    timeout: float = 1.5,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    hit_cb: Optional[Callable[[PortHit], None]] = None,
) -> List[PortHit]:
    if ports is None:
        ports = BUILTIN_PORT_LIST

    hits: List[PortHit] = []
    tasks = [(host, port) for host in hosts for port in ports]
    total = len(tasks)
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(_check_port, host, port, timeout): (host, port)
            for host, port in tasks
        }
        for future in concurrent.futures.as_completed(futures):
            done += 1
            if progress_cb:
                progress_cb(done, total)
            result = future.result()
            if result:
                hits.append(result)
                if hit_cb:
                    hit_cb(result)

    hits.sort(key=lambda h: (h.host, h.port))
    return hits


def parse_port_list(raw: str) -> List[int]:
    """Parse a port spec like '22,80,443,8000-8100' into a list of ints."""
    ports: List[int] = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                pass
        elif part.isdigit():
            ports.append(int(part))
    return sorted(set(ports)) or BUILTIN_PORT_LIST
