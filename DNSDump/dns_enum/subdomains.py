"""Subdomain brute-force enumerator with threading."""

import concurrent.futures
import dns.resolver
import dns.exception
from dataclasses import dataclass
from typing import List, Callable, Optional


@dataclass
class SubdomainHit:
    subdomain: str
    fqdn: str
    addresses: List[str]


def _check_subdomain(fqdn: str, nameserver: Optional[str]) -> Optional[SubdomainHit]:
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    resolver.lifetime = 3

    subdomain = fqdn.split(".")[0]
    addrs: List[str] = []

    for rtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(fqdn, rtype)
            addrs.extend(r.to_text() for r in answers)
        except Exception:
            pass

    if addrs:
        return SubdomainHit(subdomain=subdomain, fqdn=fqdn, addresses=addrs)
    return None


def enumerate_subdomains(
    domain: str,
    wordlist: List[str],
    threads: int = 50,
    nameserver: Optional[str] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    hit_cb: Optional[Callable[[SubdomainHit], None]] = None,
) -> List[SubdomainHit]:
    hits: List[SubdomainHit] = []
    total = len(wordlist)
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(_check_subdomain, f"{word}.{domain}", nameserver): word
            for word in wordlist
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

    hits.sort(key=lambda h: h.subdomain)
    return hits


# ------------------------------------------------------------------ #
# Built-in wordlist (500 common subdomains)                           #
# ------------------------------------------------------------------ #

BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "email",
    "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "relay",
    "vpn", "remote", "gateway", "fw", "firewall", "proxy", "socks",
    "api", "api2", "rest", "graphql", "grpc", "ws", "websocket",
    "admin", "administrator", "manage", "management", "panel", "cp", "cpanel",
    "portal", "dashboard", "console", "backend", "backoffice",
    "app", "app1", "app2", "apps", "mobile", "m", "wap",
    "dev", "develop", "development", "staging", "stage", "stg", "uat",
    "test", "testing", "qa", "sandbox", "demo", "beta", "alpha", "preview",
    "prod", "production", "live",
    "static", "assets", "cdn", "cdn1", "cdn2", "media", "images", "img",
    "video", "videos", "upload", "uploads", "files", "docs", "doc",
    "blog", "news", "forum", "community", "support", "help", "kb", "wiki",
    "shop", "store", "cart", "checkout", "pay", "payment", "billing",
    "status", "monitor", "metrics", "grafana", "kibana", "prometheus",
    "git", "gitlab", "github", "svn", "repo", "code", "ci", "jenkins",
    "jira", "confluence", "redmine", "tracker",
    "db", "database", "mysql", "postgres", "pgsql", "mongo", "redis",
    "elastic", "solr", "cassandra",
    "ldap", "auth", "sso", "login", "oauth", "id", "identity",
    "cloud", "aws", "azure", "gcp",
    "internal", "intranet", "corp", "office", "local",
    "v1", "v2", "v3", "old", "new", "legacy",
    "secure", "ssl", "tls",
    "smtp1", "smtp2", "mail1", "mail2", "mail3",
    "pop3", "imap4",
    "ntp", "time",
    "chat", "slack", "teams", "meet", "conference",
    "vpn1", "vpn2", "vpn3",
    "backup", "bak", "archive",
    "log", "logs", "syslog",
    "api3", "api-dev", "api-v1", "api-v2",
    "socket", "stream",
    "health", "ping", "alive",
    "crm", "erp", "hr",
    "report", "reports", "analytics",
    "www2", "www3", "web", "web1", "web2",
    "host", "host1", "host2",
    "server", "srv", "srv1", "srv2",
    "node", "node1", "node2",
    "lb", "loadbalancer", "haproxy", "nginx",
    "k8s", "kubernetes", "docker", "registry",
    "files2", "share", "sharepoint",
    "exchange", "autodiscover", "owa", "lync",
    "extranet",
    "ip", "ipv6",
    "download", "downloads",
    "update", "updates",
    "ads", "ad", "tracking",
    "search",
    "link", "links", "go", "redirect",
]


def load_wordlist(path: Optional[str]) -> List[str]:
    """Load wordlist from file, or return built-in list if path is None."""
    if path is None:
        return BUILTIN_WORDLIST

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()
                     and not line.startswith("#")]
        return words or BUILTIN_WORDLIST
    except OSError:
        return BUILTIN_WORDLIST
