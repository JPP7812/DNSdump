"""HTTP path/directory scanner — checks common paths on discovered hosts."""

import concurrent.futures
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import List, Callable, Optional


@dataclass
class PathHit:
    host: str
    path: str
    url: str
    status: int
    length: int


BUILTIN_PATH_WORDLIST = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/security.txt",
    # Admin / panels
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/admin/login", "/admin/login.php", "/admin/index.php",
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-config.php",
    "/wp-json", "/wp-content", "/xmlrpc.php",
    "/cpanel", "/panel", "/dashboard", "/console",
    "/manager", "/manager/html",
    "/phpmyadmin", "/pma", "/mysql", "/adminer.php",
    # Auth
    "/login", "/login.php", "/logout", "/signin", "/signup",
    "/register", "/forgot-password", "/reset-password",
    "/auth", "/sso", "/oauth",
    # API
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/swagger", "/swagger-ui.html", "/swagger-ui/",
    "/openapi.json", "/api-docs", "/graphql",
    # Spring Boot actuators
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/trace", "/env", "/beans",
    # Config / secrets
    "/.env", "/.env.local", "/.env.production",
    "/.htaccess", "/.htpasswd",
    "/config", "/config.php", "/config.json",
    "/config.yml", "/config.yaml",
    "/settings.php", "/settings.py",
    "/web.config",
    # Backups / dumps
    "/backup", "/backup.zip", "/backup.tar.gz",
    "/db.sql", "/database.sql", "/dump.sql",
    "/old", "/bak",
    # Install / setup
    "/install", "/install.php", "/setup", "/setup.php",
    "/installer",
    # Info / debug
    "/info.php", "/phpinfo.php", "/test.php",
    "/server-status", "/server-info",
    "/debug", "/status", "/health", "/ping",
    "/metrics", "/prometheus",
    # Dev tools
    "/git", "/.git", "/.git/config", "/.git/HEAD",
    "/jenkins", "/gitlab", "/ci",
    "/jira", "/confluence",
    "/grafana", "/kibana",
    # Files / uploads
    "/upload", "/uploads", "/files", "/file",
    "/download", "/downloads",
    "/share", "/tmp", "/temp",
    # Misc
    "/cgi-bin", "/cgi-bin/admin",
    "/crossdomain.xml",
    "/user", "/users", "/account", "/profile",
    "/private", "/secret", "/hidden",
    "/log", "/logs",
    "/error", "/404",
]


def _check_path(
    host: str, path: str, timeout: int, use_https: bool
) -> Optional[PathHit]:
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}{path}"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; dnsdump/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            length = int(resp.headers.get("Content-Length", 0))
            if status != 404:
                return PathHit(host=host, path=path, url=url,
                               status=status, length=length)
    except urllib.error.HTTPError as e:
        if e.code not in (404, 400):
            return PathHit(host=host, path=path, url=url,
                           status=e.code, length=0)
    except Exception:
        pass
    return None


def scan_paths(
    hosts: List[str],
    wordlist: List[str],
    threads: int = 20,
    timeout: int = 5,
    use_https: bool = True,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    hit_cb: Optional[Callable[[PathHit], None]] = None,
) -> List[PathHit]:
    hits: List[PathHit] = []
    tasks = [(host, path) for host in hosts for path in wordlist]
    total = len(tasks)
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(_check_path, host, path, timeout, use_https): (host, path)
            for host, path in tasks
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

    hits.sort(key=lambda h: (h.host, h.status, h.path))
    return hits


def load_path_wordlist(path: Optional[str]) -> List[str]:
    """Load path wordlist from file, or return built-in list if path is None."""
    if path is None:
        return BUILTIN_PATH_WORDLIST
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f
                     if line.strip() and not line.startswith("#")]
        return words or BUILTIN_PATH_WORDLIST
    except OSError:
        return BUILTIN_PATH_WORDLIST
