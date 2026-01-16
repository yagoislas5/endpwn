#!/usr/bin/env python3
# =========================
# ENDPWN V1.2.4
# =========================
import argparse
import asyncio
import json
import re
import sys
import signal
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from collections import defaultdict
from typing import Set, Dict, List, Any, Tuple
import esprima
import httpx
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init
import pickle
import hashlib
from typing import Optional

init(autoreset=True)

# =========================
# =========================
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36"
TIMEOUT = 10
MAX_HTML_PAGES = 50
MAX_CONCURRENCY = 40
MAX_ROUTE_LIMIT = 1000 
IGNORE_EXT = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
    ".mp4", ".mp3", ".avi", ".mov", ".mkv",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".css",
)
NOISE_JS = (
    "google-analytics", "gtag", "googletagmanager",
    "hotjar", "mixpanel", "segment",
    "sentry", "datadog", "newrelic",
    "clarity", "fullstory",
)
ENDPOINT_REGEX = re.compile(
    r'(["\'`])((?:/|\.\./|\./|https?:\/\/)[^"\'`\s]+(?:\.(?:js|json|php|bak|txt|xml|html|css|py|rb|asp|aspx|jsp|sql|db|zip|tar|gz|7z|rar|log|conf|config|ini|yaml|yml|toml|env|htaccess|htpasswd|git|svn|cvs|bak|~|old|backup|swp|tmp|temp|swo|swp|bak1|bak2|bak3))?)(\?.*)?\1',
    re.I
)
DYNAMIC_PATTERNS = re.compile(r'/(:[^/]+|\{[^}]+\}|\$\{[^}]+\})')
REACT_ROUTE_KEYS = ("path", "to", "href")
REACT_ROUTE_FUNCS = ("navigate", "push", "replace", "Link", "useNavigate")
FETCH_FUNCS = ("fetch", "axios", "XMLHttpRequest", "$http")
CLASSIFY_REGEX = {
    "auth": re.compile(r"auth|login|token|oauth", re.I),
    "admin": re.compile(r"admin|manage|panel|internal", re.I),
    "api": re.compile(r"/api/|/v\d+/", re.I),
    "graphql": re.compile(r"graphql", re.I),
    "debug": re.compile(r"debug|test|staging", re.I),
    "upload": re.compile(r"upload|file|media", re.I),
    "export": re.compile(r"export|download", re.I),
    "backup": re.compile(r"\.bak|\.old|\.backup|\.swp|\.tmp", re.I),
    "sensitive": re.compile(r"\.env|\.git|\.svn|config\.|secret|key|pass|token|private|credentials", re.I),
    "payment": re.compile(r"pay(ment)?|bill(ing)?|checkout|stripe|paypal|invoice|subscri(be|ption)|charge|order", re.I),
    "config": re.compile(r"config|settings|setup|preferences", re.I),
    "user": re.compile(r"user|account|profile|member", re.I),
    "data": re.compile(r"data|db|database|sql|query", re.I),
}
CLASSIFY_COLORS = {
    "auth": Fore.BLUE,
    "admin": Fore.RED,
    "api": Fore.GREEN,
    "graphql": Fore.MAGENTA,
    "debug": Fore.YELLOW,
    "upload": Fore.CYAN,
    "export": Fore.WHITE,
    "backup": Fore.LIGHTRED_EX,
    "sensitive": Fore.LIGHTMAGENTA_EX,
    "payment": Fore.LIGHTGREEN_EX,
    "config": Fore.LIGHTYELLOW_EX,
    "user": Fore.LIGHTBLUE_EX,
    "data": Fore.LIGHTCYAN_EX,
    "other": Fore.LIGHTBLACK_EX,
}
STATUS_COLORS = {
    200: Fore.GREEN, 201: Fore.GREEN, 204: Fore.GREEN,
    301: Fore.YELLOW, 302: Fore.YELLOW,
    401: Fore.RED, 403: Fore.RED,
    404: Fore.LIGHTBLACK_EX, 500: Fore.RED,
}
CLASS_PRIORITY = {
    "admin": 10,
    "payment": 9,
    "sensitive": 8,
    "data": 8,
    "auth": 7,
    "config": 7,
    "api": 6,
    "graphql": 5,
    "user": 5,
    "debug": 4,
    "upload": 3,
    "export": 2,
    "backup": 1,
    "other": 0,
}
MAX_JS_DEPTH = 10
EXPLOIT_VALUES = [
    "admin", "administrator", "root", "superuser", "sysadmin",
    "user", "guest", "anonymous", "public",

    "true", "false", "1", "0", "-1", "yes", "no", "on", "off",

    "debug", "test", "testing", "dev", "development", "staging", "internal",

    "null", "none", "nil", "undefined", "NaN", "", " ",

    "all", "*", "self", "me", "current",
    "000", "001", "999", "1000", "2147483647",

    "token", "session", "sid", "jwt", "oauth", "apikey"
]

CONTEXT_VALUES = {
    "admin": [
        "true", "1", "yes", "root", "superuser", "enabled", "-1"
    ],
    "user": [
        "self", "me", "current", "guest", "anonymous", "public"
    ],
    "debug": [
        "true", "1", "on", "enabled", "verbose", "trace"
    ],
    "auth": [
        "token", "session", "sid", "jwt", "oauth", "apikey", "bearer"
    ],
    "api": [
        "v1", "v2", "v3", "beta", "alpha", "latest", "internal"
    ],
    "id": [
        "0", "1", "-1", "999", "1000", "all", "*", "11111111-1111-1111-1111-111111111111", "00000000-0000-0000-0000-000000000000", "556ee400-e21b-413d-a776-446655440001"
    ],
    "payment": [
        "checkout", "invoice", "order", "refund", "test", "sandbox"
    ],
    "env": [
        "dev", "test", "staging", "prod", "production"
    ],
    "other": []
}

MAX_JSON_DEPTH = 7

SEMANTIC_DEPTH_LIMIT = 6

BACKUP_EXTS = [
    ".bak", ".backup", ".old", ".orig", ".tmp", ".temp",
    "~", ".swp", ".swo",
    ".txt", ".log", ".debug",
    ".config", ".cfg", ".conf",
    ".ini", ".yaml", ".yml", ".toml",
    ".env", ".env.local", ".env.prod"
]

BACKUP_SUFFIX_REGEX = re.compile(
    r'(\.(?:orig|cfg|conf|ini|log|txt|yaml|yml|toml|temp|tmp|bak|backup|debug)|~)$',
    re.I
)

VARIANT_FILE_EXTS = (
    ".js", ".map",
    ".json",
    ".php", ".phtml",
    ".xml",
    ".txt",
    ".config", ".cfg", ".conf",
    ".yaml", ".yml"
)

SOFT_404_PATTERNS = [
    r"page you are looking for does not exist",
    r"page not found",
    r"404",
    r"not found",
    r"doesn't exist",
    r"does not exist",
    r"no existe",
    r"página no encontrada",
    r"recurso no encontrado",
    r"error 404",
    r"nothing here",
    r"oops.*not found",
    r"not exist",
    r"Back to home",
    r"Hups!",
    r"Hups",
    r"hups",
    r"hoops",
]
SOFT_404_REGEX = re.compile(
    "|".join(SOFT_404_PATTERNS),
    re.I
)

KEYWORDS = {
    "ID": re.compile(
        r'\b(id|userId|accountId|clientId|sessionId)\b\s*[:=]\s*["\']?([a-zA-Z0-9_-]{6,64})["\']?',
        re.I
    ),
    "TK": re.compile(
        r'\b(token|apiKey|apikey|authToken|accessToken)\b\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,200})["\']?',
        re.I
    ),
    "JWT": re.compile(
        r'\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b'
    ),
    "PW": re.compile(
        r'\b(password|passwd|pwd|secret)\b\s*[:=]\s*["\']([^"\']{6,100})["\']',
        re.I
    ),
    "FUNC": re.compile(
        r'\b(function\s+([a-zA-Z0-9_]{3,})\b|([a-zA-Z0-9_]{3,})\s*=\s*function\b|([a-zA-Z0-9_]{3,})\s*=\s*\([^)]*\)\s*=>)',
        re.I
    ),
    "GH": re.compile(
        r'\bhttps?:\/\/github\.com\/[a-zA-Z0-9_.-]{1,39}\/[a-zA-Z0-9_.-]{1,100}(?:\/[^\s"\'<>]*)?',
        re.I
    ),
    "GH_RAW": re.compile(
        r'\bhttps?:\/\/raw\.githubusercontent\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+\/[^\s"\'<>]+',
        re.I
    ),
    "GH_TOKEN": re.compile(
        r'\bgh[pousr]_[a-zA-Z0-9]{36,255}\b|\bgithub_pat_[a-zA-Z0-9_]{20,255}\b',
        re.I
    )
    "JS_MAP": re.compile(
        r'\b[a-zA-Z0-9._-]{4,100}\.js\.map\b',
        re.I
    )
}

TYPE_STYLES = {
    "js":  ("JS", Fore.YELLOW),
    "json":("J",  Fore.LIGHTYELLOW_EX),
    "php": ("PHP",Fore.MAGENTA),
    "html":("HTML",Fore.CYAN),
    "xml": ("XML",Fore.BLUE),
    "txt": ("TXT",Fore.WHITE),
    "other":("EP", Fore.LIGHTBLACK_EX),
}

FINDING_COLORS = {
        "ID": Fore.CYAN,
        "GH": Fore.MAGENTA,
        "GH_RAW": Fore.LIGHTMAGENTA_EX,
        "GH_TOKEN": Fore.RED,
        "TK": Fore.YELLOW,
        "JWT": Fore.RED,
        "PW": Fore.LIGHTRED_EX,
        "FUNC": Fore.GREEN,
}

# =========================
# =========================
def detect_type(url: str, content_type: str) -> str:
    u = url.lower()
    ct = (content_type or "").lower()

    if u.endswith(".js") or "javascript" in ct:
        return "js"
    if u.endswith(".json") or "application/json" in ct:
        return "json"
    if u.endswith(".php"):
        return "php"
    if "text/html" in ct:
        return "html"
    if "xml" in ct:
        return "xml"
    if u.endswith(".txt"):
        return "txt"
    return "other"

def split_backup_variant(url: str) -> tuple[str, str | None]:
    m = BACKUP_SUFFIX_REGEX.search(url)
    if not m:
        return url, None
    return url[:m.start()], m.group(1)

async def analyze_for_secrets(url: str, code: str, findings: List[str]):
    for key, regex in KEYWORDS.items():
        for match in regex.findall(code):
            if isinstance(match, tuple):
                val = match[-1]
            else:
                val = match
            if val and len(val) > 0 and len(val) < 150:
                findings.append(f"[{key}] {url} : {val}")
                
class State:
    def __init__(self, max_requests: int, directory_focused: bool, route_limit: int):
        self.max_requests = max_requests
        self.requests = 0
        self.stop = False

        self.seen_js: Set[str] = set()
        self.js_graph: Dict[str, Set[str]] = defaultdict(set)

        self.endpoints: Dict[str, Dict[str, Any]] = {}
        self.routes: Set[str] = set()

        self.semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

        self.canon_to_original: Dict[str, str] = {}
        self.js_list: List[str] = []
        self.php_list: List[Dict] = []
        self.ep_list: List[Dict] = []

        self.base_netloc = ""
        self.base_domain = ""

        self._processing_variants = set()
        self.successful_bypasses: List[str] = []
        self.bypassed: Set[str] = set()

        self.home_metrics = None
        self.home_length = 0
        self.home_hash = ""
        self.home_content_type = ""

        self.dynamic_urls: List[str] = []

        self.directory_focused = directory_focused
        self.route_limit = route_limit

    def register_request(self):
        self.requests += 1
        if self.requests >= self.max_requests:
            self.stop = True


    def can_request(self) -> bool:
        return self.requests < self.max_requests and not self.stop


    def classify(self, url: str) -> str:
        for k, rx in CLASSIFY_REGEX.items():
            if rx.search(url):
                return k
        return "other"

    def canonical_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            path = parsed.path
            path = re.sub(r'/:[^/]+', '/<dynamic>', path)
            path = re.sub(r'/\{[^}]+\}', '/<dynamic>', path)
            path = re.sub(r'/\$\{[^}]+\}', '/<dynamic>', path)
            path = path.rstrip('/') if path != '/' else '/'
            query_parts = parse_qs(parsed.query)
            sorted_items = [(k, v) for k in sorted(query_parts) for v in sorted(query_parts[k])]
            sorted_query = urlencode(sorted_items, doseq=True)
            return parsed._replace(path=path, query=sorted_query, fragment='').geturl()
        except:
            return url

    def extract_params(self, url: str) -> List[str]:
        try:
            parsed = urlparse(url)
            return list(parse_qs(parsed.query).keys())
        except:
            return []

    def is_route(self, url: str) -> bool:
        parsed = urlparse(url)
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in IGNORE_EXT):
            return False
        if '.' in path.split('/')[-1]:
            return False
        return True

    async def add_endpoint(self, url: str, source: str, mark_doubtful: bool = False, allow_host_mismatch: bool = False):
        if url.lower().endswith(IGNORE_EXT):
            return
        netloc = urlparse(url).netloc
        domain = '.'.join(netloc.split('.')[-2:]) if len(netloc.split('.')) > 1 else netloc
        if source == "historical" and allow_host_mismatch:
            pass
        elif netloc != self.base_netloc and not netloc.endswith("." + self.base_netloc):
            return

        canon = self.canonical_url(url)
        if canon in self.canon_to_original:
            return 
        self.canon_to_original[canon] = url
        cls = self.classify(url)
        params = self.extract_params(url)
        has_params = bool(params)
        is_dynamic = bool(DYNAMIC_PATTERNS.search(urlparse(url).path))
        is_route = self.is_route(url)
        if is_route and len(self.routes) >= self.route_limit and not self.directory_focused:
            return  
        host_mismatch = (netloc != self.base_netloc and not netloc.endswith("." + self.base_netloc))
        self.endpoints[url] = {
            "url": url,
            "source": source,
            "class": cls,
            "status": None,
            "content_type": None,
            "params": params,
            "has_params": has_params,
            "http_method": None,
            "headers": {},
            "body_params": [],
            "sensitive": False,
            "is_dynamic": is_dynamic,
            "is_route": is_route,
            "fallback": False,
            "doubtful": mark_doubtful, 
            "inferred": False,
            "historical": False,
            "fallback_candidate": False, 
            "host_mismatch": host_mismatch,
            "fallback_status": None,  
        }
        if is_dynamic:
            self.dynamic_urls.append(url)
        if is_route:
            self.routes.add(url)

# =========================
# LOGGING
# =========================
def log_info(msg: str):
    print(f"{Fore.CYAN}[+] {msg}{Style.RESET_ALL}")

def log_js(msg: str):
    print(f"{Fore.YELLOW}[JS] {msg}{Style.RESET_ALL}")

def log_ep(msg: str, status: int = None, cls: str = "other"):
    color = STATUS_COLORS.get(status, Fore.GREEN) if status else Fore.GREEN
    class_color = CLASSIFY_COLORS.get(cls, Fore.LIGHTBLACK_EX)
    print(f"{color}[EP] {class_color}{msg}{Style.RESET_ALL}")

def log_err(msg: str):
    print(f"{Fore.RED}[!] {msg}{Style.RESET_ALL}")

def log_progress(msg: str):
    print(f"{Fore.LIGHTBLUE_EX}[PROG] {msg}{Style.RESET_ALL}")

# =========================
# U
# =========================
def same_domain(url: str, base: str, allow_sub: bool) -> bool:
    try:
        u = urlparse(url).netloc
        b = urlparse(base).netloc
        return u == b or (allow_sub and u.endswith("." + b))
    except:
        return False

def normalize(base: str, link: str) -> Optional[str]:
    try:
        return urljoin(base, link.strip())
    except:
        return None

def ignored(url: str) -> bool:
    return url.lower().endswith(IGNORE_EXT)

def is_noise_js(url: str) -> bool:
    return any(n in url.lower() for n in NOISE_JS)

def alternate_case(s: str) -> str:
    return ''.join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(s))

def get_dom_metrics(html: str) -> Tuple[int, int, int, bool, bool, int, bool]:
    soup = BeautifulSoup(html, "html.parser")
    forms = len(soup.find_all('form'))
    scripts = len(soup.find_all('script'))
    
    def max_depth(element, depth=0):
        children_with_contents = [child for child in element.contents if hasattr(child, 'contents')]
        if not children_with_contents:
            return depth
        return max(max_depth(child, depth + 1) for child in children_with_contents)
    
    dom_depth = max_depth(soup)
    has_bootstrap = any("root" in str(tag) or "app" in str(tag) for tag in soup.find_all(id=True))
    has_js_redirect = bool(re.search(r'window\.location|history\.pushstate', html, re.I))
    links = len(soup.find_all('a')) 
    has_framework = any(x in html.lower() for x in ["react", "angular", "vue", "svelte", "next.js", "nuxt"]) 
    return forms, scripts, dom_depth, has_bootstrap, has_js_redirect, links, has_framework

def metrics_similar(m1: Tuple, m2: Tuple) -> bool:
    f1, s1, d1, b1, r1, l1, fw1 = m1
    f2, s2, d2, b2, r2, l2, fw2 = m2
    return (
        abs(f1 - f2) <= 1 and
        abs(s1 - s2) <= 2 and
        abs(d1 - d2) <= 3 and
        abs(l1 - l2) <= 5 and 
        b1 == b2 and
        r1 == r2 and
        fw1 == fw2
    )
    
def is_soft_404(r: httpx.Response) -> bool:
    try:
        content_type = r.headers.get("content-type", "").lower()
        if "text/html" not in content_type:
            return False

        try:
            body = r.text
        except UnicodeDecodeError:
            body = r.content.decode("utf-8", errors="ignore")
        body = body.lower()


        if SOFT_404_REGEX.search(body):
            return True

        m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
        if m and SOFT_404_REGEX.search(m.group(1)):
            return True

        if r.headers.get("x-error") or r.headers.get("x-not-found"):
            return True

    except Exception:
        pass

    return False



def is_fallback_response(
    original_url: str,
    r: httpx.Response,
    home_metrics: Tuple,
    home_hash: str,
    home_length: int,
    home_content_type: str
) -> str:
    import hashlib
    from urllib.parse import urlparse
    
    STATIC_EXTENSIONS = (
        ".js", ".css", ".map",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
        ".woff", ".woff2", ".ttf", ".eot",
        ".ico",
        ".pdf",
        ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z",
        ".bak", ".backup", ".old", ".tmp", ".swp",
        ".log",
        ".env", ".ini", ".conf", ".config",
        ".sql", ".db",
    )

    IMPOSSIBLE_PATH_MARKERS = (
        "/node_modules/",
        "/usr/",
        "/etc/",
        "/bin/",
        "/sbin/",
        "/lib/",
        "/var/",
        "/tmp/",
        "/proc/",
        "/sys/",
    )

    SPA_MARKERS = (
        "react-dom",
        "angular",
        "vue",
        "svelte",
        "next.js",
        "nuxt",
        "id=\"root\"",
        "id=\"app\"",
        "__next_data__",
        "window.__nuxt__",
    )

    NAVIGATION_MARKERS = (
        "<nav",
        "<header",
        "<footer",
        "<main",
        "router",
        "history.push",
    )

    def path_entropy(path: str) -> float:
        if not path:
            return 0.0
        return len(set(path)) / max(len(path), 1)

    content_type = r.headers.get("content-type", "").lower()
    if not content_type:
        return "no"

    if any(x in content_type for x in (
        "application/json",
        "application/xml",
        "image/",
        "font/",
        "video/",
        "audio/",
    )):
        return "no"

    if "text/html" not in content_type:
        return "no"

    if is_soft_404(r):
        return "no"

    parsed = urlparse(original_url)
    path = parsed.path.lower()

    if path.endswith(STATIC_EXTENSIONS):
        return "no"

    if any(x in path for x in IMPOSSIBLE_PATH_MARKERS):
        return "no"

    if len(path) > 60 and path_entropy(path) > 0.55:
        return "no"

    body = r.text.lower()
    final_url = str(r.url)
    signals = 0.0

    if not any(x in body for x in NAVIGATION_MARKERS):
        return "no"

    signals += 1.0 

    parsed_final = urlparse(final_url)
    if final_url != original_url and parsed_final.path in ("/", "/login", "/login/"):
        signals += 1.0

    try:
        this_metrics = get_dom_metrics(r.text)
        if home_metrics and metrics_similar(this_metrics, home_metrics):
            signals += 1.0
    except Exception:
        pass

    try:
        this_hash = hashlib.md5(r.content).hexdigest()
        if home_hash and this_hash == home_hash:
            signals += 1.5
    except Exception:
        pass

    try:
        length_diff = abs(len(r.content) - home_length)
        if home_length and length_diff < max(500, home_length * 0.05):
            signals += 1.0
    except Exception:
        pass

    if any(x in body for x in SPA_MARKERS):
        signals += 1.0
        
    server_hdr = r.headers.get("server", "").lower()
    if any(x in server_hdr for x in ("cloudflare", "akamai", "fastly")):
        signals -= 0.5

    if any(x in body for x in ("login", "signin", "sign in")):
        signals -= 0.5


    if signals >= 3.0:
        return "confirmed"
    elif signals >= 1.5:
        return "uncertain"
    return "no"



def infer_parent_routes(url: str) -> List[str]:
    parsed = urlparse(url)
    if "/api/" in parsed.path.lower():
        return []
    segments = parsed.path.strip("/").split("/")
    parents = []
    current = ""
    for seg in segments[:-1]:
        current += "/" + seg
        parents.append(parsed._replace(path=current, query="", fragment="").geturl())
    return parents


# =========================
# DISCOVERY PHASE
# =========================
class JSAnalyzer:
    def __init__(self, base_url: str, allow_subdomains: bool, state: State):
        self.base = base_url
        self.allow_subdomains = allow_subdomains
        self.js_depth: Dict[str, int] = {}
        self.state = state

    async def analyze_js(self, client: httpx.AsyncClient, url: str, depth: int = 0):
        if url in self.state.seen_js or depth > MAX_JS_DEPTH:
            return
        if url.lower().endswith(".js") and "://" in url and not is_noise_js(url):
            if url not in self.state.js_list:
                self.state.js_list.append(url)
                log_js(url)
        self.state.seen_js.add(url)

        try:
            async with self.state.semaphore:
                if not self.state.can_request():
                    return
                self.state.register_request()
                try:
                    r = await client.get(url, timeout=TIMEOUT)
                    code = r.text
                except UnicodeDecodeError:
                    code = r.content.decode("utf-8", errors="ignore")

            for _, path, _ in ENDPOINT_REGEX.findall(code):
                ep = normalize(url, path)
                if ep and same_domain(ep, self.base, self.allow_subdomains) and not ignored(ep):
                    await self.state.add_endpoint(ep, "js-regex", mark_doubtful=True)

            new_endpoints = set()
            
            findings = getattr(self.state, "findings", [])
            await analyze_for_secrets(url, code, findings)
            self.state.findings = findings

            try:
                tree = esprima.parseModule(code, tolerant=True)
            except Exception:
                tree = None

            if tree:
                def walk(node):
                    if isinstance(node, dict):
                        node_type = node.get("type")
                        if node_type == "CallExpression":
                            callee = node.get("callee", {})
                            if callee.get("type") == "Identifier" and callee.get("name") in FETCH_FUNCS:
                                args = node.get("arguments", [])
                                if args and args[0].get("type") == "Literal" and isinstance(args[0].get("value"), str):
                                    val = args[0]["value"]
                                    ep = normalize(url, val)
                                    if ep and ep not in self.state.seen_js:
                                        new_endpoints.add(ep)
                        for v in node.values() if node else []:
                            if isinstance(v, (dict, list)):
                                walk(v)
                    elif isinstance(node, list):
                        for i in node:
                            walk(i)

                walk(tree.body)

                for ep in new_endpoints:
                    if same_domain(ep, self.base, self.allow_subdomains) and not ignored(ep):
                        await self.state.add_endpoint(ep, "js-fetch")

            try:
                import_rx = re.compile(r'import\((["\'`])(.+?)\1\)', re.I)
                for _, imp_path in import_rx.findall(code):
                    imp_url = normalize(url, imp_path)
                    if imp_url and same_domain(imp_url, self.base, self.allow_subdomains) and not ignored(imp_url):
                        await self.analyze_js(client, imp_url, depth + 1)
            except Exception as e:
                log_err(f"Error handling dynamic imports in {url} : {e}")

            if url.endswith(".js"):
                await self.analyze_sourcemap(client, url)

        except Exception as e:
            log_err(f"Error analyzing JS {url} : {e}")


    async def analyze_sourcemap(self, client: httpx.AsyncClient, js_url: str):
        map_url = js_url + ".map"
        r = await client.get(map_url, timeout=TIMEOUT)
        if r.status_code == 200:
            try:
                try:
                    sm = r.json()
                except Exception:
                    try:
                        sm = json.loads(r.content.decode("utf-8", errors="ignore"))
                    except Exception:
                        sm = None
                if sm:
                    for orig in sm.get("sources", []):
                        clean_path = re.sub(r'^(webpack:///\.?/|~|@|\?\?)/?', '', orig)
                        ep = normalize(js_url, clean_path)
                        if ep and same_domain(ep, self.base, self.allow_subdomains) and not ignored(ep) and not is_noise_js(ep):
                            await self.state.add_endpoint(ep, "sourcemap-path")
            except Exception:
                pass


class HTMLCrawler:
    def __init__(self, base_url: str, allow_subdomains: bool, js_engine: JSAnalyzer, state: State):
        self.base = base_url
        self.allow_subdomains = allow_subdomains
        self.js = js_engine
        self.visited: Set[str] = set()
        self.queue: List[str] = [base_url]
        self.state = state

    async def crawl(self, client: httpx.AsyncClient):
        while self.queue and len(self.visited) < MAX_HTML_PAGES and self.state.can_request():
            url = self.queue.pop(0)
            if url in self.visited:
                continue
            path_segments = len(urlparse(url).path.strip('/').split('/'))
            if path_segments > SEMANTIC_DEPTH_LIMIT:
                continue
            self.visited.add(url)
            log_info(f"HTML {url} ({len(self.visited)}/{MAX_HTML_PAGES})")
            try:
                async with self.state.semaphore:
                    if not self.state.can_request():
                        return
                    self.state.register_request()
                    r = await client.get(url, timeout=TIMEOUT)


                if "text/html" not in r.headers.get("content-type", ""):
                    continue
                soup = BeautifulSoup(r.text, "html.parser")
                for s in soup.find_all("script", src=True):
                    js_url = normalize(url, s["src"])
                    if js_url and same_domain(js_url, self.base, self.allow_subdomains) and not ignored(js_url) and not is_noise_js(js_url):
                        await self.js.analyze_js(client, js_url)
              
                for tag in soup.find_all(["a", "form"]):
                    attr = tag.get("href") or tag.get("action")
                    if attr:
                        nxt = normalize(url, attr)
                        if nxt and same_domain(nxt, self.base, self.allow_subdomains) and not ignored(nxt):
                            if nxt not in self.visited and nxt not in self.queue:
                                await self.state.add_endpoint(nxt, "html")
                                if len(self.visited) + len(self.queue) < MAX_HTML_PAGES:
                                    if self.state.directory_focused and self.state.is_route(nxt):
                                        self.queue.insert(0, nxt)
                                    else:
                                        self.queue.append(nxt)

            except Exception as e:
                log_err(f"Error crawling {url} : {e}")

async def historical_discover(client: httpx.AsyncClient, base_url: str, state: State):
    base_netloc = urlparse(base_url).netloc
    cdx_url = f"https://web.archive.org/cdx/search/cdx?url={base_netloc}/*&output=json&fl=original&collapse=urlkey&limit=1000"
    try:
        async with state.semaphore:
            if not state.can_request():
                return
            state.register_request()
            r = await client.get(cdx_url, timeout=TIMEOUT)

        if r.status_code == 200:
            data = r.json()
            try:
                data = r.json()
            except Exception:
                data = []
            for entry in data[1:]:
                if not entry or len(entry) < 1:
                    continue
                ep = entry[0]
                if same_domain(ep, base_url, False) or '.'.join(urlparse(ep).netloc.split('.')[-2:]) == state.base_domain:
                    await state.add_endpoint(ep, "historical", mark_doubtful=True, allow_host_mismatch=True)
                    if ep in state.endpoints:
                        state.endpoints[ep]["historical"] = True
                        state.endpoints[ep]["doubtful"] = True

    except Exception as e:
        log_err(f"Historical discovery error : {e}")

# =========================
# ANALYSIS PHASE
# =========================
async def analyze_endpoints(state: State):
    for url in list(state.endpoints.keys()):
        parents = infer_parent_routes(url)
        for parent in parents:
            await state.add_endpoint(parent, "inferred-parent", mark_doubtful=True)
            if parent in state.endpoints:
                state.endpoints[parent]["inferred"] = True

    for dyn_url in list(set(state.dynamic_urls)):
        if dyn_url not in state.endpoints:
            continue
        source = state.endpoints[dyn_url]["source"]
        parsed = urlparse(dyn_url)
        clean_path = DYNAMIC_PATTERNS.sub('', parsed.path)
        clean_path = re.sub(r'//+', '/', clean_path)
        clean_url = parsed._replace(path=clean_path, query='', fragment='').geturl()
        await state.add_endpoint(clean_url, source + "-clean", mark_doubtful=True)

        if clean_url in state.endpoints:
            state.endpoints[clean_url]["fallback_candidate"] = True
            state.endpoints[clean_url]["inferred"] = True

        cls = state.endpoints[dyn_url]["class"]
        values = EXPLOIT_VALUES + CONTEXT_VALUES.get(cls, [])
        for val in values:
            var_path = DYNAMIC_PATTERNS.sub(lambda m: f'/{val}', parsed.path)
            var_path = re.sub(r'//+', '/', var_path)
            var_url = parsed._replace(path=var_path, query='', fragment='').geturl()
            if var_url != dyn_url:
                if var_url not in state.canon_to_original:
                    await state.add_endpoint(var_url, source + "-variant", mark_doubtful=True)
                    if var_url in state.endpoints:
                        state.endpoints[var_url]["inferred"] = True

    for url in list(state.endpoints.keys()):
        if url.lower().endswith(VARIANT_FILE_EXTS):
            source = state.endpoints[url]["source"]
            for ext in BACKUP_EXTS:
                var_url = url + ext
                await state.add_endpoint(var_url, source + "-backup", mark_doubtful=True)
                if var_url in state.endpoints:
                    state.endpoints[var_url]["inferred"] = True

# =========================
# VALIDATION PHASE
# =========================
async def get_home_metrics(client: httpx.AsyncClient, home_url: str, state: State):
    async with state.semaphore:
        if not state.can_request():
            return
        state.register_request()
        try:
            r = await client.get(home_url, timeout=TIMEOUT)
            if r.status_code == 200 and 'text/html' in r.headers.get("content-type", ""):
                state.home_content_type = r.headers.get("content-type", "")
                state.home_length = len(r.content)
                state.home_hash = hashlib.md5(r.content).hexdigest()
                try:
                    html = r.text
                except UnicodeDecodeError:
                    html = r.content.decode("utf-8", errors="ignore")
                state.home_metrics = get_dom_metrics(html)
        except Exception as e:
            log_err(f"Error getting home metrics : {e}")
            state.home_metrics = (0, 0, 0, False, False, 0, False) 
            state.home_length = 0
            state.home_hash = ''

async def check_if_fallback(client: httpx.AsyncClient, url: str, state: State) -> str:
    async with state.semaphore:
        if not state.can_request():
            return 'no'
        try:
            state.register_request()
            r = await client.get(url, timeout=TIMEOUT)
            if r.status_code != 200:
                return 'no'
            if state.home_metrics is None:
                return 'uncertain'
            return is_fallback_response(
                url,
                r,
                state.home_metrics,
                state.home_hash,
                state.home_length,
                state.home_content_type
            )
        except:
            return 'no'


async def try_bypasses(client: httpx.AsyncClient, url: str, original_response: httpx.Response, state: State):
    parsed = urlparse(url)
    path = parsed.path
    if not path or path == "/":
        return

    rel = path.lstrip("/")

    variants = [
        path + "/.",
        "//" + rel + "//",
        path.rstrip("/") + "/..",
        "/." + rel,
        "/%2e/" + rel,
        "/%2e%2e/" + rel,
        "/%252e/" + rel,
        "/" + rel + "%2f",
        "/;%2f" + rel,
        "/.%2f" + rel,
        "/" + alternate_case(rel),
    ]

    orig_len = len(original_response.content)
    orig_hash = hashlib.md5(original_response.content).hexdigest()
    orig_type = original_response.headers.get("content-type", "")

    for p in variants:
        var_url = parsed._replace(path=p, query="", fragment="").geturl()
        if var_url in state.successful_bypasses:
            continue

        async with state.semaphore:
            if not state.can_request():
                return
            try:
                state.register_request()
                r = await client.get(var_url, timeout=TIMEOUT)
            except Exception:
                continue

        if r.status_code == 200:
            if (
                len(r.content) != orig_len or
                r.headers.get("content-type", "") != orig_type or
                hashlib.md5(r.content).hexdigest() != orig_hash
            ):
                state.successful_bypasses.append(var_url)
                state.bypassed.add(url)


def check_if_fallback_from_response(
    url: str,
    r: httpx.Response,
    state: State
) -> str:
    if r.status_code != 200:
        return "no"
    if state.home_metrics is None:
        return "uncertain"
    return is_fallback_response(
        url,
        r,
        state.home_metrics,
        state.home_hash,
        state.home_length,
        state.home_content_type
    )


async def validate_url(client: httpx.AsyncClient, url: str, state: State, verbose: bool):
    async with state.semaphore:
        if not state.can_request():
            return

        try:
            state.register_request()
            r = await client.get(url, timeout=TIMEOUT)

            status = r.status_code
            if status == 404:
                return

            ep = state.endpoints.get(url)
            if not ep:
                return
            ep = dict(ep)
            ep["status"] = status
            ep["content_type"] = r.headers.get("content-type", "")


            fallback_status = "no"
            if status in (200, 403):
                fallback_status = check_if_fallback_from_response(url, r, state)

            ep["fallback_status"] = fallback_status
            ep["fallback"] = fallback_status == "confirmed"

            if status == 200:
                content_type = ep["content_type"].lower()

                if "text/html" in content_type and is_soft_404(r):
                    return

                try:
                    home_hash = state.home_hash
                    home_length = state.home_length

                    this_hash = hashlib.md5(r.content).hexdigest()
                    length_diff = abs(len(r.content) - home_length)

                    if (
                        home_hash
                        and this_hash == home_hash
                        and length_diff < max(300, home_length * 0.03)
                    ):
                        return
                except Exception:
                    pass

                if (
                    fallback_status == "no"
                    and ep.get("inferred")
                    and ep.get("doubtful")
                ):
                    return

            cls = ep["class"]

            if verbose:
                log_ep(f"{url} [{status}] ({cls})", status=status, cls=cls)

            if False and status == 403:
                await try_bypasses(client, url, r, state)

            if status in (200, 401, 403):
                entry = {
                    "url": url,
                    "status": status,
                    "class": cls,
                    "priority": CLASS_PRIORITY.get(cls, 0),
                    "is_dynamic": ep.get("is_dynamic", False),
                    "fallback": ep.get("fallback", False),
                    "doubtful": ep.get("doubtful", False),
                    "inferred": ep.get("inferred", False),
                    "historical": ep.get("historical", False),
                    "fallback_status": fallback_status,
                    "bypassed": url in state.bypassed,
                    "content_type": ep.get("content_type", "")
                }
                t = detect_type(ep["url"], ep.get("content_type", ""))


                if url.lower().endswith(".php"):
                    state.php_list.append(entry)
                else:
                    state.ep_list.append(entry)

        except Exception as e:
            log_err(f"Error validating {url} : {e}")



async def extract_from_json(data: Any, base: str, client: httpx.AsyncClient, state: State, depth: int = 0):
    if depth > MAX_JSON_DEPTH:
        return
    if isinstance(data, dict):
        for v in data.values():
            await extract_from_json(v, base, client, state, depth + 1)
    elif isinstance(data, list):
        for item in data:
            await extract_from_json(item, base, client, state, depth + 1)
    elif isinstance(data, str):
        for _, path, _ in ENDPOINT_REGEX.findall(data):
            ep = normalize(base, path)
            if ep and same_domain(ep, base, True):
                if ep not in state.endpoints:
                    await state.add_endpoint(ep, "json-extract")

# =========================
# MAIN
# =========================
async def main(args):
    global state
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    allow_sub = args.sub_domain
    verbose = args.verbose
    enum_only = args.enum_only
    directory_focused = args.directory_focused
    max_requests = args.max_requests
    route_limit = args.route_limit
    historical = not args.no_historical

    state = State(max_requests, directory_focused, route_limit)
    state.base_netloc = urlparse(target).netloc
    state.base_domain = '.'.join(state.base_netloc.split('.')[-2:]) if len(state.base_netloc.split('.')) > 1 else state.base_netloc
    js_engine = JSAnalyzer(target, allow_sub, state)
    crawler = HTMLCrawler(target, allow_sub, js_engine, state)

    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=TIMEOUT) as client:
        log_progress("Starting Discovery Phase...")
        await crawler.crawl(client)
        if historical:
            await historical_discover(client, target, state)

        log_progress("Starting Analysis Phase...")
        await analyze_endpoints(state)

        if not enum_only:
            log_progress("Starting Validation Phase...")
            await get_home_metrics(client, target, state)

            def chunked(lst, size):
                for i in range(0, len(lst), size):
                    yield lst[i:i + size]

            MAX_VALIDATE = 3000
            endpoints = list(state.endpoints.keys())[:MAX_VALIDATE]

            tasks = []
            for ep in endpoints:
                tasks.append(validate_url(client, ep, state, verbose))
                if len(tasks) >= MAX_CONCURRENCY:
                    await asyncio.gather(*tasks, return_exceptions=True)
                    tasks = []

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    print("\n" + "=" * 60)
    if state.js_list:
        print(f"{Fore.CYAN}[+] JS encontrados ({len(state.js_list)}):{Style.RESET_ALL}")
        for js in sorted(set(state.js_list)):
            print(f"{Fore.YELLOW}[JS]{Style.RESET_ALL} {js}")

    if state.php_list:
        state.php_list = sorted(state.php_list, key=lambda x: (-x["priority"], x["url"]))
        print(f"\n{Fore.CYAN}[+] Endpoints PHP:{Style.RESET_ALL}")
        for php in state.php_list:
            status_color = STATUS_COLORS.get(php["status"], Fore.WHITE)
            class_color = CLASSIFY_COLORS.get(php["class"], Fore.WHITE)
            dynamic_str = " [DYNAMIC]" if php["is_dynamic"] else ""
            fallback_str = " {FALLBACK_ROUTE}" if php["fallback"] else ""
            historical_str = " [HISTORICAL]" if php["historical"] else ""
            fallback_status_str = f" {{FALLBACK_{php['fallback_status'].upper()}}}" if php["fallback_status"] else ""
            print(f"{Fore.MAGENTA}[PHP]{Style.RESET_ALL} {status_color}{php['url']} [{php['status']}] {class_color}({php['class']}){dynamic_str}{fallback_str}{historical_str}{fallback_status_str}{Style.RESET_ALL}")

    collapsed = defaultdict(lambda: {"exts": set(), "entry": None})
    final_ep_list = []

    for ep in state.ep_list:
        base, ext = split_backup_variant(ep["url"])
        if not ext or ep["status"] == 200:
            final_ep_list.append(ep)
            continue
        key = (base, ep["status"])
        collapsed[key]["exts"].add(ext)
        collapsed[key]["entry"] = ep

    for (base, status), data in collapsed.items():
        exts = sorted(data["exts"])
        if len(exts) <= 4:
            entry = data["entry"].copy()
            entry["url"] = f"{base} ({', '.join(exts)})"
            final_ep_list.append(entry)

    state.ep_list = final_ep_list

    if state.ep_list:
        state.ep_list = sorted(state.ep_list, key=lambda x: (-x["priority"], x["url"]))
        print(f"\n{Fore.CYAN}[+] Endpoints interesantes:{Style.RESET_ALL}")
        for ep in state.ep_list:
            status_color = STATUS_COLORS.get(ep["status"], Fore.WHITE)
            class_color = CLASSIFY_COLORS.get(ep["class"], Fore.WHITE)
            dynamic_str = " [DYNAMIC]" if ep["is_dynamic"] else ""
            fallback_str = " {FALLBACK_ROUTE}" if ep["fallback"] else ""
            bypass_str = " {BYPASSED}" if ep.get("bypassed") else ""
            historical_str = " [HISTORICAL]" if ep["historical"] else ""
            fallback_status_str = f" {{FALLBACK_{ep['fallback_status'].upper()}}}" if ep["fallback_status"] else ""
            t = detect_type(ep["url"], ep.get("content_type", ""))
            label, color = TYPE_STYLES[t]
            print(
                f"{color}[{label}]{Style.RESET_ALL} "
                f"{status_color}{ep['url']} [{ep['status']}] "
                f"{class_color}({t})"
                f"{dynamic_str}{fallback_str}{bypass_str}{historical_str}{fallback_status_str}"
                f"{Style.RESET_ALL}"
            )

    if enum_only:
        print(f"\n{Fore.CYAN}[+] All Collected Endpoints/Routes (Unvalidated):{Style.RESET_ALL}")
        for url, data in sorted(state.endpoints.items(), key=lambda x: x[0]):
            route_str = " [ROUTE]" if data["is_route"] else ""
            historical_str = " [HISTORICAL]" if data["historical"] else ""
            fallback_cand_str = " [FALLBACK_CANDIDATE]" if data["fallback_candidate"] else ""
            host_mismatch_str = " [HOST_MISMATCH]" if data["host_mismatch"] else ""
            print(f"{Fore.LIGHTYELLOW_EX}{url}{route_str}{historical_str}{fallback_cand_str}{host_mismatch_str}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}[+] Total requests: {state.requests}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[+] Total endpoints collected: {len(state.endpoints)}{Style.RESET_ALL}")
    if not enum_only:
        print(f"{Fore.CYAN}[+] Endpoints validados (200/401/403): {len(state.php_list) + len(state.ep_list)}{Style.RESET_ALL}")

    if state.successful_bypasses:
        print(f"\n{Fore.CYAN}[+] Successful 403 Bypasses:{Style.RESET_ALL}")
        for bypass in sorted(set(state.successful_bypasses)):
            print(Back.CYAN + Fore.BLACK + bypass + Style.RESET_ALL)

    if getattr(state, "findings", None):
        print(Fore.LIGHTBLACK_EX + "\n-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-" + Style.RESET_ALL)
        print(Fore.LIGHTBLACK_EX + "' ' ' ' ' ' ' ' ' ' ' ' ' ' ' ' ' ' '" + Style.RESET_ALL)
        for f in state.findings:
            m = re.match(r"\[([A-Z_]+)\]\s+([^:]+)\s+:\s+(.*)", f)
            if not m:
                print(f)
                continue
            tag, url, value = m.groups()
            tag_color = FINDING_COLORS.get(tag, Fore.WHITE)
            print(
                f"{tag_color}[{tag}] {url}{Style.RESET_ALL} : {value}"
            )

    if args.js and state.js_list:
        try:
            with open(args.js, "w") as f:
                for js in sorted(set(state.js_list)):
                    f.write(js + "\n")
            log_info(f"JS URLs saved to {args.js}")
        except Exception as e:
            log_err(f"Failed to save JS URLs: {e}")


state = None
def stop_signal(sig, frame):
    global state
    if state is not None:
        state.stop = True
    print("\n[!] Interrumpido por el usuario")
    sys.exit(0)

signal.signal(signal.SIGINT, stop_signal)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Recursive Endpoint Discovery Engine")
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("--sub-domain", action="store_true", help="Allow subdomains")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--enum-only",action="store_true",help="Run discovery and analysis only, skip validation phase")
    parser.add_argument("--directory-focused", action="store_true", help="Focus on directory routes")
    parser.add_argument("--no-historical",action="store_true",help="Disable historical route discovery (Wayback Machine)")
    parser.add_argument("--max-requests", type=int, default=500000, help="Max HTTP requests")
    parser.add_argument("--route-limit", type=int, default=MAX_ROUTE_LIMIT, help="Max routes to collect")
    parser.add_argument("--js", type=str, help="Save collected JS URLs to a file")
    args = parser.parse_args()
    asyncio.run(main(args))
