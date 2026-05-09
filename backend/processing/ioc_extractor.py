"""
ioc_extractor.py
----------------
Automated Indicator of Compromise (IOC) extraction from raw log text.

Extracts:
  • IPv4 / IPv6 addresses (filters RFC1918 private ranges)
  • Domain names (filters common benign domains)
  • File hashes (MD5, SHA1, SHA256)
  • Email addresses
  • URLs (http/https)
  • File paths (Windows & Unix sensitive paths)

Returns a structured IOCReport with categorised, deduplicated indicators.
"""

import re
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Any, Set


# ── Compiled regex patterns ──────────────────────────────────────────────────

_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

_IPV6_RE = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    r'|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'
    r'|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b'
)

_DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|ru|cn|xyz|info|biz|cc|tk|top|pw|club|site|online|live|me|co)\b',
    re.IGNORECASE,
)

_URL_RE = re.compile(
    r'https?://[^\s\'"<>\)]+',
    re.IGNORECASE,
)

_MD5_RE = re.compile(r'\b[0-9a-fA-F]{32}\b')
_SHA1_RE = re.compile(r'\b[0-9a-fA-F]{40}\b')
_SHA256_RE = re.compile(r'\b[0-9a-fA-F]{64}\b')
# Short hash prefix (8 chars followed by ...) — common in log output
_HASH_PREFIX_RE = re.compile(r'(?:hash:\s*)([0-9a-fA-F]{8,})')

_EMAIL_RE = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
)

_WIN_PATH_RE = re.compile(
    r'[A-Z]:\\(?:Windows|Users|Program Files|ProgramData|Temp|System32)'
    r'(?:\\[^\s\\:*?"<>|]+)+',
    re.IGNORECASE,
)

_UNIX_PATH_RE = re.compile(
    r'(?:/(?:etc|var|tmp|home|root|opt|usr|bin|sbin|proc))'
    r'(?:/[^\s:*?"<>|]+)+',
)


# ── Benign allowlists ────────────────────────────────────────────────────────

BENIGN_DOMAINS: Set[str] = {
    "google.com", "microsoft.com", "windows.com", "apple.com",
    "github.com", "amazonaws.com", "azure.com", "cloudflare.com",
    "ubuntu.com", "debian.org", "centos.org", "redhat.com",
    "mozilla.org", "w3.org", "example.com", "localhost",
    "windowsupdate.com", "office.com", "live.com",
}


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class IOCIndicator:
    """A single extracted IOC."""
    value: str
    ioc_type: str          # "ipv4", "ipv6", "domain", "url", "hash_md5", etc.
    context: str = ""      # surrounding text snippet
    is_private: bool = False
    is_benign: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "ioc_type": self.ioc_type,
            "context": self.context,
            "is_private": self.is_private,
            "is_benign": self.is_benign,
        }


@dataclass
class IOCReport:
    """Aggregated IOC extraction report."""
    ipv4: List[IOCIndicator] = field(default_factory=list)
    ipv6: List[IOCIndicator] = field(default_factory=list)
    domains: List[IOCIndicator] = field(default_factory=list)
    urls: List[IOCIndicator] = field(default_factory=list)
    hashes: List[IOCIndicator] = field(default_factory=list)
    emails: List[IOCIndicator] = field(default_factory=list)
    file_paths: List[IOCIndicator] = field(default_factory=list)

    @property
    def total_count(self) -> int:
        return (len(self.ipv4) + len(self.ipv6) + len(self.domains) +
                len(self.urls) + len(self.hashes) + len(self.emails) +
                len(self.file_paths))

    @property
    def suspicious_count(self) -> int:
        """Count of IOCs that are NOT private and NOT benign."""
        all_iocs = (self.ipv4 + self.ipv6 + self.domains + self.urls +
                    self.hashes + self.emails + self.file_paths)
        return sum(1 for i in all_iocs if not i.is_private and not i.is_benign)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_count": self.total_count,
            "suspicious_count": self.suspicious_count,
            "ipv4": [i.to_dict() for i in self.ipv4],
            "ipv6": [i.to_dict() for i in self.ipv6],
            "domains": [i.to_dict() for i in self.domains],
            "urls": [i.to_dict() for i in self.urls],
            "hashes": [i.to_dict() for i in self.hashes],
            "emails": [i.to_dict() for i in self.emails],
            "file_paths": [i.to_dict() for i in self.file_paths],
        }

    def summary_text(self) -> str:
        parts = [f"IOC Extraction: {self.total_count} indicators found"]
        if self.ipv4:
            parts.append(f"  IPv4: {', '.join(i.value for i in self.ipv4[:5])}")
        if self.domains:
            parts.append(f"  Domains: {', '.join(i.value for i in self.domains[:5])}")
        if self.hashes:
            parts.append(f"  Hashes: {', '.join(i.value for i in self.hashes[:5])}")
        if self.urls:
            parts.append(f"  URLs: {len(self.urls)} found")
        return "\n".join(parts)


# ── Context extraction helper ────────────────────────────────────────────────

def _get_context(text: str, match_start: int, match_end: int, window: int = 40) -> str:
    """Extract surrounding context for an IOC match."""
    start = max(0, match_start - window)
    end = min(len(text), match_end + window)
    ctx = text[start:end].replace("\n", " ").strip()
    if start > 0:
        ctx = "…" + ctx
    if end < len(text):
        ctx = ctx + "…"
    return ctx


# ── Main extraction function ─────────────────────────────────────────────────

def extract_iocs(raw_text: str) -> IOCReport:
    """
    Extract all IOCs from raw log text.

    Args:
        raw_text: Raw log text (multi-line string).

    Returns:
        IOCReport with categorised, deduplicated indicators.
    """
    report = IOCReport()
    seen: Set[str] = set()

    if not raw_text:
        return report

    # ── IPv4 ──────────────────────────────────────────────────────────────
    for m in _IPV4_RE.finditer(raw_text):
        ip = m.group()
        if ip in seen:
            continue
        seen.add(ip)

        is_private = False
        try:
            is_private = ipaddress.ip_address(ip).is_private
        except ValueError:
            pass

        report.ipv4.append(IOCIndicator(
            value=ip,
            ioc_type="ipv4",
            context=_get_context(raw_text, m.start(), m.end()),
            is_private=is_private,
        ))

    # ── IPv6 ──────────────────────────────────────────────────────────────
    for m in _IPV6_RE.finditer(raw_text):
        ip = m.group()
        if ip in seen:
            continue
        seen.add(ip)
        report.ipv6.append(IOCIndicator(
            value=ip,
            ioc_type="ipv6",
            context=_get_context(raw_text, m.start(), m.end()),
        ))

    # ── URLs (before domains to avoid double-counting) ────────────────────
    url_domains: Set[str] = set()
    for m in _URL_RE.finditer(raw_text):
        url = m.group().rstrip(".,;)'\"")
        if url in seen:
            continue
        seen.add(url)

        # Extract domain from URL for dedup with domain extraction
        domain_match = re.search(r'https?://([^/:\s]+)', url)
        if domain_match:
            url_domains.add(domain_match.group(1).lower())

        report.urls.append(IOCIndicator(
            value=url,
            ioc_type="url",
            context=_get_context(raw_text, m.start(), m.end()),
        ))

    # ── Domains ───────────────────────────────────────────────────────────
    for m in _DOMAIN_RE.finditer(raw_text):
        domain = m.group().lower()
        if domain in seen or domain in url_domains:
            continue
        seen.add(domain)

        is_benign = any(domain.endswith(b) or domain == b for b in BENIGN_DOMAINS)

        report.domains.append(IOCIndicator(
            value=domain,
            ioc_type="domain",
            context=_get_context(raw_text, m.start(), m.end()),
            is_benign=is_benign,
        ))

    # ── File hashes ───────────────────────────────────────────────────────
    # SHA256 first (longest), then SHA1, then MD5, then prefixes
    for regex, hash_type in [
        (_SHA256_RE, "hash_sha256"),
        (_SHA1_RE, "hash_sha1"),
        (_MD5_RE, "hash_md5"),
    ]:
        for m in regex.finditer(raw_text):
            h = m.group().lower()
            if h in seen:
                continue
            # Skip if it's a substring of an already-found longer hash
            if any(h in existing for existing in seen if len(existing) > len(h)):
                continue
            seen.add(h)
            report.hashes.append(IOCIndicator(
                value=h,
                ioc_type=hash_type,
                context=_get_context(raw_text, m.start(), m.end()),
            ))

    # Hash prefix patterns (common in logs like "hash: d38e2f6b...")
    for m in _HASH_PREFIX_RE.finditer(raw_text):
        h = m.group(1).lower()
        if h in seen:
            continue
        seen.add(h)
        report.hashes.append(IOCIndicator(
            value=h,
            ioc_type="hash_prefix",
            context=_get_context(raw_text, m.start(), m.end()),
        ))

    # ── Email addresses ───────────────────────────────────────────────────
    for m in _EMAIL_RE.finditer(raw_text):
        email = m.group().lower()
        if email in seen:
            continue
        seen.add(email)
        report.emails.append(IOCIndicator(
            value=email,
            ioc_type="email",
            context=_get_context(raw_text, m.start(), m.end()),
        ))

    # ── File paths ────────────────────────────────────────────────────────
    for regex in [_WIN_PATH_RE, _UNIX_PATH_RE]:
        for m in regex.finditer(raw_text):
            path = m.group()
            if path in seen:
                continue
            seen.add(path)
            report.file_paths.append(IOCIndicator(
                value=path,
                ioc_type="file_path",
                context=_get_context(raw_text, m.start(), m.end()),
            ))

    return report
