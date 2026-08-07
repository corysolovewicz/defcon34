#!/usr/bin/env python3
"""
placeholder_squatting_probe.py - find registered placeholder domains that accept mail.

Developers hardcode fake sender domains. `noreply.com`, `donotreply.net`,
`company.us`, whatever the config template shipped with. Those domains are
registrable, and if somebody registers one and points a catch-all at it, every
piece of mail the world's misconfigured apps send to that address gets delivered
to a stranger.

This tool measures how much of that is out there. For each `<prefix>.<tld>` it:

  1. Looks up registration date and registrar over RDAP.
  2. Resolves MX (falling back to A/AAAA), and honours a null MX as an explicit
     "this domain takes no mail".
  3. Runs `HELO` / `MAIL FROM:<>` / `RCPT TO` against the first MX that answers.
  4. If, and only if, that baseline recipient was accepted, sends a second
     `RCPT TO` for an address that cannot exist. A 250 to that means catch-all.
  5. Writes every attempt to SQLite so results accumulate across runs.

A catch-all on a placeholder domain is the finding. Everything else in here
exists to make that finding trustworthy, or to keep the probe from looking like
an attack while it collects one.

Being a good citizen
    Sweeping SMTP servers is how you get your IP onto Spamhaus CSS. Three
    defaults matter and you should leave them alone:

    - Pacing. `--delay 2.0` with `--jitter 0.5`, and shuffled domain order so
      consecutive probes don't land on the same MX cluster. Volume and rhythm are
      exactly what reputation systems score.
    - HELO. Defaults to the reverse-DNS name of your egress IP, or its `[literal]`
      if there's no PTR. An unresolvable HELO is a listing trigger by itself.
    - The catch-all gate. The second probe only fires after the baseline was
      accepted. Sending guaranteed-invalid recipients to servers that already
      rejected you is the directory-harvest pattern, and it buys no information.

    The run also checks your own egress IP against four DNSBLs before it starts
    and records the answer, so you can throw out results collected from a listed
    address.

You need outbound port 25
    Residential and mobile connections will not work. Consumer ISPs and every
    mobile carrier block outbound 25, and those ranges sit on the Spamhaus PBL,
    which is the ISP saying nothing here should be speaking SMTP. Many cloud
    providers block it too: GCP always, AWS and Azure until you ask, DigitalOcean
    and Vultr on request.

    The failure is quiet, which is what makes it worth this much text. DNS
    resolves, MX lookups succeed, every SMTP connect times out, and the run
    finishes reporting every domain unreachable. That looks like "nobody runs a
    catch-all" rather than "my packets never left".

    Confirm it rather than assume it:

        python placeholder_squatting_probe.py --preflight

    That checks port 25, blocklist status, PTR, and whether the PTR
    forward-confirms, then exits non-zero if this host can't collect usable
    data. It probes nothing under study.

    Use a VPS that permits SMTP, with reverse DNS set on the IP.

Install:
    pip install dnspython
    pip install colorama      # optional, colourised output

Run:
    Default sweep, 12 built-in prefixes across the built-in TLD list:
        python placeholder_squatting_probe.py

    One prefix, a few TLDs:
        python placeholder_squatting_probe.py --prefix deleteduser --tlds com,net,us

    A single domain:
        python placeholder_squatting_probe.py --domain noreply.com

    The wide list (ships as `prefixes.txt`, ~400 labels):
        python placeholder_squatting_probe.py --prefixes-file prefixes.txt

    Skip domains you own, one per line:
        python placeholder_squatting_probe.py --exclude-file exclude.txt

    Greylisted deferrals get queued automatically. Drain them later, on a cron:
        python placeholder_squatting_probe.py --process-greylist-queue
        python placeholder_squatting_probe.py --greylist-queue-status

    Continue an interrupted sweep:
        python placeholder_squatting_probe.py --resume

Tables:
    probe_runs            one row per invocation, with egress IP, DNSBL status, pacing
    probe_results         one row per SMTP attempt; `catch_all_probe=1` is the fake-recipient probe
    probe_domain_summary  one rolled-up row per domain per run; `catch_all_likely=1` is the finding
    greylist_queue        deferred triplets awaiting retry on an escalating backoff
    v_run_diff            view: domains whose code or category changed between runs

Queries:
    Catch-alls, newest first:
        sqlite3 probe.sqlite3 "SELECT domain, catch_all_mx, registrar, registration_date
                               FROM probe_domain_summary WHERE catch_all_likely=1
                               ORDER BY ts_utc DESC"

    Behaviour changes between runs:
        sqlite3 probe.sqlite3 "SELECT domain, cat_a, cat_b, code_a, code_b FROM v_run_diff"

    Runs collected from a listed IP, which you probably want to discount:
        sqlite3 probe.sqlite3 "SELECT run_id, ts_utc, egress_ip, dnsbl_listed
                               FROM probe_runs WHERE dnsbl_listed IS NOT NULL"

Probe domains you have a reason to probe.

Copyright (C) 2026 Cory Solovewicz (interpünkt)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import smtplib
import socket
import sqlite3
import sys
import time
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import dns.resolver

__version__ = "1.0.0"

USER_AGENT = f"placeholder-squatting-probe/{__version__} (research)"


# ---------------------------------------------------------------------------
# Optional colour
# ---------------------------------------------------------------------------
# Only when colorama is installed AND the stream is a real TTY, so piping to a
# file doesn't fill it with escape codes.
try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init()
    _HAVE_COLORAMA = True
except Exception:
    _HAVE_COLORAMA = False

    class _NoColor:
        def __getattr__(self, _name):
            return ""

    Fore = Style = _NoColor()

_COLOR_ERR = _HAVE_COLORAMA and sys.stderr.isatty()   # logging goes to stderr
_COLOR_OUT = _HAVE_COLORAMA and sys.stdout.isatty()   # summary lines go to stdout


def _paint(text, *styles):
    """Colour text for the logging stream, or hand it back plain."""
    if not _COLOR_ERR:
        return str(text)
    return "".join(styles) + str(text) + Style.RESET_ALL


def _paint_out(text, *styles):
    """Colour text for stdout."""
    if not _COLOR_OUT:
        return str(text)
    return "".join(styles) + str(text) + Style.RESET_ALL


def _good(t): return _paint(t, Fore.GREEN, Style.BRIGHT)    # accepted, catch-all
def _warn(t): return _paint(t, Fore.YELLOW)                  # deferred, blackhole
def _bad(t):  return _paint(t, Fore.RED, Style.BRIGHT)       # blocked, rejected
def _dim(t):  return _paint(t, Style.DIM)                    # noise
def _head(t): return _paint(t, Fore.CYAN, Style.BRIGHT)      # domain header
def _key(t):  return _paint(t, Fore.CYAN)                    # labels


def _line(label, text):
    """Indented sub-line under a domain header."""
    return "  " + _key(label.ljust(8)) + " " + text


class _ColorFormatter(logging.Formatter):
    """INFO prints bare so the probe output reads like a report. Warnings and
    errors get a marker, debug goes dim."""

    def format(self, record):
        msg = record.getMessage()
        if record.levelno >= logging.ERROR:
            return _bad("[!] ") + msg
        if record.levelno >= logging.WARNING:
            return _warn("[!] ") + msg
        if record.levelno <= logging.DEBUG:
            return _dim("[*] " + msg)
        return msg


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_RCPT_LOCALPART = "hello"          # local part of the baseline RCPT TO
DEFAULT_DB = "probe.sqlite3"
DEFAULT_TIMEOUT = 25                      # seconds before TCP/SMTP gives up
DEFAULT_PORT = 25
DEFAULT_DELAY = 2.0                       # seconds between domains
DEFAULT_JITTER = 0.5                      # randomise each pause by +/- this fraction

# The shipped prefix list. Twelve labels that show up over and over in real
# config templates, sample code, and deletion placeholders. Order is deliberate:
# the first few are the ones people recognise, which makes a demo run land.
#
# This is a starting point, not the whole class. `prefixes.txt` ships alongside
# with roughly 400 labels covering bounce infrastructure, GDPR erasure
# placeholders, dev-environment artifacts (`localhost3000` and friends),
# fictional companies from vendor docs, and config sentinels. Load it with
# `--prefixes-file prefixes.txt`.
DEFAULT_PREFIXES = [
    "noreply",
    "donotreply",
    "company",
    "deleteduser",
    "devnull",
    "localhost",
    "noemail",
    "undefined",
    "void",
    "blank",
    "notreal",
    "redacted",
]

# TLDs swept when `--tlds` isn't given, roughly ordered by registration volume.
# source: https://research.domaintools.com/statistics/tld-counts/
TOP_TLDS = [
    "com", "de", "net", "cn", "org", "uk", "xyz", "nl", "ru", "top", "br", "info", "fr", "au",
    "shop", "eu", "ca", "co", "it", "in", "online", "ch", "pl", "cc", "es", "store", "us",
    "jp", "site", "be", "vip", "at", "cz", "ir", "se", "za", "dk", "sbs", "biz", "io", "tr",
    "bond", "mx", "me", "id", "app", "kr", "pro", "ai", "hu", "no",
]


@dataclass
class ProbeRow:
    """One row of `probe_results`."""
    domain: str
    target: str              # MX hostname or IP. DNS-phase rows carry the resolution mode.
    port: int
    phase: str               # "resolve", "connect", or "rcpt_to"
    ok: int                  # 1 if the phase completed without error
    smtp_code: Optional[int]
    smtp_message: Optional[str]
    matched_blacklist: int   # 1 if the response named this domain as blacklisted
    rejection_category: str  # see categorize_rejection()
    catch_all_probe: int     # 1 for the fake-recipient probe
    catch_all_result: str    # 'likely' | 'blackhole' | 'rejected' | 'inconclusive' | 'error' | ''
    error: Optional[str]
    # Stamped when the row is built, so this is when the probe finished rather
    # than when the run started. Lets you see where in a run behaviour shifted.
    ts_utc: str = field(default_factory=lambda: utc_now_iso())


# ---------------------------------------------------------------------------
# Egress IP reputation
# ---------------------------------------------------------------------------

# Checked once at startup. zen.spamhaus.org covers SBL, XBL and PBL in one query.
_DNSBLS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
]

_IP_DISCOVERY_URLS = [
    "https://api4.my-ip.io/ip",
    "https://ipv4.icanhazip.com",
    "https://checkip.amazonaws.com",
]


def _get_egress_ip(timeout: int = 5) -> Optional[str]:
    """Public IPv4 this machine sends from, or None if nothing answers."""
    for url in _IP_DISCOVERY_URLS:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                ip = resp.read().decode().strip()
                ipaddress.IPv4Address(ip)   # reject anything that isn't an address
                return ip
        except Exception:
            continue
    return None


def _reverse_ip(ip: str) -> str:
    """Octet-reversed form used for DNSBL lookups."""
    return ".".join(reversed(ip.split(".")))


# What Spamhaus zen answers with. The code matters: PBL means the ISP has
# declared this range shouldn't be talking SMTP directly, which is the signature
# of a residential or mobile connection, and CSS is what a sweep earns you.
_ZEN_CODES = {
    "127.0.0.2":  "SBL, spam source",
    "127.0.0.3":  "CSS, snowshoe/low-reputation sender",
    "127.0.0.4":  "XBL, exploited or compromised host",
    "127.0.0.5":  "XBL, exploited or compromised host",
    "127.0.0.6":  "XBL, exploited or compromised host",
    "127.0.0.7":  "XBL, exploited or compromised host",
    "127.0.0.9":  "SBL DROP, hijacked netblock",
    "127.0.0.10": "PBL, residential/dynamic range not meant to send mail",
    "127.0.0.11": "PBL, ISP policy says this range shouldn't run an MTA",
}
# The PBL codes. A hit here means port 25 is very probably blocked upstream too.
_PBL_CODES = {"127.0.0.10", "127.0.0.11"}


def _check_dnsbl(reversed_ip: str, bl: str) -> List[str]:
    """Return the A records the blocklist answers with. Empty means not listed.

    The codes carry the reason, so this returns them rather than a bare bool.
    """
    try:
        ans = dns.resolver.resolve(f"{reversed_ip}.{bl}", "A", lifetime=5)
        return sorted(r.to_text() for r in ans)
    except Exception:
        return []


def check_egress_ip() -> Tuple[Optional[str], List[str]]:
    """Find the outbound IP and check it against `_DNSBLS`.

    A listed IP doesn't stop the run, but it changes what the results mean: a
    rejection from a listed address tells you about your own reputation, not
    about the recipient. Both values get stored on the run so you can filter
    those runs out later.

    A PBL hit gets called out separately and loudly. That one says you're on a
    connection nobody is supposed to send mail from, which in practice means a
    home or mobile link, and those almost always have port 25 blocked upstream
    as well. The run will still go through the motions and report every domain
    as unreachable, which looks like a finding and isn't one.
    """
    ip = _get_egress_ip()
    if ip is None:
        logging.warning("could not determine outbound IP, skipping DNSBL check")
        return None, []

    rev = _reverse_ip(ip)
    listed_on, codes = [], []
    for bl in _DNSBLS:
        hits = _check_dnsbl(rev, bl)
        if hits:
            listed_on.append(bl)
            codes.extend(hits)

    if not listed_on:
        logging.info("egress IP %s clean on %d DNSBLs", ip, len(_DNSBLS))
        return ip, listed_on

    logging.warning("egress IP %s is listed on: %s", ip, ", ".join(listed_on))
    for c in sorted(set(codes)):
        if c in _ZEN_CODES:
            logging.warning("  %s  %s", c, _ZEN_CODES[c])

    if set(codes) & _PBL_CODES:
        logging.warning("")
        logging.warning("PBL listing means this looks like a residential or mobile connection.")
        logging.warning("Outbound port 25 is very likely blocked, in which case every domain")
        logging.warning("will come back 'unreachable' and the run tells you nothing. Use a VPS")
        logging.warning("or a connection that permits SMTP. See the README.")
        logging.warning("")
    else:
        logging.warning("rejections this run may be about your IP, not the recipient")

    return ip, listed_on


def ptr_hostname(ip: Optional[str]) -> Optional[str]:
    """Reverse-DNS an IP, for use as a HELO name. None if there's no PTR."""
    if not ip:
        return None
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host or None
    except Exception:
        return None


def forward_confirms(ip: str, host: str) -> bool:
    """True if `host` resolves back to `ip`.

    Forward-confirmed reverse DNS. Receiving MTAs don't just check that a PTR
    exists, they check that the name it gives resolves back to the address that
    connected. A PTR that fails this is worse than none at all, because a name
    that doesn't match reads as forgery rather than as an unconfigured host.
    """
    if not ip or not host:
        return False
    for rtype in ("A", "AAAA"):
        try:
            if any(r.to_text() == ip for r in dns.resolver.resolve(host, rtype, lifetime=5)):
                return True
        except Exception:
            continue
    return False


def pick_helo(egress_ip: Optional[str], override: Optional[str] = None) -> str:
    """Choose a HELO name.

    Prefer the egress IP's PTR, but only when it forward-confirms. An
    unconfirmed PTR gets dropped in favour of the address literal `[1.2.3.4]`,
    which is valid, honest, and doesn't look like someone claiming a name that
    isn't theirs. `probe.example` is the last resort and is itself a listing
    trigger, so it only appears when we couldn't determine our own IP.
    """
    if override:
        return override
    if not egress_ip:
        return "probe.example"
    ptr = ptr_hostname(egress_ip)
    if ptr and forward_confirms(egress_ip, ptr):
        return ptr
    if ptr:
        logging.warning("PTR %s does not resolve back to %s, using the address literal instead",
                        ptr, egress_ip)
    return f"[{egress_ip}]"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Current UTC time, ISO 8601, second precision."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def parse_iso(ts: str) -> Optional[dt.datetime]:
    """Parse one of our timestamps back to an aware datetime, or None."""
    try:
        return dt.datetime.fromisoformat(ts)
    except Exception:
        return None


def catch_all_localpart(domain: str) -> str:
    """A local part that cannot exist, derived from the domain so it's stable.

    Stability is the point. If the first attempt gets greylisted, the retry has
    to present the identical sender/recipient pair or the greylister just defers
    it again. A fresh random address every time never clears.

    `verify-probe-<8 hex>` also reads like routine recipient verification, which
    scores a lot lower on directory-harvest heuristics than a random string.
    """
    h = hashlib.sha1(domain.lower().encode("utf-8", "ignore")).hexdigest()[:8]
    return f"verify-probe-{h}"


# Greylisting tells. A 4xx matching this is worth retrying with the same
# triplet. Other 4xx (rate limits, full mailbox, service down) won't clear on
# retry, so they stay out of the queue.
_GREYLIST_RE = re.compile(
    r"grey ?list|gray ?list|greylisted|try again|retry later|temporar\w* defer"
    r"|deferred|4\.2\.0|\(gl\)|please retry",
    re.IGNORECASE)


def looks_like_greylisting(code: Optional[int], msg: Optional[str]) -> bool:
    """True if this 4xx looks like greylisting rather than a hard temp failure."""
    return code is not None and 400 <= code < 500 and bool(_GREYLIST_RE.search(msg or ""))


def _split_list(raw: str) -> List[str]:
    """Split on commas, spaces or newlines. Empty entries dropped."""
    return [p for p in (x.strip() for x in raw.replace(",", " ").split()) if p]


def parse_tlds_arg(raw: str) -> List[str]:
    """Parse a TLD list. Leading dots are fine, so `.com` and `com` both work."""
    return [p.lstrip(".").lower() for p in _split_list(raw)]


def parse_prefixes(raw: str) -> List[str]:
    """Parse a prefix list. Order preserved, duplicates dropped."""
    parts = [p.lstrip(".").lower() for p in _split_list(raw)]
    seen: set = set()
    return [p for p in parts if not (p in seen or seen.add(p))]


def load_list_file(path: str) -> List[str]:
    """Read a newline-delimited list file.

    Blank lines and `#` comments are skipped. Used for both `--prefixes-file`
    and `--exclude-file`. Duplicates are dropped, order is kept.
    """
    out: List[str] = []
    seen: set = set()
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip().lower().lstrip(".")
            if line and line not in seen:
                seen.add(line)
                out.append(line)
    return out


# ---------------------------------------------------------------------------
# RDAP
# ---------------------------------------------------------------------------
# Registration date and registrar tell you whether a catch-all placeholder is
# somebody's long-held domain or something registered last month to collect
# mail. Worth having on every row, so the lookup runs before DNS and never
# blocks the probe when it fails.

_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

# Offline fallback, only consulted when the live IANA bootstrap is unreachable.
# Generated from that file, so it agrees with it, plus five ccTLDs IANA doesn't
# list that were verified by hand.
#
# TLDs with no working RDAP endpoint are deliberately absent rather than pointing
# somewhere hopeful. A wrong entry costs a full HTTP timeout on every domain in
# that TLD; a missing one skips the lookup and moves on.
#
# Refresh with fetch_rdap_bootstrap(). Registries do move.
_RDAP_BOOTSTRAP_SNAPSHOT: Dict[str, str] = {
    "ai":       "https://rdap.identitydigital.services/rdap/",
    "app":      "https://pubapi.registry.google/rdap/",
    "au":       "https://rdap.cctld.au/rdap/",
    "biz":      "https://rdap.nic.biz/",
    "bond":     "https://rdap.centralnic.com/bond/",
    "br":       "https://rdap.registro.br/",
    "ca":       "https://rdap.ca.fury.ca/rdap/",
    "cc":       "https://tld-rdap.verisign.com/cc/v1/",
    "ch":       "https://rdap.nic.ch/",   # verified by hand, not in the IANA file
    "com":      "https://rdap.verisign.com/com/v1/",
    "cymru":    "https://rdap.nominet.uk/cymru/",
    "cz":       "https://rdap.nic.cz/",
    "de":       "https://rdap.denic.de/",   # verified by hand, not in the IANA file
    "dev":      "https://pubapi.registry.google/rdap/",
    "fans":     "https://rdap.centralnic.com/fans/",
    "fr":       "https://rdap.nic.fr/",
    "fyi":      "https://rdap.identitydigital.services/rdap/",
    "id":       "https://rdap.pandi.id/rdap/",
    "in":       "https://rdap.nixiregistry.in/rdap/",
    "info":     "https://rdap.identitydigital.services/rdap/",
    "io":       "https://rdap.identitydigital.services/rdap/",   # verified by hand, not in the IANA file
    "legal":    "https://rdap.identitydigital.services/rdap/",
    "me":       "https://rdap.identitydigital.services/rdap/",   # verified by hand, not in the IANA file
    "mobi":     "https://rdap.identitydigital.services/rdap/",
    "mov":      "https://pubapi.registry.google/rdap/",
    "name":     "https://tld-rdap.verisign.com/name/v1/",
    "net":      "https://rdap.verisign.com/net/v1/",
    "nl":       "https://rdap.sidn.nl/",
    "no":       "https://rdap.norid.no/",
    "onl":      "https://rdap.identitydigital.services/rdap/",
    "online":   "https://rdap.radix.host/rdap/",
    "org":      "https://rdap.publicinterestregistry.org/rdap/",
    "page":     "https://pubapi.registry.google/rdap/",
    "pl":       "https://rdap.dns.pl/",
    "pro":      "https://rdap.identitydigital.services/rdap/",
    "property": "https://rdap.registry.click/rdap/",
    "pw":       "https://rdap.radix.host/rdap/",
    "sbs":      "https://rdap.centralnic.com/sbs/",
    "shop":     "https://rdap.gmoregistry.net/rdap/",
    "site":     "https://rdap.radix.host/rdap/",
    "store":    "https://rdap.radix.host/rdap/",
    "tel":      "https://rdap.nic.tel/",
    "top":      "https://rdap.zdnsgtld.com/top/",
    "tv":       "https://rdap.nic.tv/",
    "uk":       "https://rdap.nominet.uk/uk/",
    "us":       "https://rdap.nic.us/",   # verified by hand, not in the IANA file
    "vip":      "https://rdap.nic.vip/",
    "xyz":      "https://rdap.centralnic.com/xyz/",
    "zip":      "https://pubapi.registry.google/rdap/",
}

_rdap_bootstrap_cache: Optional[dict] = None
_rdap_bootstrap_tried = False


def fetch_rdap_bootstrap(timeout: int = 10) -> Optional[dict]:
    """Fetch the IANA bootstrap file (RFC 7484) as a `tld -> base URL` map.

    Fetched once per process. Returns None on failure, and won't retry, so one
    unreachable IANA doesn't cost every domain in the sweep an HTTP timeout.
    """
    global _rdap_bootstrap_cache, _rdap_bootstrap_tried
    if _rdap_bootstrap_tried:
        return _rdap_bootstrap_cache
    _rdap_bootstrap_tried = True

    try:
        req = urllib.request.Request(_RDAP_BOOTSTRAP_URL, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        logging.debug("RDAP bootstrap fetch failed: %s", e)
        return None

    # Each service entry is [[tld, ...], [url, ...]]. Prefer HTTPS.
    mapping: dict = {}
    for entry in data.get("services", []):
        tlds, urls = entry[0], entry[1]
        base = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
        if base:
            for tld in tlds:
                mapping[tld.lower()] = base

    _rdap_bootstrap_cache = mapping
    logging.debug("RDAP bootstrap loaded, %d TLDs", len(mapping))
    return mapping


def _rdap_base_for(domain: str) -> Optional[str]:
    """RDAP base URL for a domain's TLD, live map first then the snapshot."""
    tld = domain.rsplit(".", 1)[-1].lower()
    live = fetch_rdap_bootstrap()
    if live and tld in live:
        return live[tld]
    return _RDAP_BOOTSTRAP_SNAPSHOT.get(tld)


def _parse_rdap_response(data: dict) -> Tuple[Optional[str], Optional[str]]:
    """Pull registration date and registrar name out of an RDAP response."""
    reg_date: Optional[str] = None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            reg_date = (event.get("eventDate") or "")[:10] or None
            break

    registrar: Optional[str] = None
    for ent in data.get("entities", []):
        roles = [r.lower() for r in ent.get("roles", [])]
        if "registrar" not in roles:
            continue
        # jCard: ["vcard", [["fn", {}, "text", "Registrar Name"], ...]]
        vcard = ent.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for prop in vcard[1]:
                if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
                    registrar = str(prop[3]).strip() or None
                    break
        if not registrar:
            registrar = ent.get("handle")
        if registrar:
            break

    return reg_date, registrar


def rdap_lookup(domain: str, timeout: int = 8) -> Tuple[Optional[str], Optional[str]]:
    """Return (registration_date, registrar) for a domain, or (None, None).

    Never raises. An unregistered domain, a registry with no RDAP endpoint, and
    a rate-limited registry all look the same from here, which is fine: the SMTP
    result is the finding and this is context.
    """
    base = _rdap_base_for(domain)
    if not base:
        logging.debug("no RDAP endpoint known for %s", domain)
        return None, None

    url = base.rstrip("/") + "/domain/" + domain
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode(errors="ignore"))
    except Exception as e:
        logging.debug("RDAP lookup failed for %s: %s", domain, e)
        return None, None

    try:
        return _parse_rdap_response(data)
    except Exception as e:
        logging.debug("RDAP parse failed for %s: %s", domain, e)
        return None, None


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS probe_runs (
        run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_utc          TEXT NOT NULL,
        mode            TEXT NOT NULL,
        prefix          TEXT NOT NULL,
        rcpt_localpart  TEXT NOT NULL,
        egress_ip       TEXT,
        dnsbl_listed    TEXT,
        note            TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS probe_results (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id             INTEGER NOT NULL,
        ts_utc             TEXT NOT NULL,
        domain             TEXT NOT NULL,
        target             TEXT NOT NULL,
        port               INTEGER NOT NULL,
        phase              TEXT NOT NULL,
        ok                 INTEGER NOT NULL,
        smtp_code          INTEGER,
        smtp_message       TEXT,
        matched_blacklist  INTEGER NOT NULL DEFAULT 0,
        rejection_category TEXT NOT NULL DEFAULT '',
        catch_all_probe    INTEGER NOT NULL DEFAULT 0,
        catch_all_result   TEXT NOT NULL DEFAULT '',
        error              TEXT,
        FOREIGN KEY(run_id) REFERENCES probe_runs(run_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS probe_domain_summary (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id            INTEGER NOT NULL,
        ts_utc            TEXT NOT NULL,
        domain            TEXT NOT NULL,
        resolution_mode   TEXT,
        targets_count     INTEGER NOT NULL,
        any_blacklist     INTEGER NOT NULL,
        any_reachable     INTEGER NOT NULL,
        any_2xx_rcpt      INTEGER NOT NULL,
        catch_all_likely  INTEGER NOT NULL DEFAULT 0,
        catch_all_mx      TEXT,
        registration_date TEXT,
        registrar         TEXT,
        notes             TEXT,
        FOREIGN KEY(run_id) REFERENCES probe_runs(run_id)
    )
    """,
    # One durable work item per deferred (domain, MX, recipient). UNIQUE means
    # re-seeding the same triplet is a no-op instead of a duplicate.
    """
    CREATE TABLE IF NOT EXISTS greylist_queue (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        domain           TEXT NOT NULL,
        target           TEXT NOT NULL,
        rcpt_addr        TEXT NOT NULL,
        probe_type       TEXT NOT NULL,                    -- 'baseline' | 'catch_all'
        first_seen_utc   TEXT NOT NULL,
        last_attempt_utc TEXT,
        attempts         INTEGER NOT NULL DEFAULT 0,
        next_due_utc     TEXT NOT NULL,
        status           TEXT NOT NULL DEFAULT 'pending',  -- pending|resolved_accept|resolved_reject|exhausted
        source_run_id    INTEGER,
        UNIQUE(domain, target, rcpt_addr)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_greylist_due ON greylist_queue(status, next_due_utc)",
    "CREATE INDEX IF NOT EXISTS ix_results_run ON probe_results(run_id, domain)",
    "CREATE INDEX IF NOT EXISTS ix_summary_run ON probe_domain_summary(run_id, domain)",
    # Which domains changed behaviour since the run before. Over months this is
    # the interesting output: a placeholder that was rejecting mail last quarter
    # and is accepting it now means somebody just pointed a catch-all at it.
    """
    CREATE VIEW IF NOT EXISTS v_run_diff AS
    SELECT a.domain,
           a.run_id AS run_a, b.run_id AS run_b,
           a.ts_utc AS ts_a,  b.ts_utc AS ts_b,
           a.rejection_category AS cat_a, b.rejection_category AS cat_b,
           a.smtp_code AS code_a, b.smtp_code AS code_b
    FROM (
        SELECT domain, run_id, ts_utc, smtp_code, rejection_category,
               ROW_NUMBER() OVER (PARTITION BY domain ORDER BY run_id DESC) AS rn
        FROM probe_results WHERE phase = 'rcpt_to' AND catch_all_probe = 0
    ) a
    JOIN (
        SELECT domain, run_id, ts_utc, smtp_code, rejection_category,
               ROW_NUMBER() OVER (PARTITION BY domain ORDER BY run_id DESC) AS rn
        FROM probe_results WHERE phase = 'rcpt_to' AND catch_all_probe = 0
    ) b ON a.domain = b.domain AND b.rn = a.rn + 1
    WHERE a.smtp_code IS NOT b.smtp_code
       OR a.rejection_category IS NOT b.rejection_category
    """,
]


def init_db(db_path: str) -> None:
    """Create tables, indexes and the diff view if they aren't there yet."""
    with sqlite3.connect(db_path) as conn:
        for stmt in _SCHEMA:
            conn.execute(stmt)
        conn.commit()


def create_run(conn: sqlite3.Connection, ts: str, mode: str, prefix: str,
               rcpt_localpart: str, egress_ip: Optional[str] = None,
               dnsbl_listed: Optional[str] = None, note: Optional[str] = None) -> int:
    """Insert a run and return its id.

    `mode` is "single", "batch" or "greylist-queue". Single-domain runs put the
    full domain in `prefix`. The egress IP and DNSBL status are recorded here so
    a run carries the conditions it was collected under.
    """
    cur = conn.execute(
        "INSERT INTO probe_runs (ts_utc, mode, prefix, rcpt_localpart, egress_ip, dnsbl_listed, note) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts, mode, prefix, rcpt_localpart, egress_ip, dnsbl_listed, note))
    conn.commit()
    return int(cur.lastrowid)


def store_result(conn: sqlite3.Connection, run_id: int, r: ProbeRow) -> None:
    """Write one probe row and commit. Per-row commits mean a killed run keeps
    everything it already collected."""
    conn.execute("""
        INSERT INTO probe_results (
            run_id, ts_utc, domain, target, port, phase, ok, smtp_code, smtp_message,
            matched_blacklist, rejection_category, catch_all_probe, catch_all_result, error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (run_id, r.ts_utc, r.domain, r.target, r.port, r.phase, r.ok, r.smtp_code,
          r.smtp_message, r.matched_blacklist, r.rejection_category, r.catch_all_probe,
          r.catch_all_result, r.error))
    try:
        conn.commit()
    except Exception:
        logging.exception("commit failed after store_result")


def store_summary(conn: sqlite3.Connection, run_id: int, domain: str,
                  mode: Optional[str], targets_count: int,
                  any_blacklist: int, any_reachable: int, any_2xx_rcpt: int,
                  notes: str, catch_all_likely: int = 0,
                  catch_all_mx: Optional[str] = None,
                  registration_date: Optional[str] = None,
                  registrar: Optional[str] = None) -> None:
    """Write the rolled-up row for one domain.

    Written last in probe_domain(), which is what makes `--resume` work: a
    summary row exists only for domains that finished.
    """
    conn.execute("""
        INSERT INTO probe_domain_summary (
            run_id, ts_utc, domain, resolution_mode, targets_count,
            any_blacklist, any_reachable, any_2xx_rcpt, catch_all_likely, catch_all_mx,
            registration_date, registrar, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (run_id, utc_now_iso(), domain, mode, targets_count, any_blacklist,
          any_reachable, any_2xx_rcpt, catch_all_likely, catch_all_mx,
          registration_date, registrar, notes))
    try:
        conn.commit()
    except Exception:
        logging.exception("commit failed after store_summary")


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def resolve_targets(domain: str) -> Tuple[List[str], str]:
    """Resolve where mail for `domain` would go.

    Returns (targets, mode) where mode is "MX", "A/AAAA" or "null-mx". MX hosts
    come back sorted by preference, so the first one is where a real sender
    would go first.

    Timeouts are short on purpose. One unresponsive registry shouldn't stall a
    600-domain sweep.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    try:
        logging.debug("MX lookup: %s", domain)
        mx_ans = resolver.resolve(domain, "MX", lifetime=resolver.lifetime)
        mx_hosts = sorted(
            [(r.preference, r.exchange.to_text().rstrip(".")) for r in mx_ans],
            key=lambda x: x[0])
        # Null MX (RFC 7505) is a single "MX 0 ." record. The exchange is the
        # root, which empties to "". It means the owner deliberately opted out
        # of mail, which is the opposite of a catch-all and worth recording as
        # its own thing. No A/AAAA fallback: they already answered the question.
        if any(h == "" for _, h in mx_hosts):
            logging.debug("null MX for %s", domain)
            return [], "null-mx"
        return [h for _, h in mx_hosts], "MX"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        logging.debug("no MX for %s", domain)
    except dns.exception.Timeout:
        logging.warning("MX lookup timed out for %s", domain)
    except dns.resolver.NoNameservers:
        logging.warning("no nameservers for MX lookup of %s", domain)
    except Exception as e:
        logging.debug("MX error for %s: %s", domain, e)

    # No MX. Fall back to A/AAAA, which is where mail goes per RFC 5321.
    targets: List[str] = []
    for rtype in ("A", "AAAA"):
        try:
            ans = resolver.resolve(domain, rtype, lifetime=resolver.lifetime)
            targets.extend([r.to_text() for r in ans])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.exception.Timeout:
            logging.warning("%s lookup timed out for %s", rtype, domain)
            continue
        except Exception as e:
            logging.debug("%s error for %s: %s", rtype, domain, e)
            continue

    return targets, "A/AAAA"


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------

def smtp_probe(target: str, port: int, rcpt: str, timeout: int,
               helo: str = "probe.example") -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """`HELO` / `MAIL FROM:<>` / `RCPT TO` against one host.

    Returns (code, message, error). On TCP failure the first two are None and
    error says why. If MAIL FROM is refused we stop there and return that
    response rather than pushing on to RCPT TO.

    The null sender in `MAIL FROM:<>` is what a bounce would use. It sidesteps
    sender-domain validation, which would otherwise reject us for reasons that
    have nothing to do with the recipient.
    """
    # smtplib.SMTP() connects on construction, so a failure here is already a
    # TCP problem. No separate pre-connect socket test: that doubles the
    # connection count and connect-then-hang-up looks like a port scan.
    try:
        logging.debug("SMTP %s:%s (timeout=%s)", target, port, timeout)
        c = smtplib.SMTP(target, port, timeout=timeout)
    except Exception as e:
        logging.debug("connect failed for %s:%s: %s", target, port, e)
        return None, None, f"connect failed: {e}"

    try:
        c.helo(helo)

        m_code, m_msg = c.mail("")
        if m_code is None or int(m_code) >= 400:
            try:
                c.quit()
            except Exception:
                pass
            m = m_msg.decode(errors="ignore") if isinstance(m_msg, (bytes, bytearray)) else str(m_msg)
            return (int(m_code) if m_code is not None else None), m, "MAIL FROM rejected"

        r_code, r_msg = c.rcpt(rcpt)
        msg = r_msg.decode(errors="ignore") if isinstance(r_msg, (bytes, bytearray)) else str(r_msg)

        try:
            c.quit()
        except Exception:
            pass    # we already have what we came for

        return int(r_code), msg, None
    except Exception as e:
        logging.debug("SMTP error for %s:%s: %s", target, port, e)
        return None, None, f"smtp failed: {e}"


# Phrases that mean "we refuse mail for this recipient domain specifically",
# as opposed to a complaint about the sender. Matched on 5xx responses that also
# name the domain, which is what keeps it from swallowing generic rejections.
_DOMAIN_BLOCK_PHRASES = (
    "recipient domain is blacklisted",
    "recipient domain is blocked",
    "domain is blacklisted",
    "domain is blocklisted",
    "domain not allowed",
    "blocked recipient domain",
    "recipient domain not accepted",
)


def match_blacklist(code: Optional[int], msg: Optional[str], domain: str) -> bool:
    """True if a 5xx names this domain as blocked.

    Requires a 5xx, one of `_DOMAIN_BLOCK_PHRASES`, and the domain string in the
    response. All three, because "blacklisted" on its own usually means our
    sending IP, and that's a different finding entirely.
    """
    if code is None or code < 500 or not msg:
        return False
    m = msg.lower()
    return domain.lower() in m and any(p in m for p in _DOMAIN_BLOCK_PHRASES)


# ---------------------------------------------------------------------------
# Rejection classifier
# ---------------------------------------------------------------------------
# Every result gets one of these, so the database is answerable in SQL without
# regexing SMTP strings after the fact. The important split is between "the
# server evaluated the recipient and said no" (a real negative) and "the server
# never got that far because it didn't like us" (inconclusive).

CATEGORY_DOMAIN_BLACKLISTED = "domain_blacklisted"   # 5xx naming this domain as blocked
CATEGORY_IP_BLACKLISTED     = "ip_blacklisted"       # our sending IP is the problem
CATEGORY_POLICY_BLOCK       = "policy_block"         # sender/content/policy, recipient never evaluated
CATEGORY_NO_PTR             = "no_ptr"               # our IP has no reverse DNS
CATEGORY_STARTTLS_REQUIRED  = "starttls_required"    # 530, STARTTLS first
CATEGORY_NO_MAILBOX         = "no_mailbox"           # user/mailbox unknown
CATEGORY_BLACKHOLE          = "blackhole"            # accepts everything and drops it
CATEGORY_ACCEPTED           = "accepted"             # 2xx
CATEGORY_TEMP_FAILURE       = "temp_failure"         # 4xx
CATEGORY_PERM_REJECTION     = "perm_rejection"       # 5xx, cause unclear
CATEGORY_CONNECT_FAILED     = "connect_failed"       # never got an SMTP response
CATEGORY_NULL_MX            = "null_mx"              # RFC 7505, declines all mail
CATEGORY_UNKNOWN            = "unknown"

# Categories where the server rejected us before looking at the recipient. A
# catch-all verdict is not available from these.
INCONCLUSIVE_CATEGORIES = frozenset({
    CATEGORY_POLICY_BLOCK, CATEGORY_IP_BLACKLISTED, CATEGORY_TEMP_FAILURE,
    CATEGORY_STARTTLS_REQUIRED, CATEGORY_NO_PTR,
})

_DNSBL_NAME_RE = re.compile(
    r"spamhaus|spamcop|barracuda|sorbs|spamrats|uceprotect|backscatterer"
    r"|\bdnsbl\b|\brbl\b|\bsbl\b|\bxbl\b|\bpbl\b", re.IGNORECASE)
_DNSBL_PHRASE_RE = re.compile(
    r"blocked using|block ?list|black ?list|listed (?:on|in|at|by)|denied by", re.IGNORECASE)
# An IPv4 not sitting inside a longer dotted number, so enhanced status codes
# like 5.7.1 don't read as addresses.
_IPV4_RE = re.compile(r"(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(r"(?:[0-9a-f]{0,4}:){3,7}[0-9a-f]{0,4}", re.IGNORECASE)
_REPUTATION_KW = ("blacklist", "block list", "blocklist", "blocked",
                  "listed", "banned", "reputation", "denied")


def _looks_like_dnsbl_block(text: str) -> bool:
    """True if this reads like a DNSBL block on our sending IP.

    Three ways in: a named blocklist zone, block-list phrasing, or an IP literal
    next to a reputation word. Kept conservative so it doesn't steal recipient
    rejections that happen to mention an address.
    """
    if _DNSBL_NAME_RE.search(text) or _DNSBL_PHRASE_RE.search(text):
        return True
    if (_IPV4_RE.search(text) or _IPV6_RE.search(text)) and any(k in text for k in _REPUTATION_KW):
        return True
    return False


def categorize_rejection(code: Optional[int], msg: Optional[str],
                         domain: str, target: str, err: Optional[str]) -> str:
    """Label one probe result. Most specific match wins, so order matters."""
    m = (msg or "").lower()
    t = (target or "").lower()

    # No code at all. If the error text shows an IP block, that's still about
    # our reputation, so keep it first-class rather than a generic failure.
    if code is None and err is not None:
        e = err.lower()
        if _looks_like_dnsbl_block(e):
            return CATEGORY_IP_BLACKLISTED
        if any(k in e for k in ("reputation", "spam", "policy", "abuse", "banned")):
            return CATEGORY_POLICY_BLOCK
        return CATEGORY_CONNECT_FAILED

    # MX named blackhole/void/discard/null that still says 250. It accepts
    # everything and drops it, which counts as a catch-all for our purposes but
    # is worth telling apart from a real mailbox.
    if code is not None and 200 <= code < 300:
        if any(k in t for k in ("blackhole", "void", "discard", "null")):
            return CATEGORY_BLACKHOLE
        return CATEGORY_ACCEPTED

    if code is not None and 400 <= code < 500:
        return CATEGORY_TEMP_FAILURE

    if code is not None and code >= 500:
        if match_blacklist(code, msg, domain):
            return CATEGORY_DOMAIN_BLACKLISTED

        if _looks_like_dnsbl_block(m):
            return CATEGORY_IP_BLACKLISTED

        if any(k in m for k in ("ptr", "reverse", "rdns", "no valid reverse",
                                "reverse lookup", "reverse dns")):
            return CATEGORY_NO_PTR

        if "starttls" in m or "530" in m:
            return CATEGORY_STARTTLS_REQUIRED

        if any(k in m for k in ("no such user", "no such mailbox", "user unknown",
                                "mailbox not found", "invalid mailbox", "does not exist",
                                "recipient not found", "invalid recipient",
                                "no mailbox", "account does not exist")):
            return CATEGORY_NO_MAILBOX

        # Bounced on spam/reputation/policy grounds without the recipient ever
        # being looked at, so this says nothing about catch-all status.
        if any(k in m for k in ("spam", "reputation", "policy", "blocked",
                                "block listed", "blacklist", "not authorized",
                                "access denied", "abuse", "5.7.1", "5.7.0",
                                "relay access denied", "not permitted")):
            return CATEGORY_POLICY_BLOCK

        return CATEGORY_PERM_REJECTION

    return CATEGORY_UNKNOWN


_CATEGORY_COLOR = {
    CATEGORY_ACCEPTED: _good,
    CATEGORY_BLACKHOLE: _warn,
    CATEGORY_TEMP_FAILURE: _warn,
    CATEGORY_NO_PTR: _warn,
    CATEGORY_STARTTLS_REQUIRED: _warn,
    CATEGORY_POLICY_BLOCK: _warn,
    CATEGORY_NULL_MX: _warn,
    CATEGORY_DOMAIN_BLACKLISTED: _bad,
    CATEGORY_IP_BLACKLISTED: _bad,
    CATEGORY_PERM_REJECTION: _bad,
    CATEGORY_NO_MAILBOX: _dim,
    CATEGORY_CONNECT_FAILED: _dim,
    CATEGORY_UNKNOWN: _dim,
}


def _color_category(cat):
    return _CATEGORY_COLOR.get(cat, lambda t: t)(cat)


def _color_code(code):
    """2xx green, 4xx yellow, 5xx red."""
    if code is None:
        return _dim("-")
    if 200 <= code < 300:
        return _good(str(code))
    if 400 <= code < 500:
        return _warn(str(code))
    if code >= 500:
        return _bad(str(code))
    return str(code)


def _verdict(domain, state, mx=None, reg_date=None, registrar=None):
    """The one-line conclusion printed under each domain."""
    tags = {
        "catchall":     _good("[+] CATCH-ALL"),
        "blackhole":    _warn("[+] BLACKHOLE (accepts and discards)"),
        "blacklisted":  _bad("[!] domain blocked by recipient policy"),
        "rejected":     _dim("[-] no catch-all (recipient rejected)"),
        "deferred":     _warn("[?] deferred (4xx), queued for retry, no verdict yet"),
        "inconclusive": _warn("[?] inconclusive, server blocked the probe not the recipient"),
        "unreachable":  _dim("[-] unreachable"),
        "parked":       _dim("[-] registered but no mail DNS (parked)"),
        "unregistered": _dim("[-] unregistered, no DNS"),
        "null_mx":      _warn("[-] null MX, declines all mail (RFC 7505)"),
        "error":        _bad("[!] error"),
    }
    tag = tags.get(state, _dim("[-] " + str(state)))
    extra = ""
    if mx and state in ("catchall", "blackhole"):
        extra += _dim(f"  ·  {mx}")
    if registrar:
        extra += _dim(f"  ·  {registrar}")
    if reg_date:
        extra += _dim(f"  ·  reg {reg_date}")
    return "  " + tag + extra


# ---------------------------------------------------------------------------
# Probing one domain
# ---------------------------------------------------------------------------

def probe_domain(conn: sqlite3.Connection, run_id: int, domain: str, rcpt: str,
                 port: int, timeout: int, index: int = 0, total: int = 0,
                 helo: str = "probe.example") -> None:
    """RDAP, DNS, baseline SMTP, then the catch-all probe if it's warranted.

    Writes a resolve row, one row per SMTP attempt, and a summary row last.
    """
    progress = f"[{index}/{total}] " if total else ""
    logging.info("")
    logging.info(_dim("-" * 68))
    logging.info(_head(f"> {progress}{domain}") + _dim(f"   rcpt {rcpt}"))

    # RDAP first, so we capture registration data even when SMTP goes nowhere.
    reg_date, registrar = rdap_lookup(domain)
    if reg_date or registrar:
        logging.info(_line("rdap", f"registered {_key(reg_date or '?')}  ·  "
                                   f"{_key(registrar or 'unknown registrar')}"))
    else:
        logging.info(_line("rdap", _dim("no registration record")))

    try:
        targets, dns_mode = resolve_targets(domain)
        if targets:
            logging.info(_line("dns", f"{dns_mode} -> " + ", ".join(targets)))
        elif dns_mode == "null-mx":
            logging.info(_line("dns", _warn("null MX, domain declines all mail")))
        else:
            logging.info(_line("dns", _dim("no records")))
        store_result(conn, run_id, ProbeRow(
            domain=domain, target=dns_mode, port=port, phase="resolve", ok=1,
            smtp_code=None, smtp_message=None, matched_blacklist=0,
            rejection_category=CATEGORY_NULL_MX if dns_mode == "null-mx" else "",
            catch_all_probe=0, catch_all_result="", error=None))
    except Exception as e:
        logging.info(_line("dns", _bad(f"resolve error: {e}")))
        store_result(conn, run_id, ProbeRow(
            domain=domain, target="resolve", port=port, phase="resolve", ok=0,
            smtp_code=None, smtp_message=None, matched_blacklist=0,
            rejection_category="", catch_all_probe=0, catch_all_result="", error=str(e)))
        store_summary(conn, run_id, domain, None, 0, 0, 0, 0, f"resolve error: {e}",
                      registration_date=reg_date, registrar=registrar)
        logging.info(_verdict(domain, "error", reg_date=reg_date, registrar=registrar))
        return

    if dns_mode == "null-mx":
        # They configured a refusal. Nothing to probe, and connecting anyway
        # would be rude.
        store_summary(conn, run_id, domain, dns_mode, 0, 0, 0, 0,
                      "null MX (RFC 7505); cat:" + CATEGORY_NULL_MX,
                      registration_date=reg_date, registrar=registrar)
        logging.info(_verdict(domain, "null_mx", reg_date=reg_date, registrar=registrar))
        return

    if not targets:
        # No mail DNS. Whether that means "nobody owns this" depends on RDAP: if
        # the registry gave us a registration date, somebody does own it and has
        # simply parked it. That's a different thing from an unregistered name,
        # and worth its own label, because a parked placeholder can be pointed at
        # a catch-all any day.
        if reg_date or registrar:
            store_summary(conn, run_id, domain, dns_mode, 0, 0, 0, 0,
                          "registered, no mail DNS",
                          registration_date=reg_date, registrar=registrar)
            logging.info(_verdict(domain, "parked", reg_date=reg_date, registrar=registrar))
        else:
            store_summary(conn, run_id, domain, dns_mode, 0, 0, 0, 0, "likely unregistered",
                          registration_date=reg_date, registrar=registrar)
            logging.info(_verdict(domain, "unregistered", reg_date=reg_date, registrar=registrar))
        return

    any_blacklist = 0
    any_reachable = 0
    any_2xx_rcpt = 0
    seen_categories: List[str] = []
    reachable_target: Optional[str] = None

    for target in targets:
        code, msg, err = smtp_probe(target, port, rcpt, timeout, helo=helo)

        # Any SMTP code back means the host is there, even an angry one.
        reachable = 1 if (err is None or code is not None) else 0
        any_reachable |= reachable
        if reachable and reachable_target is None:
            reachable_target = target

        if code is not None and 200 <= code < 300:
            any_2xx_rcpt = 1

        matched = 1 if match_blacklist(code, msg, domain) else 0
        any_blacklist |= matched
        category = categorize_rejection(code, msg, domain, target, err)
        if category and category not in seen_categories:
            seen_categories.append(category)

        preview = (msg or "")[:80].replace("\n", " ") if msg else ""
        logging.info(_line("smtp",
            f"{target} code={_color_code(code)} "
            f"matched={_bad('1') if matched else '0'} "
            f"category={_color_category(category)} "
            f"msg={preview!r} err={_bad(err) if err else 'None'}"))

        store_result(conn, run_id, ProbeRow(
            domain=domain, target=target, port=port,
            phase="rcpt_to" if code is not None else "connect",
            ok=1 if err is None else 0, smtp_code=code, smtp_message=msg,
            matched_blacklist=matched, rejection_category=category,
            catch_all_probe=0, catch_all_result="", error=err))

        # Stop at the first MX that answers, even to reject us. Catch-all is a
        # per-domain property, real senders hit the lowest-preference MX first,
        # and a second MX can't clear an IP block that follows our source
        # address. Only keep going if this one was dead at the TCP level.
        if reachable:
            break

    # The catch-all probe. Second RCPT TO for an address that cannot exist: a
    # 250 to that means the domain takes mail for anything.
    #
    # Gate: only when the baseline was accepted. That's the sole case where this
    # adds information, separating a real `hello@` mailbox from a true
    # catch-all. If the baseline was rejected the server already told us it
    # won't take this recipient, and a real catch-all would have said 250 to
    # `hello@` too. So the gate loses no verdicts, and skipping it would mean
    # firing guaranteed-invalid recipients at servers that just said no, which
    # is the directory-harvest pattern reputation systems are built to catch.
    catch_all_likely = 0
    catch_all_inconclusive = 0
    catch_all_skipped = 0
    catch_all_deferred = 0
    catch_all_mx: Optional[str] = None

    if any_2xx_rcpt:
        ca_rcpt = f"{catch_all_localpart(domain)}@{domain}"
        # Only the MX that answered the baseline. Looping the rest can't change
        # a per-domain verdict and doubles our footprint.
        ca_target = reachable_target or targets[0]
        ca_code, ca_msg, ca_err = smtp_probe(ca_target, port, ca_rcpt, timeout, helo=helo)
        ca_category = categorize_rejection(ca_code, ca_msg, domain, ca_target, ca_err)

        if ca_category == CATEGORY_CONNECT_FAILED:
            ca_result = "error"
        elif ca_category == CATEGORY_BLACKHOLE:
            ca_result = "blackhole"
            catch_all_likely = 1
            catch_all_mx = ca_target
        elif ca_category == CATEGORY_ACCEPTED:
            ca_result = "likely"
            catch_all_likely = 1
            catch_all_mx = ca_target
        elif ca_category in INCONCLUSIVE_CATEGORIES:
            # Rejected over sender, IP or policy, so the recipient was never
            # evaluated. We don't know, and retrying elsewhere won't help.
            ca_result = "inconclusive"
            catch_all_inconclusive = 1
        else:
            ca_result = "rejected"

        ca_preview = (ca_msg or "")[:80].replace("\n", " ") if ca_msg else ""
        label = {
            "likely":       _good("likely"),
            "blackhole":    _warn("blackhole"),
            "inconclusive": _warn("inconclusive"),
            "rejected":     _dim("rejected"),
            "error":        _dim("error"),
        }.get(ca_result, ca_result)
        logging.info(_line("catch?", f"{ca_target} rcpt={ca_rcpt} "
                                     f"code={_color_code(ca_code)} result={label} "
                                     f"msg={ca_preview!r}"))

        store_result(conn, run_id, ProbeRow(
            domain=domain, target=ca_target, port=port,
            phase="rcpt_to" if ca_code is not None else "connect",
            ok=1 if ca_err is None else 0, smtp_code=ca_code, smtp_message=ca_msg,
            matched_blacklist=0, rejection_category=ca_category,
            catch_all_probe=1, catch_all_result=ca_result, error=ca_err))

    elif any_reachable:
        # Reached the MX but didn't get a 2xx, so the gate holds the probe back.
        # Why it didn't get one decides what this means.
        if CATEGORY_TEMP_FAILURE in seen_categories:
            # A deferral is not an answer. Greylisting looks exactly like this on
            # first contact, and calling it "no catch-all" is how you undercount.
            # The queue will come back to it.
            catch_all_deferred = 1
            logging.info(_line("catch?", _warn("deferred, baseline got a 4xx (queued for retry)")))
        elif set(seen_categories) & INCONCLUSIVE_CATEGORIES:
            # Blocked on sender, IP or policy. The recipient was never evaluated.
            catch_all_inconclusive = 1
            logging.info(_line("catch?", _warn("inconclusive, server blocked us not the recipient")))
        else:
            # A real recipient rejection. Definitively not a catch-all, and worth
            # recording as "we know, we withheld the probe" rather than a hole.
            catch_all_skipped = 1
            logging.info(_line("catch?", _dim("skipped, baseline rejected the recipient")))

    notes = []
    if any_blacklist:
        notes.append("domain blocked by policy")
    if any_2xx_rcpt:
        notes.append("rcpt accepted (2xx)")
    if not any_reachable:
        notes.append("unreachable")
    if catch_all_likely:
        notes.append("catch-all:blackhole" if catch_all_mx and "blackhole" in catch_all_mx.lower()
                     else "catch-all:likely")
    if catch_all_inconclusive and not catch_all_likely:
        notes.append("catch-all:inconclusive (sender/IP/policy block)")
    if catch_all_deferred:
        notes.append("catch-all:deferred (baseline 4xx, pending retry)")
    if catch_all_skipped:
        notes.append("catch-all:skipped (baseline rejected recipient)")
    if seen_categories:
        notes.append("cat:" + ",".join(seen_categories))

    store_summary(conn, run_id, domain, dns_mode, len(targets),
                  any_blacklist, any_reachable, any_2xx_rcpt, "; ".join(notes) or "",
                  catch_all_likely=catch_all_likely, catch_all_mx=catch_all_mx,
                  registration_date=reg_date, registrar=registrar)

    policy_blocked = catch_all_inconclusive or (CATEGORY_POLICY_BLOCK in seen_categories)
    if catch_all_likely and catch_all_mx and "blackhole" in catch_all_mx.lower():
        state = "blackhole"
    elif catch_all_likely:
        state = "catchall"
    elif any_blacklist:
        state = "blacklisted"
    # Deferred outranks the block states: we got a 4xx, which is a "come back
    # later", and the queue is going to. Reporting it as a negative is the
    # undercount this whole retry path exists to prevent.
    elif catch_all_deferred:
        state = "deferred"
    elif policy_blocked:
        state = "inconclusive"
    elif not any_reachable:
        state = "unreachable"
    else:
        state = "rejected"
    logging.info(_verdict(domain, state, mx=catch_all_mx, reg_date=reg_date, registrar=registrar))


# ---------------------------------------------------------------------------
# Reclassify (offline backfill)
# ---------------------------------------------------------------------------

def reclassify_db(db_path: str) -> None:
    """Re-label stored rows with the current classifier.

    Categories are computed at probe time, so old rows keep whatever the
    classifier said back then. This re-derives each label from the stored code,
    message and error, which means classifier improvements reach historical runs
    without re-probing anybody. No network, no timestamps touched.
    """
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, smtp_code, smtp_message, domain, target, error, "
            "rejection_category, matched_blacklist FROM probe_results "
            "WHERE phase IN ('rcpt_to', 'connect')").fetchall()
        moves: Counter = Counter()
        changed = 0
        for rid, code, msg, domain, target, err, old_cat, old_matched in rows:
            new_cat = categorize_rejection(code, msg, domain, target or "", err)
            new_matched = 1 if match_blacklist(code, msg, domain) else 0
            if new_cat != (old_cat or "") or new_matched != (old_matched or 0):
                conn.execute("UPDATE probe_results SET rejection_category=?, "
                             "matched_blacklist=? WHERE id=?", (new_cat, new_matched, rid))
                changed += 1
                moves[f"{old_cat or 'none'} -> {new_cat}"] += 1
        conn.commit()

    logging.info("reclassify: %d of %d rows relabelled", changed, len(rows))
    for move, n in moves.most_common():
        logging.info("  %5d  %s", n, move)
    print(_paint_out(f"[+] Reclassified {changed} row(s) in {db_path}", Fore.GREEN, Style.BRIGHT))


# ---------------------------------------------------------------------------
# Greylist queue
# ---------------------------------------------------------------------------
# Greylisting defers a first-time sender and expects a retry. That's most of
# what a 4xx means during a sweep, and treating it as "no catch-all" would
# undercount badly. So deferrals go in a durable queue and get retried on a
# curve that looks like a real MTA's.

GREYLIST_BACKOFF = [900, 2700, 7200, 21600]   # 15m, 45m, 2h, 6h


def _add_seconds(iso_ts: str, seconds: int) -> str:
    """`iso_ts` plus seconds, ISO 8601. Falls back to now if the input is junk."""
    t = parse_iso(iso_ts) or dt.datetime.now(dt.timezone.utc)
    return (t + dt.timedelta(seconds=seconds)).replace(microsecond=0).isoformat()


def _enqueue_greylist(conn: sqlite3.Connection, domain: str, target: str, rcpt: str,
                      probe_type: str, first_seen: str, run_id: Optional[int],
                      due_seconds: int) -> bool:
    """Add one triplet to the queue. True if it was actually new.

    INSERT OR IGNORE on the UNIQUE constraint, so an item already in flight
    keeps its own schedule instead of being reset by a later sweep.
    """
    cur = conn.execute(
        "INSERT OR IGNORE INTO greylist_queue "
        "(domain, target, rcpt_addr, probe_type, first_seen_utc, next_due_utc, status, source_run_id) "
        "VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)",
        (domain, target, rcpt, probe_type, first_seen,
         _add_seconds(first_seen, due_seconds), run_id))
    return cur.rowcount > 0


def seed_greylist_queue(conn: sqlite3.Connection, run_id: int,
                        rcpt_localpart: str = DEFAULT_RCPT_LOCALPART) -> int:
    """Queue the greylist-looking deferrals from a run. Returns how many are new.

    Runs automatically after every sweep. Only greylist-tagged 4xx get queued:
    rate limits and full mailboxes won't clear on retry. The recipient is rebuilt
    the same way the sweep formed it, which is what makes the retry present an
    identical triplet.
    """
    added = 0
    for domain, target, code, msg, ca_probe, ts in conn.execute(
            "SELECT domain, target, smtp_code, smtp_message, catch_all_probe, ts_utc "
            "FROM probe_results WHERE run_id=? AND rejection_category=? AND phase='rcpt_to'",
            (run_id, CATEGORY_TEMP_FAILURE)):
        if not looks_like_greylisting(code, msg):
            continue
        rcpt = (f"{catch_all_localpart(domain)}@{domain}" if ca_probe
                else f"{rcpt_localpart}@{domain}")
        ptype = "catch_all" if ca_probe else "baseline"
        if _enqueue_greylist(conn, domain, target, rcpt, ptype, ts, run_id, GREYLIST_BACKOFF[0]):
            added += 1
    conn.commit()
    return added


def process_greylist_queue(db_path: str, port: int, timeout: int,
                           delay: float = DEFAULT_DELAY, jitter: float = DEFAULT_JITTER,
                           helo_override: Optional[str] = None,
                           max_probes: int = 500) -> None:
    """Retry everything that's due, then reschedule or resolve it.

    Safe to run on a cron. Only items with `next_due_utc <= now` get touched, so
    calling it when nothing is due costs one query.

    Per item:
      2xx           resolved_accept. If it was a baseline, the catch-all probe
                    gets chained in due immediately, so confirmation is automatic.
      5xx           resolved_reject.
      4xx greylist  rescheduled on the backoff, or exhausted after the last step.
      anything else soft failure, rescheduled the same way.

    Results land in a new run so the latest-run catch-all queries pick up
    anything that resolved.
    """
    conn = sqlite3.connect(db_path)
    jitter = min(max(jitter, 0.0), 1.0)

    def due_now():
        return conn.execute(
            "SELECT id, domain, target, rcpt_addr, probe_type, attempts, first_seen_utc "
            "FROM greylist_queue WHERE status='pending' AND next_due_utc <= ? "
            "ORDER BY next_due_utc", (utc_now_iso(),)).fetchall()

    pending_total = conn.execute(
        "SELECT COUNT(*) FROM greylist_queue WHERE status='pending'").fetchone()[0]
    batch = due_now()
    if not batch:
        nxt = conn.execute(
            "SELECT MIN(next_due_utc) FROM greylist_queue WHERE status='pending'").fetchone()[0]
        tail = f" (next due {nxt})" if nxt else ""
        logging.info("greylist queue: nothing due, %d pending%s", pending_total, tail)
        print(_paint_out(f"[+] Greylist queue: 0 processed, {pending_total} pending{tail}",
                         Fore.GREEN, Style.BRIGHT))
        return

    logging.info("greylist queue: %d due of %d pending", len(batch), pending_total)
    egress_ip, dnsbl_listed = check_egress_ip()
    helo = pick_helo(egress_ip, helo_override)
    run = create_run(conn, utc_now_iso(), "greylist-queue", "greylist-queue",
                     DEFAULT_RCPT_LOCALPART, egress_ip=egress_ip,
                     dnsbl_listed=", ".join(dnsbl_listed) if dnsbl_listed else None,
                     note="[greylist queue drain]")
    conn.execute("PRAGMA journal_mode=WAL;")

    accepted = rejected = deferred = exhausted = chained = probed = 0
    first = True
    while batch and probed < max_probes:
        for qid, domain, target, rcpt, ptype, attempts, _first_seen in batch:
            if probed >= max_probes:
                break
            if not first and delay > 0:
                time.sleep(max(0.0, delay * (1.0 + random.uniform(-jitter, jitter))))
            first = False

            code, msg, err = smtp_probe(target, port, rcpt, timeout, helo=helo)
            probed += 1
            category = categorize_rejection(code, msg, domain, target, err)
            is_accept = code is not None and 200 <= code < 300
            now = utc_now_iso()

            if is_accept:
                conn.execute("UPDATE greylist_queue SET status='resolved_accept', "
                             "attempts=attempts+1, last_attempt_utc=? WHERE id=?", (now, qid))
                accepted += 1
                verdict = _good(f"accepted ({ptype})")
                # A cleared baseline still needs the fake recipient to confirm
                # catch-all. Queue it due now so this same drain picks it up.
                if ptype == "baseline":
                    ca_rcpt = f"{catch_all_localpart(domain)}@{domain}"
                    if _enqueue_greylist(conn, domain, target, ca_rcpt, "catch_all", now, run, 0):
                        chained += 1
            elif looks_like_greylisting(code, msg):
                n = attempts + 1
                if n >= len(GREYLIST_BACKOFF):
                    conn.execute("UPDATE greylist_queue SET status='exhausted', attempts=?, "
                                 "last_attempt_utc=? WHERE id=?", (n, now, qid))
                    exhausted += 1
                    verdict = _dim(f"exhausted after {n} tries")
                else:
                    conn.execute("UPDATE greylist_queue SET attempts=?, last_attempt_utc=?, "
                                 "next_due_utc=? WHERE id=?",
                                 (n, now, _add_seconds(now, GREYLIST_BACKOFF[n]), qid))
                    deferred += 1
                    verdict = _warn(f"still deferred, +{GREYLIST_BACKOFF[n] // 60}m")
            elif code is not None and code >= 500:
                conn.execute("UPDATE greylist_queue SET status='resolved_reject', "
                             "attempts=attempts+1, last_attempt_utc=? WHERE id=?", (now, qid))
                rejected += 1
                verdict = _dim(f"rejected ({category})")
            else:
                n = attempts + 1
                if n >= len(GREYLIST_BACKOFF):
                    conn.execute("UPDATE greylist_queue SET status='exhausted', attempts=?, "
                                 "last_attempt_utc=? WHERE id=?", (n, now, qid))
                    exhausted += 1
                    verdict = _dim(f"error, exhausted ({category})")
                else:
                    conn.execute("UPDATE greylist_queue SET attempts=?, last_attempt_utc=?, "
                                 "next_due_utc=? WHERE id=?",
                                 (n, now, _add_seconds(now, GREYLIST_BACKOFF[n]), qid))
                    deferred += 1
                    verdict = _dim(f"error, retry ({category})")

            logging.info(_line("gq", f"{rcpt} @ {target} code={_color_code(code)} -> {verdict}"))
            store_result(conn, run, ProbeRow(
                domain=domain, target=target, port=port,
                phase="rcpt_to" if code is not None else "connect",
                ok=1 if err is None else 0, smtp_code=code, smtp_message=msg,
                matched_blacklist=1 if match_blacklist(code, msg, domain) else 0,
                rejection_category=category,
                catch_all_probe=1 if ptype == "catch_all" else 0,
                catch_all_result="likely" if (is_accept and ptype == "catch_all") else "",
                error=err))
        conn.commit()
        batch = due_now()   # picks up the catch-all items chained above

    if probed >= max_probes:
        logging.warning("hit the %d-probe cap, %s items left for the next run",
                        max_probes, "some")
    still_pending = conn.execute(
        "SELECT COUNT(*) FROM greylist_queue WHERE status='pending'").fetchone()[0]
    logging.info("greylist queue: %d probed | %d accepted, %d rejected, %d deferred, "
                 "%d exhausted, %d chained",
                 probed, accepted, rejected, deferred, exhausted, chained)
    print(_paint_out(
        f"[+] Greylist queue run {run}: {accepted} accepted, {rejected} rejected, "
        f"{deferred} re-queued, {exhausted} exhausted ({still_pending} pending)",
        Fore.GREEN, Style.BRIGHT))


def greylist_queue_status(db_path: str) -> None:
    """Print what's in the queue and when it comes due."""
    conn = sqlite3.connect(db_path)
    try:
        counts = dict(conn.execute(
            "SELECT status, COUNT(*) FROM greylist_queue GROUP BY status").fetchall())
    except sqlite3.OperationalError:
        print(_paint_out("[+] Greylist queue is empty (no table yet)", Fore.GREEN, Style.BRIGHT))
        return

    total = sum(counts.values())
    if not total:
        print(_paint_out("[+] Greylist queue is empty", Fore.GREEN, Style.BRIGHT))
        return

    logging.info("greylist queue: %d total", total)
    for s in ("pending", "resolved_accept", "resolved_reject", "exhausted"):
        if counts.get(s):
            logging.info("  %-16s %d", s, counts[s])

    now = utc_now_iso()
    due = conn.execute("SELECT COUNT(*) FROM greylist_queue "
                       "WHERE status='pending' AND next_due_utc<=?", (now,)).fetchone()[0]
    upcoming = conn.execute(
        "SELECT domain, target, probe_type, attempts, next_due_utc FROM greylist_queue "
        "WHERE status='pending' ORDER BY next_due_utc LIMIT 12").fetchall()
    if upcoming:
        logging.info("  %d due now. next pending:", due)
        for domain, target, ptype, attempts, nd in upcoming:
            mark = _good("DUE") if nd <= now else _dim(nd[11:19])
            logging.info("    %s  %-24s %-9s try#%d  %s", mark, domain, ptype, attempts + 1, target)

    gave_up = conn.execute(
        "SELECT domain, target FROM greylist_queue WHERE status='exhausted' "
        "ORDER BY domain").fetchall()
    if gave_up:
        # These stay temp_failure in any write-up. An aggressive greylister is
        # not evidence of anything either way.
        logging.info("  exhausted, report as temp_failure not catch-all: %d", len(gave_up))
        for domain, target in gave_up[:12]:
            logging.info("    %-24s %s", domain, target)

    print(_paint_out(
        f"[+] Greylist queue: {total} items, {counts.get('pending', 0)} pending "
        f"({due} due now), {counts.get('resolved_accept', 0)} accepted, "
        f"{counts.get('resolved_reject', 0)} rejected, {counts.get('exhausted', 0)} exhausted",
        Fore.GREEN, Style.BRIGHT))


# Well-run MTAs used to prove outbound 25 works. Only the greeting is read; no
# mail is offered and nothing is sent, so this costs the operator a TCP accept.
_PORT25_CANARIES = ["gmail-smtp-in.l.google.com", "mx.zoho.com", "aspmx.l.google.com"]


def preflight(port: int = DEFAULT_PORT, timeout: int = 10) -> int:
    """Check whether this host can actually collect usable data. Returns an exit code.

    Answers the four questions that decide whether a run is worth starting: can
    we reach port 25, are we on a blocklist, do we have a PTR, and does that PTR
    forward-confirm. Sends no probes at anything under study.
    """
    print(_paint_out("Preflight", Fore.CYAN, Style.BRIGHT))
    print()
    problems, warnings = [], []

    ip = _get_egress_ip()
    if not ip:
        print(f"  {_bad('[!]')} egress IP    could not be determined (no outbound HTTPS?)")
        return 2
    print(f"  {_good('[+]')} egress IP    {ip}")

    # 1. Reverse DNS, and whether it stands up.
    ptr = ptr_hostname(ip)
    if not ptr:
        print(f"  {_warn('[!]')} PTR          none set")
        warnings.append("No PTR. HELO will be the address literal, which some MTAs penalise. "
                        "Ask your provider to set reverse DNS on the IP.")
        helo = f"[{ip}]"
    elif forward_confirms(ip, ptr):
        print(f"  {_good('[+]')} PTR          {ptr}")
        print(f"  {_good('[+]')} FCrDNS       resolves back to {ip}")
        helo = ptr
    else:
        print(f"  {_bad('[!]')} PTR          {ptr}")
        print(f"  {_bad('[!]')} FCrDNS       does NOT resolve back to {ip}")
        problems.append(f"PTR {ptr} does not forward-confirm. To a receiving MTA that reads "
                        "as a forged name, which is worse than having no PTR. Fix the forward "
                        "record or have the PTR removed.")
        helo = f"[{ip}]"
    print(f"  {_dim('[*]')} HELO will be {helo}")
    print()

    # 2. Blocklists, with the codes decoded.
    rev = _reverse_ip(ip)
    listed, codes = [], []
    for bl in _DNSBLS:
        hits = _check_dnsbl(rev, bl)
        if hits:
            listed.append(bl)
            codes.extend(hits)
    if not listed:
        print(f"  {_good('[+]')} blocklists   clean on all {len(_DNSBLS)}")
    else:
        for bl in listed:
            print(f"  {_bad('[!]')} blocklists   listed on {bl}")
        for c in sorted(set(codes)):
            if c in _ZEN_CODES:
                print(f"      {_dim(c)}  {_ZEN_CODES[c]}")
        if set(codes) & _PBL_CODES:
            problems.append("PBL listing. This is a residential or mobile range and port 25 "
                            "is almost certainly blocked. Use a VPS.")
        else:
            warnings.append("Listed. Rejections may be about your reputation rather than the "
                            "recipient, which shows up as inconclusive rather than as data.")
    print()

    # 3. The one that actually decides it.
    reachable = []
    for host in _PORT25_CANARIES:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            banner = s.recv(256).decode(errors="ignore").strip().splitlines()
            s.close()
            reachable.append(host)
            print(f"  {_good('[+]')} port {port:<5}   {host} -> {(banner[0] if banner else '')[:52]}")
        except Exception as e:
            print(f"  {_bad('[!]')} port {port:<5}   {host} -> {e}")
    if not reachable:
        problems.append(f"Outbound port {port} is blocked. Every domain will report unreachable "
                        "and the run will look like nobody operates a catch-all. This is the "
                        "one thing you cannot work around.")
    print()

    for p in problems:
        print(_paint_out("  [!] " + p, Fore.RED, Style.BRIGHT))
    for w in warnings:
        print(_paint_out("  [?] " + w, Fore.YELLOW))

    if problems:
        print()
        print(_paint_out("[!] Not ready. Fix the above before collecting data.", Fore.RED, Style.BRIGHT))
        return 1
    if warnings:
        print()
        print(_paint_out("[+] Usable, with caveats noted above.", Fore.YELLOW, Style.BRIGHT))
        return 0
    print(_paint_out("[+] Ready to probe.", Fore.GREEN, Style.BRIGHT))
    return 0


def warn_if_port25_blocked(conn: sqlite3.Connection, run_id: int) -> None:
    """Say so when a run looks like it never got out of the building.

    A DNSBL check catches residential ranges, but plenty of cloud providers block
    outbound 25 with no listing at all, and the symptom is identical: every
    domain that resolved to a real MX reports unreachable. Left unexplained that
    reads like "nobody runs a catch-all", which is the wrong conclusion drawn
    from a firewall.

    Only fires when there were enough domains for the ratio to mean anything.
    """
    row = conn.execute(
        "SELECT COUNT(*), SUM(CASE WHEN any_reachable = 0 THEN 1 ELSE 0 END) "
        "FROM probe_domain_summary WHERE run_id = ? AND targets_count > 0",
        (run_id,)).fetchone()
    attempted, unreachable = (row[0] or 0), (row[1] or 0)
    if attempted < 5 or not unreachable:
        return

    pct = 100.0 * unreachable / attempted
    if pct < 90:
        return

    logging.warning("")
    logging.warning("%d of %d domains with a real MX were unreachable (%.0f%%).",
                    unreachable, attempted, pct)
    logging.warning("That is the signature of outbound port 25 being blocked, not of")
    logging.warning("those domains refusing mail. Most residential ISPs, most mobile")
    logging.warning("networks, and several cloud providers block it by default.")
    logging.warning("Check with:  nc -vz -w5 gmail-smtp-in.l.google.com 25")
    logging.warning("If that hangs, this run is not usable. See the README.")
    logging.warning("")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="placeholder_squatting_probe.py",
        description="Find registered placeholder domains that accept mail.",
        epilog="Defaults are tuned to keep your sending IP off blocklists. "
               "Think before you raise the rate.",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    g = ap.add_argument_group("what to probe")
    g.add_argument("--domain", default="",
                   help="Probe one domain and stop. Overrides the batch options.")
    g.add_argument("--prefix", default="",
                   help="A single label to sweep across the TLD list.")
    g.add_argument("--prefixes", default="",
                   help="Several labels, comma or space separated. Overrides --prefix.")
    g.add_argument("--prefixes-file", default="",
                   help="Read labels from a file, one per line ('#' comments allowed). "
                        "The bundled prefixes.txt has the full ~400-label list.")
    g.add_argument("--tlds", default="",
                   help=f"TLDs to sweep, comma separated. Default: {len(TOP_TLDS)} built-in.")
    g.add_argument("--tlds-file", default="",
                   help="Read TLDs from a file, one per line.")
    g.add_argument("--exclude-file", default="",
                   help="Skip these domains, one per line. Use it for domains you own so a "
                        "sweep never probes your own infrastructure.")
    g.add_argument("--rcpt-localpart", default=DEFAULT_RCPT_LOCALPART,
                   help=f"Local part for the baseline RCPT TO (default: {DEFAULT_RCPT_LOCALPART})")

    p = ap.add_argument_group("pacing and identity")
    p.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                   help=f"Seconds between domains (default: {DEFAULT_DELAY}). 0 disables it, "
                        "which is how you get listed.")
    p.add_argument("--jitter", type=float, default=DEFAULT_JITTER,
                   help=f"Randomise each pause by +/- this fraction of --delay, 0 to 1 "
                        f"(default: {DEFAULT_JITTER}). Keeps the cadence off a metronome.")
    p.add_argument("--no-shuffle", dest="shuffle", action="store_false",
                   help="Probe in prefix x TLD order. Default is shuffled so consecutive "
                        "probes don't land on the same MX cluster.")
    p.set_defaults(shuffle=True)
    p.add_argument("--seed", type=int, default=None,
                   help="RNG seed for shuffle and jitter. Default is random, logged, and "
                        "written into the run note so any run can be replayed.")
    p.add_argument("--helo", default=None,
                   help="HELO name. Default is the egress IP's PTR, or its [literal]. "
                        "An unresolvable HELO gets you listed.")

    o = ap.add_argument_group("storage and modes")
    o.add_argument("--db", default=DEFAULT_DB, help=f"SQLite file (default: {DEFAULT_DB})")
    o.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"SMTP port (default: {DEFAULT_PORT})")
    o.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                   help=f"TCP/SMTP timeout in seconds (default: {DEFAULT_TIMEOUT})")
    o.add_argument("--note", default="",
                   help="Free text stored with the run, e.g. 'linode us-east' or 'hotel wifi'.")
    o.add_argument("--resume", action="store_true",
                   help="Continue the last interrupted run instead of starting a new one. "
                        "Reuses its run_id and skips domains that already finished. Re-run "
                        "with the same prefix/TLD options; --seed doesn't matter.")
    o.add_argument("--resume-run-id", type=int, default=None,
                   help="Which run to resume. Default is the most recent batch or single run.")
    o.add_argument("--preflight", action="store_true",
                   help="Check this host can collect usable data (port 25, blocklists, PTR, "
                        "FCrDNS), then exit. Probes nothing under study. Run it first, and "
                        "again whenever the egress IP changes. Exit 1 if not usable.")
    o.add_argument("--reclassify", action="store_true",
                   help="Re-label stored rows with the current classifier and exit. "
                        "No probing, no network.")
    o.add_argument("--process-greylist-queue", action="store_true",
                   help="Retry every queued deferral that's due, then exit. Idempotent, "
                        "so put it on a cron.")
    o.add_argument("--greylist-queue-status", action="store_true",
                   help="Print queue counts and what's due, then exit.")
    o.add_argument("--seed-greylist-queue", action="store_true",
                   help="Backfill the queue from an existing run, then exit. Sweeps seed "
                        "themselves, so this is only for older runs.")
    o.add_argument("--verbose", "-v", action="store_true", help="DEBUG logging for DNS and SMTP.")
    o.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def resolve_prefixes(args) -> List[str]:
    """Work out which labels to sweep. File beats --prefixes beats --prefix."""
    if args.prefixes_file:
        prefixes = load_list_file(args.prefixes_file)
        logging.info("loaded %d prefix(es) from %s", len(prefixes), args.prefixes_file)
        return prefixes
    if args.prefixes:
        return parse_prefixes(args.prefixes)
    if args.prefix:
        return parse_prefixes(args.prefix)
    return list(DEFAULT_PREFIXES)


def resolve_tlds(args) -> List[str]:
    """Work out which TLDs to sweep."""
    if args.tlds_file:
        tlds = load_list_file(args.tlds_file)
        logging.info("loaded %d TLD(s) from %s", len(tlds), args.tlds_file)
        return tlds
    if args.tlds:
        return parse_tlds_arg(args.tlds)
    return list(TOP_TLDS)


def main() -> None:
    args = build_parser().parse_args()

    handler = logging.StreamHandler()
    handler.setFormatter(_ColorFormatter())
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        handlers=[handler])

    if args.preflight:
        sys.exit(preflight(port=args.port, timeout=args.timeout))

    # Offline modes first, before anything touches the network.
    if args.reclassify:
        reclassify_db(args.db)
        return

    if args.greylist_queue_status:
        greylist_queue_status(args.db)
        return

    if args.seed_greylist_queue:
        init_db(args.db)
        with sqlite3.connect(args.db) as conn:
            src = (args.resume_run_id
                   or (conn.execute("SELECT MAX(run_id) FROM probe_runs").fetchone() or [None])[0])
            if not src:
                logging.error("no runs in %s to seed from", args.db)
                return
            row = conn.execute("SELECT rcpt_localpart FROM probe_runs WHERE run_id=?",
                               (src,)).fetchone()
            added = seed_greylist_queue(conn, src, row[0] if row else DEFAULT_RCPT_LOCALPART)
        print(_paint_out(f"[+] Seeded {added} greylist item(s) from run {src}",
                         Fore.GREEN, Style.BRIGHT))
        return

    if args.process_greylist_queue:
        init_db(args.db)
        process_greylist_queue(args.db, args.port, args.timeout, delay=args.delay,
                               jitter=args.jitter, helo_override=args.helo)
        return

    # Always land on a concrete seed, even when the user didn't give one, so the
    # order and pacing of any run can be replayed later.
    if args.seed is None:
        args.seed = random.randrange(2 ** 32)
    random.seed(args.seed)
    args.jitter = min(max(args.jitter, 0.0), 1.0)

    if args.delay <= 0:
        logging.warning("--delay 0: no pacing. Expect your IP to get listed.")
    logging.info("pacing: delay=%.1fs jitter=+/-%d%% shuffle=%s seed=%d",
                 args.delay, int(args.jitter * 100), args.shuffle, args.seed)

    egress_ip, dnsbl_listed = check_egress_ip()
    dnsbl_str = ", ".join(dnsbl_listed) if dnsbl_listed else None
    helo = pick_helo(egress_ip, args.helo)
    logging.info("HELO %s", helo)

    if args.domain:
        run_mode = "single"
        domains = [(args.domain.lower(), f"{args.rcpt_localpart}@{args.domain.lower()}")]
        prefix_label = args.domain.lower()
    else:
        run_mode = "batch"
        prefixes = resolve_prefixes(args)
        tlds = resolve_tlds(args)
        if not prefixes or not tlds:
            logging.error("nothing to probe: %d prefixes, %d TLDs", len(prefixes), len(tlds))
            return
        domains = [(f"{p}.{t}", f"{args.rcpt_localpart}@{p}.{t}") for p in prefixes for t in tlds]
        prefix_label = ",".join(prefixes[:8]) + (",..." if len(prefixes) > 8 else "")

    # Exclusions. This is where your own domains go: a sweep that probes your
    # own honeypots wastes traffic and pollutes the results with hits you
    # already know about.
    if args.exclude_file:
        excluded = set(load_list_file(args.exclude_file))
        before = len(domains)
        domains = [(d, r) for (d, r) in domains if d not in excluded]
        if before - len(domains):
            logging.info("excluded %d domain(s) from %s", before - len(domains), args.exclude_file)
        if not domains:
            logging.warning("everything was excluded, nothing to do")
            return

    if args.shuffle and len(domains) > 1:
        random.shuffle(domains)

    # Fold pacing into the note so a run documents how it was collected.
    pace = f"pace:delay={args.delay},jitter={args.jitter},shuffle={args.shuffle},seed={args.seed}"
    run_note = f"{args.note} [{pace}]" if args.note else f"[{pace}]"

    logging.info("mode=%s prefix=%s rcpt=%s domains=%d db=%s egress=%s dnsbl=%s",
                 run_mode, prefix_label, args.rcpt_localpart, len(domains), args.db,
                 egress_ip or "unknown", dnsbl_str or "clean")

    init_db(args.db)
    seeded = 0

    with sqlite3.connect(args.db) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")   # readers can query while we write

        if args.resume:
            # Skip domains that already finished. A domain counts as finished
            # when its summary row exists, and that's written last, so anything
            # interrupted mid-probe correctly gets probed again. Matching is by
            # name, so shuffle order (and --seed) is irrelevant. You just need
            # the same prefix/TLD options so the rebuilt set matches.
            if args.resume_run_id:
                run_id = args.resume_run_id
                if not conn.execute("SELECT 1 FROM probe_runs WHERE run_id=?", (run_id,)).fetchone():
                    logging.error("--resume: run_id %s not in %s", run_id, args.db)
                    return
            else:
                row = conn.execute("SELECT MAX(run_id) FROM probe_runs "
                                   "WHERE mode IN ('batch','single')").fetchone()
                run_id = row[0] if row else None
            if run_id is None:
                logging.error("--resume: no batch or single run to resume in %s", args.db)
                return

            done = {d for (d,) in conn.execute(
                "SELECT DISTINCT domain FROM probe_domain_summary WHERE run_id=?", (run_id,))}
            before = len(domains)
            domains = [(d, r) for (d, r) in domains if d not in done]
            logging.info("resuming run %s: %d done, %d left of %d",
                         run_id, len(done), len(domains), before)
            if not domains:
                print(_paint_out(f"[+] Run {run_id} is already complete", Fore.GREEN, Style.BRIGHT))
                return
        else:
            run_id = create_run(conn, utc_now_iso(), run_mode, prefix_label,
                                args.rcpt_localpart, egress_ip=egress_ip,
                                dnsbl_listed=dnsbl_str, note=run_note)
            logging.info("run_id=%s", run_id)

        total = len(domains)
        try:
            for i, (domain, rcpt) in enumerate(domains, 1):
                probe_domain(conn, run_id, domain, rcpt, args.port, args.timeout,
                             index=i, total=total, helo=helo)
                if args.delay and i < total:
                    pause = max(0.0, args.delay * (1.0 + random.uniform(-args.jitter, args.jitter)))
                    logging.debug("sleeping %.1fs", pause)
                    time.sleep(pause)
        except KeyboardInterrupt:
            # Everything so far is already committed. Say how to pick it up.
            logging.warning("interrupted. Resume with: --resume --resume-run-id %s", run_id)

        conn.commit()
        warn_if_port25_blocked(conn, run_id)
        seeded = seed_greylist_queue(conn, run_id, args.rcpt_localpart)
        if seeded:
            logging.info("queued %d deferral(s), drain with --process-greylist-queue", seeded)

    print(_paint_out(f"[+] Stored in {args.db} (run_id={run_id})", Fore.GREEN, Style.BRIGHT))
    if seeded:
        print(_paint_out(f"[+] {seeded} greylisted triplet(s) queued for retry",
                         Fore.GREEN, Style.BRIGHT))
    print(_paint_out(
        f"[*] Catch-alls: sqlite3 {args.db} \"SELECT domain, catch_all_mx, registrar "
        f"FROM probe_domain_summary WHERE catch_all_likely=1 AND run_id={run_id}\"",
        Style.DIM))


if __name__ == "__main__":
    main()
