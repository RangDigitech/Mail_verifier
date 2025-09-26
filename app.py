#!/usr/bin/env python3
"""
mailso_clone_verifier.py
A Mail.so-like email verifier (raw standalone script)

Features:
- syntax check
- MX lookup (with A/AAAA fallback)
- SPF / DKIM / DMARC checks
- SMTP probing across *all* MX hosts:
    - RCPT TO target
    - RCPT TO random nonexistent
    - aggregate host-level responses
- provider-specific heuristics (Gmail, Yahoo/AOL, Outlook/Hotmail)
- retry on 4xx (greylisting) with exponential backoff
- sqlite caching for MX & SMTP host results
- concurrency via ThreadPoolExecutor
- outputs: CSV + JSON
"""

from __future__ import annotations
import re
import os
import csv
import sys
import time
import json
import random
import socket
import sqlite3
import argparse
import smtplib
import threading
import logging
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from tqdm import tqdm
import dns.resolver, dns.exception

# -------------------------
# Configurable parameters
# -------------------------
SMTP_TIMEOUT = 3                 # seconds per SMTP connection attempt
DNS_TIMEOUT = 6                  # seconds per DNS query
SMTP_RETRY_COUNT = 0             # retries for 4xx (greylist) responses
SMTP_RETRY_BACKOFF = 3           # base seconds for backoff (exponential)
DEFAULT_WORKERS = 8
DB_DEFAULT = "mailso_verifier_cache.db"
LOG_LEVEL = logging.INFO

# Limits for safety
MAX_CONCURRENT_SMTP = 40         # recommended maximum to avoid rate-limiting by providers

# Lightweight lists (expandable)
DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.net", "10minutemail.com", "trashmail.com", "guerrillamail.com"
}
ROLE_LOCALPARTS = {"admin", "administrator", "info", "support", "sales", "contact", "help", "office", "postmaster"}
FREE_PROVIDERS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "aol.com"}

# Provider-specific tuning (feel free to extend)
# 'mode' values:
#  - 'trust_mx' : if MX exists and target accepted then consider valid (Gmail-like)
#  - 'strict' : require host-level evidence (target accepted while random rejected) to mark valid (Yahoo-like)
PROVIDER_RULES = {
    # TRUST MX (if syntax+MX are good, usually reliable even if catch-all-like)
    "gmail.com": {"mode": "trust_mx"},
    "googlemail.com": {"mode": "trust_mx"},
    "hotmail.com": {"mode": "trust_mx"},
    "outlook.com": {"mode": "trust_mx"},
    "live.com": {"mode": "trust_mx"},
    "msn.com": {"mode": "trust_mx"},
    "icloud.com": {"mode": "trust_mx"},
    "me.com": {"mode": "trust_mx"},

    # STRICT (require target accepted AND random rejected)
    "yahoo.com": {"mode": "strict"},
    "ymail.com": {"mode": "strict"},
    "rocketmail.com": {"mode": "strict"},
    "aol.com": {"mode": "strict"},
    "rediffmail.com": {"mode": "strict"},
    "gmx.com": {"mode": "strict"},
    "gmx.net": {"mode": "strict"},
    "mail.com": {"mode": "strict"},
    "zoho.com": {"mode": "strict"},
    "protonmail.com": {"mode": "strict"},

    # LEGACY INDIAN ISPs (many now dead or unreliable → mark risky unless explicit)
    "vsnl.com": {"mode": "strict"},
    "vsnl.net": {"mode": "strict"},
    "vsnl.net.in": {"mode": "strict"},
    "sify.com": {"mode": "strict"},
    "mtnl.net.in": {"mode": "strict"},
    "bharatmail.com": {"mode": "strict"},
}

# Regex for strong but manageable RFC-ish validation
EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,}$"
)

# Patterns indicating user-not-found in SMTP textual response
SMTP_USER_NOT_FOUND_PATTERNS = [
    r"user not found", r"unknown user", r"no such user", r"recipient .* not found", r"mailbox unavailable",
    r"unknown recipient", r"550 5\.1\.1", r"recipient unknown"
]
SMTP_USER_NOT_FOUND_RE = re.compile("|".join(SMTP_USER_NOT_FOUND_PATTERNS), re.IGNORECASE)

# Logging
logger = logging.getLogger("mailso_clone")
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(ch)
logger.setLevel(LOG_LEVEL)

# DB lock
db_lock = threading.Lock()

# -------------------------
# DB (SQLite) helpers
# -------------------------
def connect_db(path: str) -> sqlite3.Connection:
    # ensure directory exists
    pdir = os.path.dirname(os.path.abspath(path))
    os.makedirs(pdir, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    return conn

def init_db(conn: sqlite3.Connection) -> None:
    with db_lock:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS mx_cache (
                domain TEXT PRIMARY KEY,
                mx_hosts TEXT,
                ts INTEGER
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS smtp_cache (
                host TEXT PRIMARY KEY,
                smtp_ok INTEGER,
                last_checked_ts INTEGER,
                sample_msg TEXT
            )
        """)
        conn.commit()

def cache_mx(conn: sqlite3.Connection, domain: str, mx_hosts: List[str]) -> None:
    with db_lock:
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO mx_cache(domain, mx_hosts, ts) VALUES (?, ?, ?)",
                    (domain, json.dumps(mx_hosts), int(time.time())))
        conn.commit()

def get_cached_mx(conn: sqlite3.Connection, domain: str, max_age_days: int = 7) -> Optional[List[str]]:
    with db_lock:
        cur = conn.cursor()
        cur.execute("SELECT mx_hosts, ts FROM mx_cache WHERE domain = ?", (domain,))
        r = cur.fetchone()
        if not r:
            return None
        mx_hosts = json.loads(r[0])
        ts = int(r[1])
        if time.time() - ts > max_age_days * 86400:
            return None
        return mx_hosts

def cache_smtp_result(conn: sqlite3.Connection, host: str, smtp_ok: bool, sample_msg: str) -> None:
    with db_lock:
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO smtp_cache(host, smtp_ok, last_checked_ts, sample_msg) VALUES (?, ?, ?, ?)",
                    (host, int(smtp_ok), int(time.time()), sample_msg[:512]))
        conn.commit()

def get_cached_smtp(conn: sqlite3.Connection, host: str, max_age_days: int = 1) -> Optional[Dict[str, Any]]:
    with db_lock:
        cur = conn.cursor()
        cur.execute("SELECT smtp_ok, last_checked_ts, sample_msg FROM smtp_cache WHERE host = ?", (host,))
        r = cur.fetchone()
        if not r:
            return None
        smtp_ok, ts, msg = int(r[0]), int(r[1]), r[2]
        if time.time() - ts > max_age_days * 86400:
            return None
        return {"smtp_ok": bool(smtp_ok), "response": msg}

# -------------------------
# DNS helpers
# -------------------------
def norm_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")

def lookup_mx(domain: str) -> List[str]:
    domain = norm_domain(domain)
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=DNS_TIMEOUT)
        mxs = []
        for r in answers:
            mxs.append(str(r.exchange).rstrip("."))
        # sort by MX priority (dns.resolver returns in priority order often but we don't rely on that)
        return mxs
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        # fallback to A/AAAA per RFC when no MX
        hosts = []
        try:
            a_answers = dns.resolver.resolve(domain, "A", lifetime=DNS_TIMEOUT)
            for a in a_answers:
                hosts.append(str(a))
        except Exception:
            pass
        try:
            aaaa_answers = dns.resolver.resolve(domain, "AAAA", lifetime=DNS_TIMEOUT)
            for a in aaaa_answers:
                hosts.append(str(a))
        except Exception:
            pass
        return hosts
    except dns.exception.Timeout:
        raise
    except Exception as e:
        logger.debug(f"Unexpected DNS error for {domain}: {e}")
        return []

def lookup_txt(domain: str) -> List[str]:
    domain = norm_domain(domain)
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=DNS_TIMEOUT)
        txts = []
        for r in answers:
            # r.strings isn't guaranteed; use to_text
            txts.append(r.to_text().strip('"'))
        return txts
    except Exception:
        return []

def has_spf(domain: str) -> bool:
    txts = lookup_txt(domain)
    for t in txts:
        if "v=spf1" in t.lower():
            return True
    return False

def has_dmarc(domain: str) -> bool:
    txts = lookup_txt(f"_dmarc.{domain}")
    for t in txts:
        if "v=dmarc1" in t.lower():
            return True
    return False

def has_dkim(domain: str, selectors: Optional[List[str]] = None) -> bool:
    if selectors is None:
        selectors = ["default", "selector1", "s1", "google", "mail"]
    for s in selectors:
        txts = lookup_txt(f"{s}._domainkey.{domain}")
        for t in txts:
            if "v=dkim1" in t.lower():
                return True
    return False

# -------------------------
# SMTP probe helpers
# -------------------------
def smtp_connect_and_rcpt(mx_host: str, smtp_from: str, rcpt: str, timeout: int = SMTP_TIMEOUT) -> Dict[str, Any]:
    """
    Connect to mx_host:25, issue EHLO/HELO, MAIL FROM, RCPT TO.
    Returns dict with keys: code (int|None), message (str), accepted(bool), perm(bool), temp(bool)
    """
    res = {"code": None, "message": "", "accepted": False, "perm": False, "temp": False}
    mx_host = str(mx_host).rstrip(".")
    try:
        s = smtplib.SMTP(timeout=timeout)
        # connect may raise exception
        s.connect(mx_host, 25)
        # try EHLO then HELO fallback
        try:
            s.ehlo()
        except Exception:
            try:
                s.helo()
            except Exception:
                pass
        # set MAIL FROM; some servers tolerate odd values, use a valid-looking domain
        try:
            s.mail(smtp_from)
        except Exception:
            # keep moving; some servers expect EHLO first
            pass
        # RCPT TO
        code, msg = s.rcpt(rcpt)
        # sometimes msg is bytes or tuple; convert safely
        try:
            res["code"] = int(code) if code is not None else None
        except Exception:
            res["code"] = None
        try:
            if isinstance(msg, (bytes, bytearray)):
                res["message"] = msg.decode(errors="ignore")
            else:
                res["message"] = str(msg)
        except Exception:
            res["message"] = str(msg)
        if res["code"] is not None:
            if 200 <= res["code"] < 300:
                res["accepted"] = True
            elif 400 <= res["code"] < 500:
                res["temp"] = True
            elif 500 <= res["code"] < 600:
                res["perm"] = True
        # textual hints
        if SMTP_USER_NOT_FOUND_RE.search(res["message"] or ""):
            res["perm"] = True
            res["accepted"] = False
        # close
        try:
            s.quit()
        except Exception:
            try:
                s.close()
            except Exception:
                pass
    except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        res["message"] = f"connect_error:{e}"
        # treat connect errors as temporary/unresolved
        res["temp"] = True
    except Exception as e:
        # other exceptions
        res["message"] = f"error:{e}"
    return res

def probe_host_with_retries(host: str, smtp_from: str, rcpt: str, retries: int = SMTP_RETRY_COUNT) -> Dict[str, Any]:
    """Probe host; if temp error (4xx) retry with exponential backoff."""
    attempt = 0
    last_res = None
    while attempt <= retries:
        res = smtp_connect_and_rcpt(host, smtp_from, rcpt)
        last_res = res
        # if success or permanent error, return immediately
        if res.get("accepted") or res.get("perm"):
            return res
        # if temp -> maybe retry
        if res.get("temp"):
            attempt += 1
            backoff = SMTP_RETRY_BACKOFF * (2 ** (attempt - 1))
            time.sleep(backoff)
            continue
        # else ambiguous -> return
        return res
    return last_res

# -------------------------
# Domain-level probe: target vs random across MX hosts
# -------------------------
def probe_domain(mx_hosts: List[str], domain: str, smtp_from: str, target_email: str, db_conn: Optional[sqlite3.Connection]) -> Dict[str, Any]:
    """
    For each MX host: probe target and a generated random (nonexistent) address.
    Aggregate the host responses and apply decision heuristics.

    Returns:
      {
        "smtp_ok": True/False/None,
        "catch_all": True/False/None,
        "hosts": [ {host, target_res, random_res} ],
        "reason": str
      }
    """
    domain = norm_domain(domain)
    rand_local = "noexist_" + ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))
    random_addr = f"{rand_local}@{domain}"
    host_results = []

    # probe each host in order; consult per-host smtp cache to reduce load
    for host in mx_hosts:
        # consult smtp cache
        cached = None
        if db_conn:
            cached = get_cached_smtp(db_conn, host)
        # If cached and recent and matches what we need, we can skip real probe for performance.
        # But we still should probe target vs random to get per-address result, so we won't skip.
        # Probe target
        t_res = probe_host_with_retries(host, smtp_from, target_email)
        # Probe random
        r_res = probe_host_with_retries(host, smtp_from, random_addr)
        host_results.append({"host": host, "target": t_res, "random": r_res})
        # cache host-level smtp success/accept if obvious
        try:
            if db_conn:
                # treat smtp_ok as True if host accepted random or target (host can accept RCPT)
                smtp_ok_flag = bool((t_res.get("accepted") or r_res.get("accepted")))
                sample = f"T:{t_res.get('code')}-{(t_res.get('message') or '')[:140]}|R:{r_res.get('code')}-{(r_res.get('message') or '')[:140]}"
                cache_smtp_result(db_conn, host, smtp_ok_flag, sample)
        except Exception:
            pass

    # Aggregation rules (practical heuristics)
    any_perm_reject_target = any(hr["target"].get("perm") for hr in host_results)
    any_accept_target = any(hr["target"].get("accepted") for hr in host_results)
    any_accept_random = any(hr["random"].get("accepted") for hr in host_results)
    host_accept_target_and_reject_random = any(
        (hr["target"].get("accepted") and (hr["random"].get("perm") or not hr["random"].get("accepted"))) for hr in host_results
    )
    any_temp = any(hr["target"].get("temp") or hr["random"].get("temp") for hr in host_results)

    smtp_ok = None
    catch_all = None
    reason = ""

    # If all responding hosts permanently reject target and none accept it -> invalid
    if any_perm_reject_target and not any_accept_target:
        smtp_ok = False
        catch_all = False
        reason = "All responding hosts permanently rejected target"
    # If at least one host accepts target and the same host rejects random -> valid
    elif host_accept_target_and_reject_random:
        smtp_ok = True
        catch_all = False
        reason = "At least one MX accepts target but rejects random -> target likely exists"
    # If target accepted but random not accepted across hosts -> valid-ish
    elif any_accept_target and not any_accept_random:
        smtp_ok = True
        catch_all = False
        reason = "Target accepted by one/more hosts while random not accepted -> likely valid"
    # If both target and random accepted across hosts -> catch-all / ambiguous
    elif any_accept_target and any_accept_random:
        smtp_ok = None
        catch_all = True
        reason = "Hosts accept both target and random -> catch-all / ambiguous"
    elif any_temp:
        smtp_ok = None
        catch_all = None
        reason = "Temporary errors encountered (4xx / greylisting) -> ambiguous"
    else:
        smtp_ok = None
        catch_all = None
        reason = "No clear acceptance/rejection pattern -> ambiguous"

    # If contradictory evidence: e.g., some hosts perm-reject while others accept -> ambiguous/risky
    if any_perm_reject_target and any_accept_target:
        smtp_ok = None
        reason = "Disagreement across MX hosts (some 5xx, some 250) -> ambiguous / risky"

    return {
        "smtp_ok": smtp_ok,
        "catch_all": catch_all,
        "hosts": host_results,
        "reason": reason
    }

# -------------------------
# Per-email validation pipeline
# -------------------------
def validate_single(email: str, smtp_from: str, db_conn: sqlite3.Connection, smtp_probe_flag: bool) -> Dict[str, Any]:
    """
    Returns a dictionary with detailed findings for 'email'.
    """
    result: Dict[str, Any] = {
        "email": email,
        "local_part": None, "domain": None,
        "syntax_ok": False,
        "disposable": False, "role_based": False, "free_provider": False,
        "mx_hosts": [], "mx_ok": False,
        "spf": False, "dkim": False, "dmarc": False,
        "smtp_tested": False, "smtp_ok": None, "catch_all": None, "smtp_reason": "",
        "score": None, "final_status": None, "notes": [], "probe_details": None
    }

    email_str = (email or "").strip()
    result["email"] = email_str

    if not email_str:
        result["final_status"] = "invalid"
        result["notes"].append("empty address")
        result["score"] = 0
        return result

    # Syntax check
    if not EMAIL_REGEX.match(email_str):
        result["syntax_ok"] = False
        result["final_status"] = "invalid"
        result["notes"].append("invalid syntax")
        result["score"] = 0
        return result
    result["syntax_ok"] = True

    # Parse local/domain
    try:
        local, domain = email_str.rsplit("@", 1)
    except Exception:
        result["syntax_ok"] = False
        result["final_status"] = "invalid"
        result["notes"].append("invalid parsing")
        result["score"] = 0
        return result

    domain = norm_domain(domain)
    result["local_part"] = local
    result["domain"] = domain
    result["disposable"] = domain in DISPOSABLE_DOMAINS
    result["role_based"] = local.lower() in ROLE_LOCALPARTS or any(local.lower().startswith(r + "+") for r in ROLE_LOCALPARTS)
    result["free_provider"] = domain in FREE_PROVIDERS

    # MX lookup (with cache)
    cached_mx = None
    try:
        cached_mx = get_cached_mx(db_conn, domain) if db_conn else None
    except Exception:
        cached_mx = None

    if cached_mx is not None:
        mx_hosts = cached_mx
    else:
        try:
            mx_hosts = lookup_mx(domain)
        except dns.exception.Timeout:
            result["notes"].append("dns timeout during MX lookup")
            mx_hosts = []
        except Exception as e:
            result["notes"].append(f"mx lookup error: {e}")
            mx_hosts = []

        if db_conn is not None:
            try:
                cache_mx(db_conn, domain, mx_hosts)
            except Exception:
                pass

    result["mx_hosts"] = mx_hosts
    result["mx_ok"] = bool(mx_hosts)

    # If no MX and no A/AAAA fallback -> invalid domain for mail
    if not mx_hosts:
        result["final_status"] = "invalid"
        result["notes"].append("no MX/A records")
        result["score"] = 0
        # also still populate SPF/DKIM/DMARC if possible
        result["spf"] = has_spf(domain)
        result["dkim"] = has_dkim(domain)
        result["dmarc"] = has_dmarc(domain)
        return result

    # Auth checks
    try:
        result["spf"] = has_spf(domain)
        result["dkim"] = has_dkim(domain)
        result["dmarc"] = has_dmarc(domain)
    except Exception:
        pass

    # SMTP probing (if requested)
    probe_res = None
    if smtp_probe_flag:
        result["smtp_tested"] = True
        try:
            probe_res = probe_domain(mx_hosts, domain, smtp_from, email_str, db_conn)
            result["smtp_ok"] = probe_res["smtp_ok"]
            result["catch_all"] = probe_res["catch_all"]
            result["smtp_reason"] = probe_res["reason"]
            result["probe_details"] = probe_res["hosts"]
            if probe_res["reason"]:
                result["notes"].append(probe_res["reason"])
        except dns.exception.Timeout:
            result["notes"].append("smtp probe dns timeout")
        except Exception as e:
            result["notes"].append(f"smtp probe error: {e}")

    # apply provider-specific heuristics
    pr = PROVIDER_RULES.get(domain)
    # default heuristic (if not provider-specific)
    # scoring base
    score = 50
    if not result["syntax_ok"]:
        score -= 50
    if result["mx_ok"]:
        score += 20
    if result["disposable"]:
        score -= 40
    if result["role_based"]:
        score -= 10
    if result["free_provider"]:
        score += 5
    if result["spf"]:
        score += 5
    if result["dkim"]:
        score += 5
    if result["dmarc"]:
        score += 5

    # SMTP influences
    if smtp_probe_flag:
        if result["smtp_ok"] is True:
            score += 25
        elif result["smtp_ok"] is False:
            score -= 40
        else:
            # ambiguous
            score -= 5

        if result["catch_all"]:
            score -= 20

    # Provider-specific overrides/tuning
    if pr:
        mode = pr.get("mode")
        if mode == "trust_mx":
            # For Gmail/Outlook-like: if mx present and no explicit perm reject -> treat more confidently
            if result["mx_ok"] and (result["smtp_ok"] is not False):
                # boost score a bit
                score += 10
            # If probes found explicit perm rejection -> keep invalid
            if result["smtp_ok"] is False:
                score -= 30
        elif mode == "strict":
            # For Yahoo/AOL-like: require explicit host-level evidence (target accepted & random rejected) to consider valid
            if result["smtp_ok"] is True and not result["catch_all"]:
                score += 15
            else:
                # If ambiguous, more conservative
                if result["smtp_ok"] is None:
                    score -= 10

    score = max(0, min(100, int(score)))
    result["score"] = score

    # Final status thresholds (tunable)
    if score >= 75:
        final = "valid"
    elif score >= 45:
        final = "risky"
    else:
        final = "invalid"

    result["final_status"] = final

    # Helpful notes
    if result["disposable"]:
        result["notes"].append("disposable domain")
    if result["role_based"]:
        result["notes"].append("role-based mailbox")
    if result["catch_all"]:
        result["notes"].append("catch-all detected")
    if result["smtp_tested"] and result["smtp_ok"] is False:
        result["notes"].append("smtp rejected (permanent)")

    return result

# -------------------------
# Runner: process CSV and produce outputs
# -------------------------
def load_emails_from_csv(path: str) -> List[str]:
    emails = []
    with open(path, newline="", encoding="utf-8") as f:
        # support header 'email' or single col list
        sample = f.read(8192)
        f.seek(0)
        reader = csv.reader(f)
        rows = list(reader)
        if not rows:
            return []
        # if header row contains '@' assume no header
        first = rows[0]
        if any("@" in cell for cell in first):
            # treat all rows as emails (first included)
            for r in rows:
                if r and r[0].strip():
                    emails.append(r[0].strip())
        else:
            # if first cell lower == email then parse column
            if first and first[0].strip().lower() == "email":
                for r in rows[1:]:
                    if r and r[0].strip():
                        emails.append(r[0].strip())
            else:
                # treat first column as data
                for r in rows:
                    if r and r[0].strip():
                        emails.append(r[0].strip())
    return emails

def write_outputs(results: List[Dict[str, Any]], outdir: str) -> None:
    os.makedirs(outdir, exist_ok=True)
    csv_path = os.path.join(outdir, "results.csv")
    json_path = os.path.join(outdir, "results.json")

    # determine fieldnames (flatten probe details to string)
    if not results:
        print("No results to write.")
        return

    # build rows with consistent fields
    rows = []
    # pick canonical header order
    header = [
        "email", "final_status", "score", "syntax_ok", "local_part", "domain",
        "mx_ok", "mx_hosts", "smtp_tested", "smtp_ok", "catch_all",
        "spf", "dkim", "dmarc", "disposable", "role_based", "free_provider",
        "smtp_reason", "notes", "probe_details"
    ]
    for r in results:
        row = {}
        for h in header:
            if h == "mx_hosts":
                row[h] = ",".join(r.get("mx_hosts") or [])
            elif h == "probe_details":
                # compact string of host probe summaries
                pd = r.get("probe_details")
                if not pd:
                    row[h] = ""
                else:
                    parts = []
                    for hr in pd:
                        host = hr.get("host")
                        t = hr.get("target") or {}
                        rr = hr.get("random") or {}
                        parts.append(f"{host}:T({t.get('code')},int(bool(t.get('accepted')))))R({rr.get('code')},int(bool(rr.get('accepted')))))")
                    row[h] = " | ".join(parts)
            elif h == "notes":
                row[h] = " ; ".join(r.get("notes") or [])
            else:
                row[h] = r.get(h) if h in r else ""
        rows.append(row)

    # write CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    # write JSON (full)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"results": results}, f, indent=2)

    logger.info(f"Wrote CSV -> {csv_path}")
    logger.info(f"Wrote JSON -> {json_path}")

def run_file(input_file: str, outdir: str, smtp_flag: bool, smtp_from: str, db_path: str, workers: int) -> None:
    if workers < 1:
        workers = 1
    if workers > MAX_CONCURRENT_SMTP:
        logger.warning(f"Clamping workers to {MAX_CONCURRENT_SMTP} to avoid overloading remote servers.")
        workers = MAX_CONCURRENT_SMTP

    emails = load_emails_from_csv(input_file)
    total = len(emails)
    if total == 0:
        logger.error("No emails loaded from input file.")
        return

    logger.info(f"Loaded {total} emails. Workers={workers}. SMTP probing={'ON' if smtp_flag else 'OFF'}")

    db_conn = connect_db(db_path)
    init_db(db_conn)

    results: List[Dict[str, Any]] = []
    summary = defaultdict(int)

    # Use ThreadPoolExecutor: SMTP connects are IO-bound
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(validate_single, e, smtp_from, db_conn, smtp_flag): e for e in emails}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="Validating"):
            email = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:
                logger.exception(f"Error validating {email}: {exc}")
                res = {"email": email, "final_status": "error", "notes": [str(exc)]}
            results.append(res)
            summary[res.get("final_status", "unknown")] += 1

    # write outputs
    write_outputs(results, outdir)
    logger.info(f"Summary: {dict(summary)}")

# -------------------------
# CLI
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Mail.so-like email verifier (raw script)")
    p.add_argument("input_file", help="CSV file with emails (single column or with header 'email')")
    p.add_argument("--outdir", default="results", help="Directory to write results")
    p.add_argument("--smtp", action="store_true", help="Enable SMTP RCPT probing (recommended for accuracy)")
    p.add_argument("--smtp-from", default="noreply@example.com", help="MAIL FROM value used during SMTP probes")
    p.add_argument("--db", default=DB_DEFAULT, help="SQLite DB path for caching")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Number of concurrent workers (IO-bound)")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    run_file(args.input_file, args.outdir, args.smtp, args.smtp_from, args.db, args.workers)
