#!/usr/bin/env python3
"""
ghost.py — OSINT recon framework v3
beautiful terminal · advanced modules · interactive shell
"""

import sys, os, re, json, socket, hashlib, time, argparse, ipaddress, ssl
import urllib.parse, base64, struct, random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ── dependency check ──────────────────────────────────────────────────────────
_missing = []
try:    import requests
except: _missing.append("requests")
try:    import dns.resolver, dns.zone, dns.query, dns.rdatatype
except: _missing.append("dnspython")
try:    import whois
except: _missing.append("python-whois")
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.align import Align
    from rich import box
    from rich.markup import escape
    from rich.tree import Tree
    from rich.padding import Padding
    from rich.style import Style
    from rich.live import Live
    from rich.layout import Layout
    from rich.segment import Segment
except: _missing.append("rich")

if _missing:
    print(f"[!] missing : {', '.join(_missing)}")
    print("  please install requirments.txt")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
#  GLOBALS
# ══════════════════════════════════════════════════════════════════════════════

console   = Console(highlight=False)
VERSION   = "v3.0"
LOG       = []          # (timestamp, module, line)
HISTORY   = []          # command history

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
HEADERS_HTTP = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}

# ══════════════════════════════════════════════════════════════════════════════
#  DECORATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

BANNER_ART = """[bold white]\
 ██████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓
▒██    ▒ ▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒
░ ▓██▄   ▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░
  ▒   ██▒░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░ 
▒██████▒▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░ 
▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░  
░ ░▒  ░ ░ ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░   
░  ░  ░   ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░     
      ░   ░  ░  ░    ░ ░        ░          [/bold white]"""

TAGLINE_PARTS = [
    ("◆ ", "dim white"),
    ("open source intelligence", "white"),
    ("  ·  ", "dim"),
    ("passive recon framework", "dim white"),
    ("  ·  ", "dim"),
    (VERSION, "dim white"),
    ("  ◆", "dim white"),
]

MODULE_ICONS = {
    "username": "◈",
    "email":    "✉",
    "domain":   "⬡",
    "ip":       "⊙",
    "phone":    "☏",
    "url":      "⌁",
    "ports":    "⊞",
    "dns":      "⊛",
    "breach":   "⚿",
    "ssl":      "⬜",
    "headers":  "⊟",
    "whois":    "⊡",
    "geo":      "⊕",
    "tech":     "⊗",
    "sub":      "⊜",
    "asn":      "⊘",
    "crawler":  "⟳",
    "traceroute":"⟶",
    "cert":     "⬟",
}

# colour theme
C = {
    "accent":   "white",
    "dim":      "dim white",
    "good":     "green",
    "warn":     "yellow",
    "bad":      "red",
    "info":     "cyan",
    "label":    "dim",
    "value":    "white",
    "url":      "cyan",
    "hi":       "bold white",
}


def _t(text, color): return f"[{color}]{escape(str(text))}[/{color}]"


def print_banner():
    console.print()
    # top border
    console.print(f"[dim]{'═'*66}[/dim]")
    console.print()
    console.print(Align.center(BANNER_ART))
    console.print()
    # tagline
    tag = ""
    for txt, col in TAGLINE_PARTS:
        tag += f"[{col}]{txt}[/{col}]"
    console.print(Align.center(tag))
    console.print()
    console.print(f"[dim]{'═'*66}[/dim]")
    # stats bar
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    console.print(
        f"  [dim]session started[/dim] [dim white]{now}[/dim white]"
        f"   [dim]│[/dim]   "
        f"[dim]type[/dim] [white]help[/white] [dim]for commands[/dim]"
    )
    console.print(f"[dim]{'─'*66}[/dim]")
    console.print()


def section_header(module_key, title, target=""):
    icon = MODULE_ICONS.get(module_key, "◆")
    console.print()
    console.print(f"[dim]╔{'═'*64}╗[/dim]")
    left  = f"[dim]║[/dim]  [bold white]{icon}  {title}[/bold white]"
    right = f"[dim white]{escape(target)}[/dim white]  [dim]║[/dim]"
    pad   = 64 - len(f"  {icon}  {title}") - len(f"{target}  ")
    console.print(f"{left}{'': <{max(1,pad)}}{right}")
    console.print(f"[dim]╚{'═'*64}╝[/dim]")


def sub_header(title):
    line = f"─── {title} "
    line += "─" * max(0, 62 - len(line))
    console.print(f"\n  [dim]{line}[/dim]")


def row(label, value, color=None, good=None, icon=None):
    color = color or C["info"]
    if good is True:    color, sfx = C["good"], " [dim]✓[/dim]"
    elif good is False: color, sfx = C["bad"],  " [dim]✗[/dim]"
    elif good == "warn":color, sfx = C["warn"],  " [dim]⚠[/dim]"
    else:               sfx = ""
    ico = f" {icon}" if icon else "  "
    console.print(f"{ico} [dim]{label:<26}[/dim][{color}]{escape(str(value))}[/{color}]{sfx}")


def blank(): console.print()
def ok(m):   console.print(f"   [green]✓[/green]  {m}")
def warn(m): console.print(f"   [yellow]⚠[/yellow]  {m}")
def err(m):  console.print(f"   [red]✗[/red]  {m}")
def info(m): console.print(f"   [dim]·  {escape(str(m))}[/dim]")

def result_table(columns, rows, title=""):
    t = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold dim",
        border_style="dim",
        title=f"[dim]{title}[/dim]" if title else "",
        title_justify="left",
        padding=(0,1),
    )
    for col in columns:
        if isinstance(col, tuple):
            t.add_column(col[0], **col[1])
        else:
            t.add_column(col, style="white")
    for r in rows:
        t.add_row(*[str(c) for c in r])
    console.print(Padding(t, (0,2)))


def divider():
    console.print(f"\n[dim]{'─'*66}[/dim]")


def log(module, line):
    LOG.append((datetime.now().strftime("%H:%M:%S"), module, str(line)))


def bar_prog(desc="working...", total=100):
    return Progress(
        SpinnerColumn(spinner_name="dots2", style="white"),
        TextColumn(f"[dim]{desc}[/dim]"),
        BarColumn(bar_width=32, style="dim", complete_style="white", finished_style="dim white"),
        TaskProgressColumn(style="dim"),
        TimeElapsedColumn(),
        console=console, transient=True,
    )


def spin_prog(desc="working..."):
    return Progress(
        SpinnerColumn(spinner_name="dots2", style="white"),
        TextColumn(f"[dim]{desc}[/dim]"),
        console=console, transient=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP SESSION
# ══════════════════════════════════════════════════════════════════════════════

SESSION = requests.Session()
SESSION.headers.update(HEADERS_HTTP)
SESSION.max_redirects = 10


def get(url, timeout=10, **kw):
    return SESSION.get(url, timeout=timeout, **kw)


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: USERNAME
# ══════════════════════════════════════════════════════════════════════════════

PLATFORMS = {
    "GitHub":         "https://github.com/{}",
    "GitLab":         "https://gitlab.com/{}",
    "Twitter/X":      "https://twitter.com/{}",
    "Instagram":      "https://www.instagram.com/{}/",
    "Reddit":         "https://www.reddit.com/user/{}/about.json",
    "TikTok":         "https://www.tiktok.com/@{}",
    "Pinterest":      "https://www.pinterest.com/{}/",
    "Twitch":         "https://www.twitch.tv/{}",
    "YouTube":        "https://www.youtube.com/@{}",
    "Medium":         "https://medium.com/@{}",
    "Dev.to":         "https://dev.to/{}",
    "Keybase":        "https://keybase.io/{}",
    "HackerNews":     "https://hacker-news.firebaseio.com/v0/user/{}.json",
    "Steam":          "https://steamcommunity.com/id/{}",
    "Pastebin":       "https://pastebin.com/u/{}",
    "Replit":         "https://replit.com/@{}",
    "ProductHunt":    "https://www.producthunt.com/@{}",
    "Fiverr":         "https://www.fiverr.com/{}",
    "Linktree":       "https://linktr.ee/{}",
    "Behance":        "https://www.behance.net/{}",
    "Dribbble":       "https://dribbble.com/{}",
    "SoundCloud":     "https://soundcloud.com/{}",
    "Last.fm":        "https://www.last.fm/user/{}",
    "Letterboxd":     "https://letterboxd.com/{}",
    "Goodreads":      "https://www.goodreads.com/{}",
    "Spotify":        "https://open.spotify.com/user/{}",
    "Codecademy":     "https://www.codecademy.com/profiles/{}",
    "Gravatar":       "https://en.gravatar.com/{}",
    "Flickr":         "https://www.flickr.com/people/{}",
    "500px":          "https://500px.com/p/{}",
    "Instructables":  "https://www.instructables.com/member/{}",
    "HuggingFace":    "https://huggingface.co/{}",
    "Kaggle":         "https://www.kaggle.com/{}",
    "npm":            "https://www.npmjs.com/~{}",
    "PyPI":           "https://pypi.org/user/{}",
    "DockerHub":      "https://hub.docker.com/u/{}",
    "Mastodon":       "https://mastodon.social/@{}",
    "Lobsters":       "https://lobste.rs/u/{}",
    "Vimeo":          "https://vimeo.com/{}",
}


def _probe(args):
    platform, url_t, username = args
    url = url_t.format(username)
    try:
        r = get(url, timeout=8, allow_redirects=True)
        found = r.status_code == 200
        return platform, url, found, r.status_code
    except Exception:
        return platform, url, False, 0


def cmd_username(username):
    section_header("username", "Username Hunt", username)
    log("username", username)

    tasks = [(p, t, username) for p, t in PLATFORMS.items()]
    hits, misses = [], []

    with bar_prog(f"scanning {len(tasks)} platforms", len(tasks)) as prog:
        task = prog.add_task("", total=len(tasks))
        with ThreadPoolExecutor(max_workers=15) as ex:
            futs = {ex.submit(_probe, t): t for t in tasks}
            for f in as_completed(futs):
                platform, url, found, code = f.result()
                (hits if found else misses).append((platform, url, code))
                prog.advance(task)

    blank()
    if hits:
        result_table(
            [("Platform", {"style":"bold white","width":16}),
             ("URL",      {"style":"cyan"}),
             ("HTTP",     {"style":"dim","width":6})],
            [(p, u, str(c)) for p, u, c in sorted(hits)],
        )
        ok(f"[white]{len(hits)}[/white] profiles found  ·  [dim]{len(misses)} not found[/dim]")
    else:
        warn("no profiles found across platforms")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: EMAIL
# ══════════════════════════════════════════════════════════════════════════════

def cmd_email(email):
    section_header("email", "Email Recon", email)
    log("email", email)

    if not re.match(r'^[\w\.\+\-]+@[\w\.-]+\.\w{2,}$', email):
        err("invalid email format"); return

    local, domain = email.split("@", 1)

    sub_header("Address Analysis")
    row("Full address",  email)
    row("Local part",    local)
    row("Domain",        domain)
    if "+" in local:
        row("Base alias",   local.split("+")[0])
        row("Tag/label",    local.split("+")[1], color=C["warn"])

    # ── MX / Provider ─────────────────────────────────────────────────────────
    sub_header("Mail Infrastructure")
    try:
        mx = sorted([(r.preference, str(r.exchange).rstrip("."))
                     for r in dns.resolver.resolve(domain, "MX")])
        for pref, host in mx[:5]:
            row(f"MX {pref}", host, C["info"])

        mx_str = " ".join(h for _, h in mx).lower()
        provider = (
            "Google Workspace / Gmail"    if "google" in mx_str or "gmail" in mx_str else
            "Microsoft 365 / Outlook"     if "protection.outlook" in mx_str else
            "ProtonMail"                  if "protonmail" in mx_str else
            "Fastmail"                    if "fastmail" in mx_str else
            "Zoho Mail"                   if "zoho" in mx_str else
            "Yahoo Mail"                  if "yahoodns" in mx_str else
            "Mimecast (enterprise)"       if "mimecast" in mx_str else
            "Barracuda"                   if "barracuda" in mx_str else
            "self-hosted / unknown"
        )
        row("Provider",     provider, C["warn"])
    except Exception as e:
        warn(f"MX lookup failed: {e}")

    # SPF
    try:
        for r in dns.resolver.resolve(domain, "TXT"):
            txt = r.to_text().strip('"')
            if txt.startswith("v=spf1"):
                row("SPF", txt[:90], good=True); break
    except:
        row("SPF", "not configured", good=False)

    # DMARC
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            txt = r.to_text().strip('"')
            if "DMARC1" in txt:
                pol = "reject" if "p=reject" in txt else "quarantine" if "p=quarantine" in txt else "none (monitor only)"
                row("DMARC policy", pol, good=(pol=="reject"))
                break
    except:
        row("DMARC", "not configured", good=False)

    # DKIM common selectors
    found_dkim = []
    for sel in ["default","google","mail","k1","selector1","selector2","smtp","dkim","mailjet","sendgrid","amazonses","mxvault"]:
        try:
            dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT", lifetime=2)
            found_dkim.append(sel)
        except: pass
    row("DKIM selectors", ", ".join(found_dkim) if found_dkim else "none found from common list",
        good=bool(found_dkim) or None)

    # BIMI
    try:
        dns.resolver.resolve(f"default._bimi.{domain}", "TXT", lifetime=2)
        row("BIMI", "present (brand logo record)", good=True)
    except:
        row("BIMI", "not configured", good=None)

    # ── Gravatar / linked profiles ─────────────────────────────────────────────
    sub_header("Linked Profiles")
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    try:
        r = get(f"https://www.gravatar.com/avatar/{email_hash}?d=404", timeout=5)
        if r.status_code == 200:
            row("Gravatar", f"https://www.gravatar.com/{email_hash}", good=True)
        else:
            row("Gravatar", "no avatar registered", good=None)
    except:
        warn("Gravatar unreachable")

    # Google account hint (public profile check)
    try:
        r = get(f"https://profiles.google.com/{local}", timeout=5, allow_redirects=True)
        if r.status_code == 200 and "google.com/maps/contrib" not in r.url:
            row("Google Profile", r.url, good=True)
    except: pass

    sub_header("Breach Exposure Links")
    enc = urllib.parse.quote(email)
    row("HIBP",            f"https://haveibeenpwned.com/account/{enc}", C["url"])
    row("DeHashed",        f"https://dehashed.com/search?query={enc}", C["url"])
    row("LeakCheck",       f"https://leakcheck.io/search?query={enc}", C["url"])
    row("BreachDirectory", f"https://breachdirectory.org/", C["url"])
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: DOMAIN
# ══════════════════════════════════════════════════════════════════════════════

SUBDOMAINS = [
    "www","mail","remote","blog","webmail","ns1","ns2","ns3","smtp","secure",
    "vpn","m","shop","ftp","api","dev","staging","test","admin","portal","app",
    "cdn","assets","static","git","gitlab","github","jira","confluence","jenkins",
    "mx","mx1","mx2","autodiscover","auth","login","sso","id","status","monitor",
    "grafana","kibana","elastic","db","mysql","redis","s3","files","media","images",
    "docs","support","help","forum","community","wiki","kb","intranet","internal",
    "vpn2","owa","exchange","cpanel","whm","plesk","direct","cloud","backup","old",
    "new","beta","alpha","sandbox","demo","uat","prod","production","management",
    "dashboard","analytics","metrics","log","logs","ops","infra","corp","office",
]


def _sub_check(args):
    sub, domain = args
    fqdn = f"{sub}.{domain}"
    try:
        socket.setdefaulttimeout(2)
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except: return None, None


def cmd_domain(domain):
    section_header("domain", "Domain Recon", domain)
    log("domain", domain)

    # ── WHOIS ──────────────────────────────────────────────────────────────────
    sub_header("WHOIS Registration")
    try:
        w = whois.whois(domain)
        created = w.creation_date
        expires = w.expiration_date
        updated = w.updated_date
        if isinstance(created, list): created = created[0]
        if isinstance(expires, list): expires = expires[0]
        if isinstance(updated, list): updated = updated[0]

        row("Registrar",       w.registrar or "unknown")
        row("Registered",      str(created).split(" ")[0] if created else "unknown")
        row("Expires",         str(expires).split(" ")[0] if expires else "unknown")
        row("Last updated",    str(updated).split(" ")[0] if updated else "unknown")

        if expires:
            days = (expires - datetime.now()).days if hasattr(expires,"year") else None
            if days is not None:
                row("Days until expiry", str(days),
                    good=(True if days>60 else "warn" if days>14 else False))

        if w.name_servers:
            ns = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
            row("Nameservers",  ", ".join(str(n).lower().rstrip(".") for n in sorted(set(ns))[:4]))
        if w.org:     row("Organisation",  w.org)
        if w.country: row("Country",       w.country)
        if w.status:
            st = w.status if isinstance(w.status, list) else [w.status]
            row("Status",       ", ".join(str(s).split(" ")[0] for s in st[:3]))
        emails = w.emails
        if emails:
            if isinstance(emails, str): emails = [emails]
            row("Registrant email", ", ".join(emails[:2]), C["warn"])
    except Exception as e:
        warn(f"WHOIS: {e}")

    # ── DNS Records ────────────────────────────────────────────────────────────
    sub_header("DNS Records")
    dns_colors = {"A":"white","AAAA":"cyan","MX":"yellow","NS":"dim white",
                  "TXT":"dim cyan","SOA":"dim","CAA":"yellow","CNAME":"cyan",
                  "DNSKEY":"red","SRV":"green","PTR":"dim white"}
    found_records = []
    for rtype in ["A","AAAA","CNAME","MX","NS","TXT","SOA","CAA","SRV","DNSKEY"]:
        try:
            for r in dns.resolver.resolve(domain, rtype, lifetime=5):
                val = r.to_text()
                found_records.append((rtype, val[:110]))
                row(rtype, val[:110], dns_colors.get(rtype,"cyan"))
        except: pass

    # ── SSL Certificate ────────────────────────────────────────────────────────
    sub_header("TLS / SSL Certificate")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((domain, 443), timeout=6),
                             server_hostname=domain) as s:
            cert = s.getpeercert()
        subj   = dict(x[0] for x in cert.get("subject",[]))
        issuer = dict(x[0] for x in cert.get("issuer",[]))
        not_before = cert.get("notBefore","")
        not_after  = cert.get("notAfter","")
        sans = [v for t, v in cert.get("subjectAltName",[]) if t=="DNS"]
        serial = cert.get("serialNumber","")

        row("Common Name",    subj.get("commonName","?"))
        row("Organisation",   subj.get("organizationName","—"))
        row("Issuer",         issuer.get("organizationName","?"))
        row("Issuer CN",      issuer.get("commonName","?"))
        row("Serial",         serial[:32] if serial else "?", C["dim"])
        row("Valid from",     not_before)
        row("Valid until",    not_after)
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.utcnow()).days
                row("Days remaining", str(days),
                    good=(True if days>30 else "warn" if days>7 else False))
            except: pass
        if sans:
            row("SANs", ", ".join(sans[:8]) + (f"  +{len(sans)-8} more" if len(sans)>8 else ""))

        # cert transparency link
        row("Cert transparency", f"https://crt.sh/?q={urllib.parse.quote(domain)}", C["url"])
    except Exception as e:
        warn(f"SSL: {e}")

    # ── HTTP Fingerprint ───────────────────────────────────────────────────────
    sub_header("HTTP Fingerprint")
    for scheme in ["https","http"]:
        try:
            r = get(f"{scheme}://{domain}", timeout=10, allow_redirects=True)
            row("Scheme",        scheme.upper())
            row("Status",        str(r.status_code),
                good=(True if r.status_code==200 else False))
            row("Final URL",     r.url)
            for h in ["Server","X-Powered-By","X-Generator","Via","X-Cache","CF-Ray"]:
                if r.headers.get(h):
                    row(h, r.headers[h], C["warn"])

            # cookies
            if r.cookies:
                cnames = [c.name for c in r.cookies]
                row("Cookies",   ", ".join(cnames[:6]), C["dim"])

            # CMS fingerprint
            body = r.text[:12000].lower()
            cms = []
            if "wp-content" in body or "wp-json" in body:                cms.append("WordPress")
            if "drupal" in body or "drupal" in r.headers.get("X-Generator","").lower(): cms.append("Drupal")
            if "joomla" in body:                                          cms.append("Joomla")
            if "__nuxt" in body:                                          cms.append("Nuxt.js")
            if "_next/static" in body:                                    cms.append("Next.js")
            if "gatsby" in body:                                          cms.append("Gatsby")
            if "shopify" in body:                                         cms.append("Shopify")
            if "wix.com" in body:                                         cms.append("Wix")
            if "squarespace" in body:                                     cms.append("Squarespace")
            if "webflow" in body:                                         cms.append("Webflow")
            if "ghost.io" in body or "ghost-sdk" in body:                cms.append("Ghost")
            if "laravel" in body:                                         cms.append("Laravel")
            if "django" in body:                                          cms.append("Django")
            if "react" in body and "createElement" in r.text[:12000]:    cms.append("React")
            if "angular" in body:                                         cms.append("Angular")
            if cms:
                row("CMS / Framework", ", ".join(cms), C["warn"])

            # Security headers audit
            sub_header("Security Headers")
            security_headers = [
                ("Strict-Transport-Security", "HSTS"),
                ("Content-Security-Policy",   "CSP"),
                ("X-Frame-Options",           "X-Frame-Options"),
                ("X-Content-Type-Options",    "X-Content-Type-Options"),
                ("Referrer-Policy",           "Referrer-Policy"),
                ("Permissions-Policy",        "Permissions-Policy"),
                ("Cross-Origin-Opener-Policy","COOP"),
                ("Cross-Origin-Resource-Policy","CORP"),
            ]
            score = 0
            for hdr, label in security_headers:
                val = r.headers.get(hdr)
                present = bool(val)
                score += 1 if present else 0
                row(label, val[:70] if val else "missing", good=(True if present else False))
            row("Security score", f"{score}/{len(security_headers)}",
                good=(True if score>=6 else "warn" if score>=3 else False))
            break
        except Exception as e:
            warn(f"HTTP ({scheme}): {e}")
            continue

    # ── Subdomains ─────────────────────────────────────────────────────────────
    sub_header(f"Subdomain Enumeration  ({len(SUBDOMAINS)} wordlist)")
    found_subs = []
    with bar_prog("enumerating subdomains", len(SUBDOMAINS)) as prog:
        task = prog.add_task("", total=len(SUBDOMAINS))
        with ThreadPoolExecutor(max_workers=25) as ex:
            futs = {ex.submit(_sub_check, (s, domain)): s for s in SUBDOMAINS}
            for f in as_completed(futs):
                fqdn, ip = f.result()
                if fqdn: found_subs.append((fqdn, ip))
                prog.advance(task)

    blank()
    if found_subs:
        result_table(
            [("Subdomain", {"style":"white","min_width":32}),
             ("Resolves to", {"style":"cyan"})],
            sorted(found_subs),
        )
        ok(f"[white]{len(found_subs)}[/white] subdomains resolved")
    else:
        warn("no subdomains resolved from wordlist")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: IP
# ══════════════════════════════════════════════════════════════════════════════

def cmd_ip(ip):
    section_header("ip", "IP Address Recon", ip)
    log("ip", ip)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        err("invalid IP address"); return

    if addr.is_private:   warn("RFC1918 private address — geo will not work")
    if addr.is_loopback:  warn("loopback address")
    if addr.is_multicast: warn("multicast address")

    row("Version",   f"IPv{addr.version}")
    row("Private",   str(addr.is_private))
    row("Type",      "IPv6" if addr.version==6 else "IPv4")

    # ── ip-api geolocation ─────────────────────────────────────────────────────
    sub_header("Geolocation")
    try:
        r = get(f"http://ip-api.com/json/{ip}?fields=status,message,country,"
                "countryCode,regionName,city,district,zip,lat,lon,timezone,offset,"
                "isp,org,as,asname,reverse,mobile,proxy,hosting", timeout=8)
        d = r.json()
        if d.get("status") == "success":
            flag_offset = 127397
            cc = d.get("countryCode","")
            flag = "".join(chr(flag_offset + ord(c)) for c in cc) if len(cc)==2 else ""
            row("Country",   f"{flag}  {d.get('country','?')} ({cc})")
            row("Region",    d.get("regionName","?"))
            row("City",      d.get("city","?"))
            if d.get("district"): row("District", d["district"])
            row("ZIP",       d.get("zip","?"))
            row("Latitude",  str(d.get("lat","")))
            row("Longitude", str(d.get("lon","")))
            row("Timezone",  f"{d.get('timezone','?')}  (UTC{d.get('offset',0)//3600:+d})")
            blank()
            row("ISP",       d.get("isp","?"))
            row("Org",       d.get("org","?"))
            row("ASN",       d.get("as","?"))
            row("AS name",   d.get("asname","?"))
            row("Reverse",   d.get("reverse","") or "none")
            blank()
            row("Mobile",    str(d.get("mobile",False)), good=(None))
            row("Proxy/VPN", str(d.get("proxy",False)),
                good=(False if d.get("proxy") else True))
            row("Hosting/DC",str(d.get("hosting",False)), good=(None))

            maps = f"https://maps.google.com/?q={d.get('lat')},{d.get('lon')}"
            row("Map link",  maps, C["url"])
        else:
            warn(d.get("message","lookup failed"))
    except Exception as e:
        err(f"ip-api: {e}")

    # ── Shodan InternetDB ──────────────────────────────────────────────────────
    sub_header("Shodan InternetDB")
    try:
        r = get(f"https://internetdb.shodan.io/{ip}", timeout=8)
        if r.status_code == 200:
            d = r.json()
            if d.get("ports"):
                row("Open ports",  ", ".join(str(p) for p in sorted(d["ports"])))
            if d.get("hostnames"):
                row("Hostnames",   ", ".join(d["hostnames"][:6]))
            if d.get("cpes"):
                row("CPEs",        ", ".join(d["cpes"][:4]), C["warn"])
            if d.get("tags"):
                row("Tags",        ", ".join(d["tags"]))
            if d.get("vulns"):
                row("Known CVEs",  ", ".join(d["vulns"][:8]), good=False)
            else:
                row("CVEs",        "none in database", good=True)
        elif r.status_code == 404:
            info("no data in Shodan InternetDB")
        else:
            warn(f"HTTP {r.status_code}")
    except Exception as e:
        warn(f"Shodan: {e}")

    # ── Reverse DNS / WHOIS ────────────────────────────────────────────────────
    sub_header("Reverse DNS")
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        row("PTR record",  hostname, good=True)
    except:
        row("PTR record",  "none", good=None)

    parts = ip.split(".")
    if len(parts)==4:
        arpa = ".".join(reversed(parts)) + ".in-addr.arpa"
        row("ARPA zone",   arpa, C["dim"])

    sub_header("Abuse / Reputation Links")
    row("AbuseIPDB",   f"https://www.abuseipdb.com/check/{ip}", C["url"])
    row("VirusTotal",  f"https://www.virustotal.com/gui/ip-address/{ip}", C["url"])
    row("Shodan",      f"https://www.shodan.io/host/{ip}", C["url"])
    row("Censys",      f"https://search.censys.io/hosts/{ip}", C["url"])
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: PHONE
# ══════════════════════════════════════════════════════════════════════════════

CC_MAP = {
    "1":"USA/Canada","7":"Russia","20":"Egypt","27":"South Africa","30":"Greece",
    "31":"Netherlands","32":"Belgium","33":"France","34":"Spain","36":"Hungary",
    "39":"Italy","40":"Romania","41":"Switzerland","43":"Austria","44":"UK",
    "45":"Denmark","46":"Sweden","47":"Norway","48":"Poland","49":"Germany",
    "51":"Peru","52":"Mexico","53":"Cuba","54":"Argentina","55":"Brazil",
    "56":"Chile","57":"Colombia","58":"Venezuela","60":"Malaysia","61":"Australia",
    "62":"Indonesia","63":"Philippines","64":"New Zealand","65":"Singapore",
    "66":"Thailand","81":"Japan","82":"South Korea","84":"Vietnam","86":"China",
    "90":"Turkey","91":"India","92":"Pakistan","94":"Sri Lanka","98":"Iran",
    "212":"Morocco","213":"Algeria","216":"Tunisia","218":"Libya",
    "221":"Senegal","234":"Nigeria","254":"Kenya","255":"Tanzania",
    "256":"Uganda","260":"Zambia","263":"Zimbabwe","351":"Portugal",
    "352":"Luxembourg","353":"Ireland","354":"Iceland","358":"Finland",
    "359":"Bulgaria","370":"Lithuania","371":"Latvia","372":"Estonia",
    "380":"Ukraine","381":"Serbia","385":"Croatia","386":"Slovenia",
    "420":"Czech Republic","421":"Slovakia",
    "966":"Saudi Arabia","971":"UAE","972":"Israel","964":"Iraq",
    "965":"Kuwait","961":"Lebanon","962":"Jordan","963":"Syria",
}

US_AREA_REGIONS = {
    "212":"New York, NY","213":"Los Angeles, CA","312":"Chicago, IL",
    "415":"San Francisco, CA","713":"Houston, TX","305":"Miami, FL",
    "404":"Atlanta, GA","206":"Seattle, WA","617":"Boston, MA",
    "202":"Washington DC","702":"Las Vegas, NV","602":"Phoenix, AZ",
    "503":"Portland, OR","512":"Austin, TX","303":"Denver, CO",
}


def cmd_phone(number):
    section_header("phone", "Phone Number Recon", number)
    log("phone", number)

    clean = re.sub(r'[\s\-\(\)\+\.\u00a0]', '', number)
    if not clean.isdigit():
        err("cannot parse — use digits, spaces, dashes, or +CC format"); return

    row("Normalized",   clean)
    row("Length",       str(len(clean)))

    # Country code match
    cc = None
    for length in [3, 2, 1]:
        prefix = clean[:length]
        if prefix in CC_MAP:
            cc = prefix; break

    sub_header("Number Analysis")
    if cc:
        row("Country code",  f"+{cc}", C["warn"])
        row("Country",       CC_MAP[cc])
        local = clean[len(cc):]
        row("Local number",  local)
        row("E.164 format",  f"+{clean}")

        # NANP (North America)
        if cc == "1" and len(local) == 10:
            area = local[:3]
            exchange = local[3:6]
            subscriber = local[6:]
            row("Format",       "NANP (North American)")
            row("Area code",    area)
            row("Exchange",     exchange)
            row("Subscriber",   subscriber)
            row("Formatted",    f"+1 ({area}) {exchange}-{subscriber}")
            if area in US_AREA_REGIONS:
                row("Area region",  US_AREA_REGIONS[area], C["warn"])
    else:
        warn("cannot match country code — provide in +CC format")

    sub_header("Search / Lookup Links")
    enc = urllib.parse.quote(f"+{clean}" if cc else clean)
    row("Truecaller",   f"https://www.truecaller.com/search/us/{clean}", C["url"])
    row("WhoCalld",     f"https://whocalld.com/+{clean}", C["url"])
    row("SpyDialer",    f"https://www.spydialer.com/default.aspx", C["url"])
    row("NumLookup",    f"https://www.numlookup.com/?number={enc}", C["url"])
    row("Google",       f"https://google.com/search?q=%22{enc}%22", C["url"])
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: URL SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def cmd_url(url):
    section_header("url", "URL Scanner", url)
    log("url", url)

    if not url.startswith(("http://","https://")):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    sub_header("URL Anatomy")
    row("Scheme",       parsed.scheme)
    row("Host",         parsed.netloc)
    row("Path",         parsed.path or "/")
    if parsed.query:
        for k, v in urllib.parse.parse_qsl(parsed.query):
            row(f"  param: {k}", v, C["warn"])
    if parsed.fragment:
        row("Fragment",  parsed.fragment, C["dim"])

    # redirect chain
    sub_header("Redirect Chain")
    try:
        r = get(url, timeout=12, allow_redirects=True)
        if r.history:
            for i, resp in enumerate(r.history):
                loc = resp.headers.get("Location","?")
                row(f"Hop {i+1}  [{resp.status_code}]", loc, C["warn"])
        row("Final status",  str(r.status_code), good=(r.status_code==200))
        row("Final URL",     r.url)
        row("Content-Type",  r.headers.get("Content-Type","?"))
        row("Size",          f"{len(r.content):,} bytes")
        row("Response time", f"{r.elapsed.total_seconds():.2f}s")

        m = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.I|re.S)
        if m: row("Page title", m.group(1).strip()[:90], C["warn"])

        # meta description
        m2 = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', r.text, re.I)
        if m2: row("Meta desc",  m2.group(1).strip()[:120], C["dim"])

        # outbound links count
        links = re.findall(r'href=["\']https?://([^/"\']+)', r.text)
        external = set(l for l in links if parsed.netloc not in l)
        row("External links", str(len(external)))

        sub_header("Content Signals")
        signals = {
            "iframes present":         "<iframe" in r.text.lower(),
            "eval() calls":            "eval(" in r.text,
            "document.write()":        "document.write(" in r.text,
            "base64 blobs":            re.search(r'base64,[A-Za-z0-9+/]{100}', r.text) is not None,
            ".onion links":            ".onion" in r.text,
            "crypto wallet patterns":  bool(re.search(r'(bitcoin|ethereum|wallet)', r.text, re.I)),
            "login/password fields":   bool(re.search(r'type=["\']password', r.text, re.I)),
            "form actions":            bool(re.search(r'<form[^>]+action', r.text, re.I)),
            "obfuscated JS":           bool(re.search(r'\\x[0-9a-f]{2}', r.text)),
            "websocket usage":         "WebSocket" in r.text,
        }
        for signal, detected in signals.items():
            row(signal, "detected" if detected else "not found",
                good=(False if detected and signal not in ("form actions","websocket usage","login/password fields") else None))

        sub_header("Security Headers")
        for h in ["Strict-Transport-Security","Content-Security-Policy",
                   "X-Frame-Options","X-Content-Type-Options","Referrer-Policy"]:
            v = r.headers.get(h)
            row(h, v[:60] if v else "missing", good=bool(v))

    except Exception as e:
        err(f"request failed: {e}")

    sub_header("External Analysis")
    enc = urllib.parse.quote(url, safe="")
    row("VirusTotal",  f"https://www.virustotal.com/gui/url/{enc}", C["url"])
    row("URLScan.io",  f"https://urlscan.io/search/#page.url:\"{urllib.parse.quote(url)}\"", C["url"])
    row("Web Archive", f"https://web.archive.org/web/*/{url}", C["url"])
    row("Google Cache",f"https://webcache.googleusercontent.com/search?q=cache:{url}", C["url"])
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: PORT SCAN
# ══════════════════════════════════════════════════════════════════════════════

PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
    465:"SMTPS",587:"SMTP-submission",993:"IMAPS",995:"POP3S",
    1433:"MSSQL",1521:"Oracle",2375:"Docker",2376:"Docker-TLS",
    3306:"MySQL",3389:"RDP",4444:"Metasploit/RAT",5432:"PostgreSQL",
    5900:"VNC",6379:"Redis",6443:"Kubernetes-API",8080:"HTTP-alt",
    8443:"HTTPS-alt",8888:"Jupyter",9000:"PHP-FPM/Portainer",
    9090:"Cockpit/Prometheus",9200:"Elasticsearch",9300:"Elasticsearch-cluster",
    11211:"Memcached",27017:"MongoDB",27018:"MongoDB-alt",50000:"SAP",
}

RISKY = {4444,6379,27017,9200,11211,5900,23,2375,50000}


def _port_scan(args):
    host, port, timeout = args
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        open_ = s.connect_ex((host, port)) == 0
        s.close()
        return port, open_
    except: return port, False


def _banner_grab(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        s.send(b"\r\n")
        data = s.recv(256)
        s.close()
        return data.decode("utf-8","ignore").strip()[:80]
    except: return ""


def cmd_ports(host, custom_ports=None, timeout=1.0):
    section_header("ports", "Port Scanner", host)
    log("ports", host)

    try:
        ip = socket.gethostbyname(host)
        if ip != host: row("Resolved",  ip)
    except Exception as e:
        err(f"cannot resolve: {e}"); return

    ports_to_scan = custom_ports if custom_ports else list(PORTS.keys())
    open_ports = []

    with bar_prog(f"scanning {len(ports_to_scan)} ports", len(ports_to_scan)) as prog:
        task = prog.add_task("", total=len(ports_to_scan))
        with ThreadPoolExecutor(max_workers=60) as ex:
            futs = {ex.submit(_port_scan, (ip, p, timeout)): p for p in ports_to_scan}
            for f in as_completed(futs):
                port, is_open = f.result()
                if is_open: open_ports.append(port)
                prog.advance(task)

    blank()
    if open_ports:
        rows = []
        for port in sorted(open_ports):
            svc   = PORTS.get(port,"unknown")
            risky = " ⚠ HIGH RISK" if port in RISKY else ""
            banner = _banner_grab(ip, port)
            rows.append((
                str(port),
                svc + risky,
                banner if banner else "—",
                "[red]●[/red]" if port in RISKY else "[green]●[/green]",
            ))
        result_table(
            [("Port",    {"style":"white","width":7}),
             ("Service", {"style":"cyan","width":24}),
             ("Banner",  {"style":"dim","min_width":30}),
             ("",        {"width":3})],
            rows,
        )
        ok(f"[white]{len(open_ports)}[/white] open  ·  [dim]{len(ports_to_scan)-len(open_ports)} closed/filtered[/dim]")
        if any(p in RISKY for p in open_ports):
            warn("high-risk services detected on this host")
    else:
        warn("no open ports found in scanned range")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: DNS DEEP DIVE
# ══════════════════════════════════════════════════════════════════════════════

def cmd_dns(domain):
    section_header("dns", "DNS Deep Dive", domain)
    log("dns", domain)

    dns_colors = {"A":"white","AAAA":"cyan","MX":"yellow","NS":"dim white",
                  "TXT":"dim cyan","SOA":"dim","CAA":"yellow","CNAME":"cyan",
                  "DNSKEY":"red","SRV":"green","NAPTR":"dim white","PTR":"dim"}

    for rtype in ["A","AAAA","CNAME","MX","NS","SOA","TXT","CAA","SRV","NAPTR","DNSKEY","DS"]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=6)
            for r in answers:
                row(rtype, r.to_text()[:120], dns_colors.get(rtype,"cyan"))
        except dns.resolver.NoAnswer:    pass
        except dns.resolver.NXDOMAIN:
            err("domain does not exist (NXDOMAIN)"); return
        except Exception:                pass

    # resolver comparison
    sub_header("Resolver Comparison")
    resolvers = {
        "Google (8.8.8.8)":     "8.8.8.8",
        "Cloudflare (1.1.1.1)": "1.1.1.1",
        "OpenDNS (208.67.222)": "208.67.222.222",
        "Quad9 (9.9.9.9)":      "9.9.9.9",
    }
    for name, ns_ip in resolvers.items():
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [ns_ip]
            r.lifetime = 4
            ans = r.resolve(domain, "A")
            ips = ", ".join(str(a) for a in ans)
            row(name, ips)
        except Exception as e:
            row(name, f"failed: {e}", C["dim"])

    # zone transfer
    sub_header("Zone Transfer Attempt (AXFR)")
    try:
        ns_answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        for ns_rr in ns_answers:
            ns = str(ns_rr.target).rstrip(".")
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                warn(f"ZONE TRANSFER SUCCEEDED on {ns}")
                for name in list(z.nodes.keys())[:20]:
                    console.print(f"    [red]{name}.{domain}[/red]")
            except Exception:
                row(ns, "transfer refused (good)", good=True)
    except Exception as e:
        warn(f"NS lookup failed: {e}")

    # DNSSEC validation
    sub_header("DNSSEC")
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=5)
        row("DNSKEY", "present", good=True)
    except dns.resolver.NoAnswer:
        row("DNSKEY", "not configured", good=False)
    except Exception:
        row("DNSKEY", "could not check", good=None)

    try:
        dns.resolver.resolve(domain, "DS", lifetime=5)
        row("DS record", "present (chain of trust)", good=True)
    except Exception:
        row("DS record", "not found", good=None)

    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: SSL DEEP INSPECT
# ══════════════════════════════════════════════════════════════════════════════

def cmd_ssl(host, port=443):
    section_header("ssl", "SSL/TLS Inspector", f"{host}:{port}")
    log("ssl", f"{host}:{port}")

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=8),
                             server_hostname=host) as s:
            cert   = s.getpeercert()
            cipher = s.cipher()
            proto  = s.version()

        sub_header("Protocol & Cipher")
        row("TLS version",  proto,
            good=(True if proto in ("TLSv1.3","TLSv1.2") else False))
        row("Cipher suite", cipher[0] if cipher else "?")
        row("Key bits",     str(cipher[2]) if cipher else "?",
            good=(True if cipher and cipher[2]>=256 else None))

        sub_header("Certificate")
        subj   = dict(x[0] for x in cert.get("subject",[]))
        issuer = dict(x[0] for x in cert.get("issuer",[]))
        sans   = [v for t,v in cert.get("subjectAltName",[]) if t=="DNS"]
        serial = cert.get("serialNumber","")
        not_after = cert.get("notAfter","")

        row("CN",           subj.get("commonName","?"))
        row("Org",          subj.get("organizationName","—"))
        row("Country",      subj.get("countryName","—"))
        row("Issuer",       issuer.get("organizationName","?"))
        row("Issuer CN",    issuer.get("commonName","?"))
        row("Serial",       serial, C["dim"])
        row("Not before",   cert.get("notBefore","?"))
        row("Not after",    not_after)

        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.utcnow()).days
                row("Days remaining", str(days),
                    good=(True if days>60 else "warn" if days>14 else False))
            except: pass

        row("SANs", ", ".join(sans[:10]) + (f"  +{len(sans)-10} more" if len(sans)>10 else ""))

        # wildcard?
        for san in sans:
            if san.startswith("*."):
                row("Wildcard", san, good=None); break

        # self-signed?
        if subj == issuer:
            row("Self-signed", "YES", good=False)
        else:
            row("Self-signed", "no", good=True)

        sub_header("Weak Protocol Check")
        for bad_proto, bad_port in [("SSLv3",443),("TLSv1.0",443),("TLSv1.1",443)]:
            try:
                bad_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                bad_ctx.check_hostname = False
                bad_ctx.verify_mode = ssl.CERT_NONE
                if hasattr(ssl,"OP_NO_TLSv1_3"):
                    bad_ctx.options |= ssl.OP_NO_TLSv1_3
                with bad_ctx.wrap_socket(socket.create_connection((host, port), timeout=4),
                                         server_hostname=host):
                    row(bad_proto, "ACCEPTED (downgrade risk)", good=False)
            except:
                row(bad_proto, "rejected", good=True)

        sub_header("External Links")
        row("crt.sh",      f"https://crt.sh/?q={urllib.parse.quote(host)}", C["url"])
        row("SSL Labs",    f"https://www.ssllabs.com/ssltest/analyze.html?d={host}", C["url"])
        row("Observatory", f"https://observatory.mozilla.org/analyze/{host}", C["url"])

    except Exception as e:
        err(f"SSL inspection failed: {e}")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: WHOIS DEEP
# ══════════════════════════════════════════════════════════════════════════════

def cmd_whois(target):
    section_header("whois", "WHOIS Lookup", target)
    log("whois", target)
    try:
        w = whois.whois(target)
        for key in ["domain_name","registrar","whois_server","referral_url",
                     "updated_date","creation_date","expiration_date",
                     "name_servers","status","emails","dnssec","name",
                     "org","address","city","state","zipcode","country"]:
            val = getattr(w, key, None)
            if val is None: continue
            if isinstance(val, list):
                val = val[0] if len(val)==1 else str(val[:3])[1:-1]
            row(key.replace("_"," ").title(), str(val)[:100], C["info"])
    except Exception as e:
        err(f"WHOIS failed: {e}")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: ASN LOOKUP
# ══════════════════════════════════════════════════════════════════════════════

def cmd_asn(asn_or_ip):
    section_header("asn", "ASN Lookup", asn_or_ip)
    log("asn", asn_or_ip)

    target = asn_or_ip.upper().replace("AS","")
    try:
        # BGPView API (free, no key)
        if target.isdigit():
            url = f"https://api.bgpview.io/asn/{target}"
        else:
            # try as IP prefix
            url = f"https://api.bgpview.io/ip/{asn_or_ip}"

        r = get(url, timeout=10)
        d = r.json()
        if d.get("status") == "ok":
            data = d.get("data",{})
            if "asn" in data:
                row("ASN",         str(data["asn"]))
                row("Name",        data.get("name","?"))
                row("Description", data.get("description_short","?"))
                row("Country",     data.get("country_code","?"))
                row("Website",     data.get("website","?"), C["url"])
                email_contacts = data.get("email_contacts",[])
                if email_contacts:
                    row("Email",   ", ".join(email_contacts[:3]))

            # prefixes
            purl = f"https://api.bgpview.io/asn/{target}/prefixes"
            pr = get(purl, timeout=8).json()
            if pr.get("status")=="ok":
                v4 = pr["data"].get("ipv4_prefixes",[])
                v6 = pr["data"].get("ipv6_prefixes",[])
                sub_header("IPv4 Prefixes")
                for pref in v4[:10]:
                    row(pref.get("prefix",""), pref.get("description",""))
                if len(v4)>10: info(f"... and {len(v4)-10} more")
                if v6:
                    sub_header("IPv6 Prefixes")
                    for pref in v6[:5]:
                        row(pref.get("prefix",""), pref.get("description",""))
        else:
            warn("no data returned")
    except Exception as e:
        err(f"ASN lookup failed: {e}")

    row("BGPView",  f"https://bgpview.io/asn/{target}", C["url"])
    row("HurricaneE",f"https://bgp.he.net/AS{target}", C["url"])
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: GEO (IP → Map)
# ══════════════════════════════════════════════════════════════════════════════

def cmd_geo(target):
    section_header("geo", "Geolocation", target)
    log("geo", target)

    # resolve to IP first
    ip = target
    try:
        resolved = socket.gethostbyname(target)
        if resolved != target:
            row("Resolved",  resolved)
        ip = resolved
    except: pass

    try:
        r = get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
                "regionName,city,zip,lat,lon,timezone,isp,org,as", timeout=8)
        d = r.json()
        if d.get("status")=="success":
            row("IP",        ip)
            row("Country",   f"{d.get('country')} ({d.get('countryCode')})")
            row("Region",    d.get("regionName","?"))
            row("City",      d.get("city","?"))
            row("ZIP",       d.get("zip","?"))
            row("Lat/Lon",   f"{d.get('lat')}, {d.get('lon')}")
            row("Timezone",  d.get("timezone","?"))
            row("ISP",       d.get("isp","?"))
            lat, lon = d.get("lat"), d.get("lon")
            row("Google Maps", f"https://maps.google.com/?q={lat},{lon}", C["url"])
            row("OpenStreetMap",f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=12", C["url"])
        else:
            warn("geo lookup failed")
    except Exception as e:
        err(f"geo: {e}")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: TECH STACK
# ══════════════════════════════════════════════════════════════════════════════

def cmd_tech(target):
    section_header("tech", "Technology Stack", target)
    log("tech", target)

    if not target.startswith(("http://","https://")):
        target = "https://" + target

    try:
        r = get(target, timeout=12, allow_redirects=True)
        body  = r.text[:20000]
        lower = body.lower()

        sub_header("Web Server")
        for h in ["Server","X-Powered-By","X-Generator","X-AspNet-Version",
                   "X-AspNetMvc-Version","X-Drupal-Cache","X-Varnish",
                   "Via","CF-Ray","X-Cache","X-Served-By","X-Backend"]:
            if r.headers.get(h):
                row(h, r.headers[h], C["warn"])

        sub_header("Frontend Frameworks")
        fe_checks = [
            ("React",        "react" in lower and ("createelement" in lower or "__reactfiber" in lower)),
            ("Vue.js",       "__vue__" in lower or "vue.min.js" in lower),
            ("Angular",      "ng-version" in lower or "angular.min.js" in lower),
            ("Next.js",      "_next/static" in lower),
            ("Nuxt.js",      "__nuxt" in lower),
            ("Gatsby",       "gatsby" in lower),
            ("Svelte",       "svelte" in lower),
            ("Ember.js",     "ember" in lower),
            ("Backbone.js",  "backbone" in lower),
            ("jQuery",       "jquery" in lower),
            ("Bootstrap",    "bootstrap" in lower),
            ("Tailwind",     "tailwind" in lower or "tw-" in lower),
        ]
        for name, found in fe_checks:
            if found: row(name, "detected", good=True)

        sub_header("Backend / CMS")
        be_checks = [
            ("WordPress",    "wp-content" in lower or "wp-json" in lower),
            ("Drupal",       "drupal" in lower or "drupal" in r.headers.get("X-Generator","").lower()),
            ("Joomla",       "joomla" in lower),
            ("Ghost",        "ghost-sdk" in lower or "ghost.io" in lower),
            ("Shopify",      "shopify" in lower or "cdn.shopify.com" in lower),
            ("WooCommerce",  "woocommerce" in lower),
            ("Magento",      "magento" in lower or "mage" in lower),
            ("PrestaShop",   "prestashop" in lower),
            ("Wix",          "wix.com" in lower),
            ("Squarespace",  "squarespace" in lower),
            ("Webflow",      "webflow" in lower),
            ("Laravel",      "laravel" in lower or "laravel_session" in str(r.cookies)),
            ("Django",       "csrfmiddlewaretoken" in lower),
            ("Ruby on Rails","x-runtime" in r.headers and "rack" in lower),
            ("ASP.NET",      "aspnet" in lower or "__viewstate" in lower),
        ]
        for name, found in be_checks:
            if found: row(name, "detected", good=True)

        sub_header("CDN / Infrastructure")
        cdn_checks = [
            ("Cloudflare",   "cf-ray" in r.headers or "cloudflare" in r.headers.get("Server","").lower()),
            ("AWS CloudFront","cloudfront" in r.headers.get("Via","").lower() or "amazon" in r.headers.get("Server","").lower()),
            ("Fastly",       "fastly" in r.headers.get("Via","").lower() or "x-served-by" in r.headers),
            ("Akamai",       "akamai" in r.headers.get("X-Check-Cacheable","").lower()),
            ("Varnish",      "x-varnish" in r.headers),
            ("Nginx",        "nginx" in r.headers.get("Server","").lower()),
            ("Apache",       "apache" in r.headers.get("Server","").lower()),
            ("Vercel",       "x-vercel-id" in r.headers),
            ("Netlify",      "x-nf-request-id" in r.headers),
        ]
        for name, found in cdn_checks:
            if found: row(name, "detected", good=True)

        sub_header("Analytics / Tracking")
        analytics = {
            "Google Analytics":   "google-analytics.com" in lower or "gtag" in lower,
            "Google Tag Manager": "googletagmanager" in lower,
            "Facebook Pixel":     "connect.facebook.net" in lower,
            "Hotjar":             "hotjar" in lower,
            "Mixpanel":           "mixpanel" in lower,
            "Segment":            "segment.io" in lower or "segment.com" in lower,
            "Heap":               "heap" in lower and "heapanalytics" in lower,
            "Intercom":           "intercom" in lower,
            "Hubspot":            "hubspot" in lower,
            "Crisp":              "crisp.chat" in lower,
        }
        found_analytics = [k for k, v in analytics.items() if v]
        if found_analytics:
            for a in found_analytics:
                row(a, "detected", C["warn"])
        else:
            info("no common analytics detected")

    except Exception as e:
        err(f"tech scan failed: {e}")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: CERT TRANSPARENCY
# ══════════════════════════════════════════════════════════════════════════════

def cmd_cert(domain):
    section_header("cert", "Certificate Transparency", domain)
    log("cert", domain)

    try:
        r = get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        certs = r.json()

        seen = set()
        unique = []
        for c in certs:
            name = c.get("name_value","").strip()
            for line in name.split("\n"):
                line = line.strip().lower()
                if line and line not in seen:
                    seen.add(line)
                    unique.append({
                        "name":   line,
                        "issuer": c.get("issuer_name","?")[:40],
                        "date":   str(c.get("not_before","?"))[:10],
                        "id":     c.get("id",""),
                    })

        # sort by date descending
        unique.sort(key=lambda x: x["date"], reverse=True)

        console.print()
        result_table(
            [("Name/SAN",  {"style":"white","min_width":36}),
             ("Issued",    {"style":"dim","width":12}),
             ("Issuer",    {"style":"dim cyan","min_width":20})],
            [(c["name"], c["date"], c["issuer"][:40]) for c in unique[:40]],
        )
        ok(f"[white]{len(unique)}[/white] unique names found across [white]{len(certs)}[/white] certificates")
        if len(unique) > 40:
            info(f"showing first 40 — full list at https://crt.sh/?q=%.{domain}")
    except Exception as e:
        err(f"crt.sh query failed: {e}")

    row("crt.sh",      f"https://crt.sh/?q=%.{domain}", C["url"])
    row("Cert Spotter",f"https://sslmate.com/certspotter/api/v1/issuances?domain={domain}", C["url"])
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: HEADER AUDIT
# ══════════════════════════════════════════════════════════════════════════════

def cmd_headers(target):
    section_header("headers", "HTTP Header Audit", target)
    log("headers", target)

    if not target.startswith(("http://","https://")):
        target = "https://" + target
    try:
        r = get(target, timeout=10, allow_redirects=True)

        sub_header("All Response Headers")
        for k, v in sorted(r.headers.items()):
            row(k, v[:100], C["dim"])

        sub_header("Security Header Audit")
        checks = [
            ("Strict-Transport-Security", True,  "HSTS missing — HTTP downgrade possible"),
            ("Content-Security-Policy",   True,  "CSP missing — XSS risk"),
            ("X-Frame-Options",           True,  "clickjacking protection missing"),
            ("X-Content-Type-Options",    True,  "MIME sniffing protection missing"),
            ("Referrer-Policy",           True,  "referrer info may leak"),
            ("Permissions-Policy",        True,  "no feature restrictions set"),
            ("Cross-Origin-Opener-Policy",True,  "COOP not set"),
            ("Cross-Origin-Resource-Policy",True,"CORP not set"),
        ]
        score = 0
        for header, required, note in checks:
            val = r.headers.get(header)
            if val:
                row(header, val[:70], good=True)
                score += 1
            else:
                row(header, f"MISSING — {note}", good=False)

        blank()
        grade = "A" if score>=7 else "B" if score>=5 else "C" if score>=3 else "F"
        grade_color = "green" if grade=="A" else "yellow" if grade in ("B","C") else "red"
        console.print(f"   Security grade: [{grade_color}]  {grade}  ({score}/8)[/{grade_color}]")

        sub_header("Info-Disclosure Headers")
        risky_headers = ["Server","X-Powered-By","X-Generator","X-AspNet-Version",
                         "X-AspNetMvc-Version","X-Backend","X-App-Name"]
        for h in risky_headers:
            val = r.headers.get(h)
            if val:
                row(h, val, good=False)

    except Exception as e:
        err(f"request failed: {e}")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: BREACH CHECK
# ══════════════════════════════════════════════════════════════════════════════

def cmd_breach(query):
    section_header("breach", "Breach Exposure Check", query)
    log("breach", query)

    warn("full breach data requires paid API key — showing public lookup links")
    blank()

    enc = urllib.parse.quote(query)
    sub_header("Lookup Links")
    row("HIBP",             f"https://haveibeenpwned.com/account/{enc}", C["url"])
    row("DeHashed",         f"https://dehashed.com/search?query={enc}", C["url"])
    row("LeakCheck",        f"https://leakcheck.io/search?query={enc}", C["url"])
    row("BreachDirectory",  f"https://breachdirectory.org/", C["url"])
    row("Snusbase",         f"https://snusbase.com/", C["url"])
    row("IntelX",           f"https://intelx.io/?s={enc}", C["url"])

    # k-anonymity password check hint
    sub_header("Password Hash Check (k-Anonymity)")
    info("to check if a password appears in breaches without sending the plaintext:")
    info("  1. SHA1-hash your password")
    info("  2. send first 5 chars to: https://api.pwnedpasswords.com/range/{first5}")
    info("  3. check if the remainder appears in the response")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE: REPORT EXPORT
# ══════════════════════════════════════════════════════════════════════════════

def cmd_export(filename=None):
    if not LOG:
        warn("nothing logged yet"); return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = filename or f"ghost_report_{ts}.txt"
    with open(fname, "w", encoding="utf-8") as f:
        f.write(f"ghost OSINT Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 66 + "\n\n")
        for ts_, module, line in LOG:
            f.write(f"[{ts_}] [{module:>12}]  {line}\n")
        f.write("\n" + "=" * 66 + "\n")
    ok(f"exported → [cyan]{fname}[/cyan]  ({len(LOG)} entries)")


# ══════════════════════════════════════════════════════════════════════════════
#  AUTO-DETECT
# ══════════════════════════════════════════════════════════════════════════════

def auto_detect(target):
    target = target.strip()
    try:
        ipaddress.ip_address(target)
        cmd_ip(target); return
    except ValueError: pass

    if re.match(r'^[\w\.\+\-]+@[\w\.-]+\.\w{2,}$', target):
        cmd_email(target)
        cmd_domain(target.split("@")[1]); return

    if re.match(r'^AS\d+$', target, re.I):
        cmd_asn(target); return

    if re.match(r'^https?://', target):
        cmd_url(target); return

    if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', target) and "." in target:
        cmd_domain(target); return

    if re.match(r'^\+?\d[\d\s\-\(\)]{6,}$', target):
        cmd_phone(target); return

    cmd_username(target)


# ══════════════════════════════════════════════════════════════════════════════
#  HELP
# ══════════════════════════════════════════════════════════════════════════════

HELP = """
[bold white]Core Recon[/bold white]
  [white]username[/white]  <name>           hunt profile across 38 platforms
  [white]email[/white]     <addr>           MX, SPF, DMARC, DKIM, BIMI, Gravatar
  [white]domain[/white]    <domain>         WHOIS, DNS, SSL, HTTP, subdomains, CMS
  [white]ip[/white]        <address>        geo, ASN, Shodan, PTR, reputation
  [white]phone[/white]     <number>         country, carrier, lookup links

[bold white]Web & Network[/bold white]
  [white]url[/white]       <url>            redirect chain, signals, content analysis
  [white]ports[/white]     <host> [ports]   threaded port scan + banner grab
  [white]headers[/white]   <url>            full header audit + security grade
  [white]tech[/white]      <domain>         framework, CDN, analytics fingerprint
  [white]ssl[/white]       <host> [port]    TLS version, cipher, cert, weak proto check

[bold white]DNS & Infrastructure[/bold white]
  [white]dns[/white]       <domain>         all record types, resolver compare, AXFR, DNSSEC
  [white]whois[/white]     <domain/ip>      detailed WHOIS output
  [white]asn[/white]       <ASN or IP>      BGP info, prefixes, org
  [white]cert[/white]      <domain>         certificate transparency (crt.sh)
  [white]geo[/white]       <ip/domain>      geolocation + map links

[bold white]Investigation[/bold white]
  [white]breach[/white]    <email>          breach exposure links
  [white]scan[/white]      <target>         auto-detect and run all relevant modules

[bold white]Session[/bold white]
  [white]export[/white]    [filename]       save session log to file
  [white]history[/white]                    show command history
  [white]clear[/white]                      clear screen
  [white]help[/white]                       this screen
  [white]exit[/white]                       quit

[dim]tip: just type any target — ghost auto-detects it.[/dim]
"""


# ══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE SHELL
# ══════════════════════════════════════════════════════════════════════════════

def run_shell():
    print_banner()

    while True:
        try:
            console.print()
            raw = console.input(
                "[dim]┌[/dim] [bold white]ghost[/bold white][dim]@recon[/dim]"
                " [dim]▶[/dim] "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]session ended.[/dim]")
            break

        if not raw: continue
        HISTORY.append(raw)

        parts = raw.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        if cmd in ("exit","quit","q"):
            console.print("[dim]session ended.[/dim]"); break

        elif cmd == "help":
            console.print(HELP)

        elif cmd == "clear":
            os.system("cls" if os.name == "nt" else "clear")
            print_banner()

        elif cmd == "history":
            sub_header("Command History")
            for i, h in enumerate(HISTORY[:-1], 1):
                console.print(f"  [dim]{i:>3}[/dim]  {h}")
            blank()

        elif cmd == "export":
            cmd_export(args[0] if args else None)

        elif cmd == "username" and args:
            cmd_username(args[0])

        elif cmd == "email" and args:
            cmd_email(args[0])

        elif cmd == "domain" and args:
            cmd_domain(args[0])

        elif cmd == "ip" and args:
            cmd_ip(args[0])

        elif cmd == "phone" and args:
            cmd_phone(" ".join(args))

        elif cmd == "url" and args:
            cmd_url(args[0])

        elif cmd == "ports" and args:
            host = args[0]
            if len(args) > 1:
                try:
                    p_list = [int(p) for p in args[1].split(",")]
                    cmd_ports(host, p_list)
                except ValueError:
                    err("ports: comma-separated integers")
            else:
                cmd_ports(host)

        elif cmd == "dns" and args:
            cmd_dns(args[0])

        elif cmd == "ssl" and args:
            port = int(args[1]) if len(args)>1 else 443
            cmd_ssl(args[0], port)

        elif cmd == "whois" and args:
            cmd_whois(args[0])

        elif cmd == "asn" and args:
            cmd_asn(args[0])

        elif cmd == "cert" and args:
            cmd_cert(args[0])

        elif cmd == "geo" and args:
            cmd_geo(args[0])

        elif cmd == "tech" and args:
            cmd_tech(args[0])

        elif cmd == "headers" and args:
            cmd_headers(args[0])

        elif cmd == "breach" and args:
            cmd_breach(args[0])

        elif cmd == "scan" and args:
            auto_detect(" ".join(args))

        else:
            # bare target — auto-detect
            if cmd not in ("help","clear","export","exit","quit","history"):
                auto_detect(raw)
            else:
                warn(f"unknown command or missing argument — type [white]help[/white]")


# ══════════════════════════════════════════════════════════════════════════════
#  CLI ENTRY
# ══════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description="ghost v3 — OSINT recon framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="no args → interactive shell"
    )
    p.add_argument("target",          nargs="?",          help="auto-detect target")
    p.add_argument("-u","--username", metavar="NAME")
    p.add_argument("-e","--email",    metavar="EMAIL")
    p.add_argument("-d","--domain",   metavar="DOMAIN")
    p.add_argument("-i","--ip",       metavar="IP")
    p.add_argument(     "--phone",    metavar="PHONE")
    p.add_argument(     "--url",      metavar="URL")
    p.add_argument(     "--ports",    metavar="HOST")
    p.add_argument(     "--dns",      metavar="DOMAIN")
    p.add_argument(     "--ssl",      metavar="HOST")
    p.add_argument(     "--whois",    metavar="TARGET")
    p.add_argument(     "--asn",      metavar="ASN")
    p.add_argument(     "--cert",     metavar="DOMAIN")
    p.add_argument(     "--geo",      metavar="TARGET")
    p.add_argument(     "--tech",     metavar="DOMAIN")
    p.add_argument(     "--headers",  metavar="URL")
    p.add_argument(     "--breach",   metavar="EMAIL")
    p.add_argument("-o","--output",   metavar="FILE",     help="export session log")
    args = p.parse_args()

    ran = any([args.username, args.email, args.domain, args.ip,
               args.phone, args.url, args.ports, args.dns, args.ssl,
               args.whois, args.asn, args.cert, args.geo, args.tech,
               args.headers, args.breach, args.target])

    if not ran:
        run_shell(); return

    print_banner()
    if args.username: cmd_username(args.username)
    if args.email:    cmd_email(args.email)
    if args.domain:   cmd_domain(args.domain)
    if args.ip:       cmd_ip(args.ip)
    if args.phone:    cmd_phone(args.phone)
    if args.url:      cmd_url(args.url)
    if args.ports:    cmd_ports(args.ports)
    if args.dns:      cmd_dns(args.dns)
    if args.ssl:      cmd_ssl(args.ssl)
    if args.whois:    cmd_whois(args.whois)
    if args.asn:      cmd_asn(args.asn)
    if args.cert:     cmd_cert(args.cert)
    if args.geo:      cmd_geo(args.geo)
    if args.tech:     cmd_tech(args.tech)
    if args.headers:  cmd_headers(args.headers)
    if args.breach:   cmd_breach(args.breach)
    if args.target:   auto_detect(args.target)
    if args.output:   cmd_export(args.output)

    divider()
    console.print(f"[dim]done · {datetime.now().strftime('%H:%M:%S')}[/dim]\n")


if __name__ == "__main__":
    main()
