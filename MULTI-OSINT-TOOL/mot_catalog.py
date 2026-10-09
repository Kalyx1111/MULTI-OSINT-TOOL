"""MULTI-OSINT-TOOL :: tool catalogue.

Every source the program knows about is listed here, whether or not it runs automatically. For each
one the catalogue says what it is used for, which search types it covers, how it is reached, and how
far its facts were verified. A search can then show which sources were chosen, which were skipped
and why, and what each source contributed.

Verification levels (field "check"):
  docs    the vendor documentation was read during development (see the connector's docs_url)
  code    the behaviour is taken from this program's connector code; vendor docs not re-read
  search  only that a public page was found in a search; the page itself was not read
  none    not checked; the entry must not be relied on until researched

Status for entries without a connector:
  handoff   a website only; the program can open it for you and never sends it the target
  manual    deliberately not automated (the reason is in the note)
  research  not verified enough to use; nothing is sent to it
Entries with a connector take their status from the connector kind (api, cli, local -> automated;
handoff -> handoff; export -> export).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Search types the program understands (internal names; the labels are what people see).
TYPE_INFO = {
    "email": ("Email address", "name@example.com"),
    "username": ("Username or ID", "a handle or account name"),
    "ip": ("IP address", "203.0.113.9"),
    "phone": ("Phone number", "+44 20 7946 0000"),
    "domain": ("Domain", "example.com"),
    "url": ("Web address", "https://example.com/page"),
    "hash": ("File hash", "SHA-256, MD5 or SHA-1"),
    "keyword": ("Name or keyword", "a person's or company's name"),
    "password": ("Password (checked, never stored)", "checked by hash prefix only"),
    "image": ("Face or image", "a photo you are allowed to search"),
}

ACCESS_INFO = {
    "FREE_PUBLIC_API": "Free public API, no key",
    "FREE_KEY_API": "Free with a key",
    "PAID_API": "Paid API",
    "CLI_OPEN_SOURCE": "Open-source tool run on this computer",
    "WEB_ONLY": "Website only",
    "ENTERPRISE_CONTRACT": "Enterprise contract",
    "UNKNOWN": "Not verified yet",
}
CHECKS = ("docs", "code", "search", "none")
CAT_STATUS = ("handoff", "manual", "research")


@dataclass(frozen=True)
class Entry:
    id: str
    name: str
    category: str
    use: str
    types: tuple = ()
    access: str = "UNKNOWN"
    check: str = "none"
    status: str = "research"
    official: str = ""
    note: str = ""


def _e(*a, **k) -> Entry:
    return Entry(*a, **k)


# ---- entries that have a connector: the connector supplies the search types and the kind
REGISTRY_ENTRIES = [
    _e("sherlock", "Sherlock", "Username", "Checks whether a username is registered on many public websites; the results show which sites answered.", access="CLI_OPEN_SOURCE", check="code"),
    _e("maigret", "Maigret", "Username", "Username search across a large catalogue of sites, with profile details collected where a site shows them.", access="CLI_OPEN_SOURCE", check="code"),
    _e("holehe", "Holehe", "Email intelligence", "Checks which websites an email address appears to be registered on, through each site's sign-in or recovery form.", access="CLI_OPEN_SOURCE", check="code",
       note="Contacts third-party sites on the target's behalf, so the shield must allow it."),
    _e("theharvester", "theHarvester", "Domain recon", "Collects email addresses, hostnames and subdomains for a domain from public search and passive sources.", access="CLI_OPEN_SOURCE", check="code"),
    _e("spiderfoot", "SpiderFoot", "Recon automation", "Runs many OSINT modules against one target and links the results; you choose which modules run.", access="CLI_OPEN_SOURCE", check="code"),
    _e("phoneinfoga", "PhoneInfoga + libphonenumber", "Phone", "Gathers public information about a phone number: country, carrier and line-type hints from local number parsing.", access="CLI_OPEN_SOURCE", check="code",
       note="Local number parsing needs no internet; the PhoneInfoga binary is optional."),
    _e("shodan", "Shodan", "Infrastructure", "Shows open ports, services and known CVE hints for an IP or domain from Shodan's index of internet-facing devices.", access="FREE_KEY_API", check="code",
       note="Without a key the free InternetDB view is used."),
    _e("dehashed", "DeHashed", "Breach data", "Searches breached-credential records by email, username, domain, IP or phone; passwords stay hidden until you reveal them.", access="PAID_API", check="code"),
    _e("hibp", "Have I Been Pwned", "Breach data", "Checks whether an email address or domain appears in known data breaches; passwords are checked by hash prefix only.", access="FREE_KEY_API", check="code",
       note="Breach lookups need a paid key; the Pwned Passwords check needs none."),
    _e("pimeyes", "PimEyes", "Face search", "Face search on the PimEyes website. The program does not upload your image; you search there yourself.", access="WEB_ONLY", check="code",
       note="Face search is sensitive. The program asks you before it opens the site."),
    _e("epieos", "Epieos", "Email intelligence", "Finds public accounts and profile traces linked to an email address or phone number.", access="UNKNOWN", check="code",
       note="Keyed access terms are not verified. Research required before relying on it."),
    _e("hunter", "Hunter.io", "Email intelligence", "Finds professional email addresses published for a company domain, and checks an email address.", access="FREE_KEY_API", check="code"),
    _e("intelx", "Intelligence X", "Dark web & leaks", "Searches leak archives, pastes and indexed sources for an email, domain, IP, phone or URL.", access="UNKNOWN", check="code",
       note="Needs a key; free-tier limits are not verified."),
    _e("virustotal", "VirusTotal", "Reputation", "Checks a domain, IP, URL or file hash against VirusTotal's detections and submission history.", access="FREE_KEY_API", check="code"),
    _e("urlscan", "urlscan.io", "Web history", "Lists public scans of a domain, IP or URL, including screenshots and the requests the page made.", access="FREE_KEY_API", check="code"),
    _e("github", "GitHub", "Identity & code", "Searches public GitHub code, profiles and commits for a username, email or domain.", access="FREE_KEY_API", check="code",
       note="A token is optional and raises the limits."),
    _e("hudsonrock", "Hudson Rock Cavalier", "Dark web & leaks", "Checks whether an email, username or domain appears in infostealer-malware data.", access="UNKNOWN", check="code",
       note="Keyed contract terms are not verified. Research required."),
    _e("wayback", "Wayback Machine", "Web history", "Lists archived snapshots of a domain or URL from the Internet Archive's CDX index.", access="FREE_PUBLIC_API", check="code"),
    _e("ahmia", "Ahmia (Tor index)", "Dark web & leaks", "Searches an index of public .onion sites through Tor. The program queries the index; it does not open the onion sites.", access="FREE_PUBLIC_API", check="code",
       note="Free, and used only through Tor."),
    _e("maltego", "Maltego", "Graph & analysis", "Graph and link-analysis tool. This program exports results as Maltego-compatible CSV or ZIP files for you to open there.", access="UNKNOWN", check="code",
       note="Maltego has its own licence. This program only writes the export files."),
    _e("rdap", "RDAP registration record", "Domain & DNS", "Registrar, dates, status and nameservers for a domain, from the registry that holds it (IANA bootstrap).", access="FREE_PUBLIC_API", check="docs"),
    _e("abuseipdb", "AbuseIPDB", "Reputation", "Crowd-sourced abuse reports and a confidence score for an IP address.", access="FREE_KEY_API", check="docs",
       note="Needs a free account key. Response field names still need a live check."),
    _e("greynoise", "GreyNoise Community", "Reputation", "Shows whether an IP address is seen scanning the internet, and how it is classified (community data).", access="FREE_KEY_API", check="docs",
       note="Works without a key within a small daily allowance. Response field names still need a live check."),
]

# ---- entries without a connector
OTHER_ENTRIES = [
    _e("ghunt", "GHunt", "Email intelligence", "Investigates a Google account from its email address (public profile details). It needs a signed-in Google session.", ("email",), "CLI_OPEN_SOURCE", "none", "manual",
       note="Running it would use a Google login. It stays off automated searches so no personal account is used by the program."),
    _e("castrick", "Castrick", "Identity & people", "Not verified yet. Research required before use.", (), "UNKNOWN", "none", "research"),
    _e("emailrep", "EmailRep", "Reputation", "Email reputation signals for risky or disposable addresses, from public and reported data.", ("email",), "UNKNOWN", "none", "research",
       note="Vendor documentation was not read in development."),
    _e("breachdirectory", "BreachDirectory", "Breach data", "Breach search for email addresses, usernames and domains.", ("email", "username", "domain"), "UNKNOWN", "none", "research",
       note="Access and terms were not read."),
    _e("leakcheck", "LeakCheck", "Breach data", "Breach search for email addresses and usernames.", ("email", "username", "domain"), "UNKNOWN", "search", "research",
       note="Unofficial client code refers to API v2. The official documentation was not read."),
    _e("simplelogin", "SimpleLogin", "Privacy protection", "Email-alias service: gives you a forwarding address for sign-ups so your own inbox stays private. It protects you; it is not a lookup source.", (), "UNKNOWN", "none", "manual"),
    _e("whoxy", "Whoxy", "Domain & DNS", "WHOIS and reverse-WHOIS data: who registered a domain, and other domains linked to the same registrant.", ("domain",), "UNKNOWN", "none", "research"),
    _e("thatsthem", "That's Them", "Identity & people", "People-search website built from public records. Results can expose private people, so use it only for a specific, lawful purpose.", ("email", "phone", "username", "keyword"), "WEB_ONLY", "none", "research"),
    _e("osint_industries", "OSINT Industries", "Identity & people", "Commercial email, phone and username enrichment service.", ("email", "phone", "username"), "UNKNOWN", "none", "research"),
    _e("mailcat", "Mailcat", "Email intelligence", "Not verified yet. Research required, including whether it contacts third-party sites.", ("email",), "UNKNOWN", "none", "research"),
    _e("xposedornot", "XposedOrNot", "Breach data", "Breach-check service for an email address. Public client code exists; the official API page was not read.", ("email",), "UNKNOWN", "search", "research",
       official="https://github.com/XposedOrNot"),
    _e("signalhire", "SignalHire", "Identity & people", "Contact-data platform for professional emails and phone numbers. Paid access.", ("email", "phone", "username"), "UNKNOWN", "none", "research"),
    _e("skymem", "Skymem", "Identity & people", "Web directory of email addresses by domain or company. Web lookup only.", ("domain", "email"), "WEB_ONLY", "none", "research"),
    _e("proton_mail", "Proton Mail", "Privacy protection", "Encrypted email provider: keeps your own mailbox separate from the investigation. It is not a lookup source.", (), "WEB_ONLY", "none", "manual"),
    _e("darkowl", "DarkOwl Vision", "Dark web & leaks", "Dark-web data platform: searches stolen-data and leak sources for an organisation's data and credentials. Enterprise sales.", ("keyword", "email", "domain"), "ENTERPRISE_CONTRACT", "none", "research"),
    _e("recorded_future", "Recorded Future", "Threat intelligence", "Threat-intelligence platform for security teams: tracks threat actors, leaked credentials and exposed assets. Enterprise subscription.", ("email", "domain", "ip", "hash", "url", "keyword"), "ENTERPRISE_CONTRACT", "none", "research"),
    _e("spycloud", "SpyCloud", "Breach data", "Identity-exposure platform: finds breached and stolen credentials tied to an organisation or a person. Enterprise subscription.", ("email", "username", "domain"), "ENTERPRISE_CONTRACT", "none", "research"),
    _e("intsights", "IntSights", "Threat intelligence", "Threat-intelligence platform for external threats and leaks. Ownership changed; research the current product first.", ("keyword", "domain", "email"), "UNKNOWN", "none", "research"),
    _e("constella", "Constella Intelligence", "Breach data", "Identity-breach monitoring (formerly 4iQ). The current name and access terms need research.", ("email", "username", "phone"), "UNKNOWN", "none", "research"),
    _e("kela", "KELA", "Threat intelligence", "Threat-intelligence and dark-web monitoring platform for enterprises.", ("keyword", "domain", "email", "ip"), "ENTERPRISE_CONTRACT", "none", "research"),
    _e("cybersixgill", "Cybersixgill", "Dark web & leaks", "Dark-web threat-intelligence platform for analysts.", ("keyword", "domain", "email", "ip", "hash"), "ENTERPRISE_CONTRACT", "none", "research"),
    _e("digital_shadows", "Digital Shadows SearchLight", "Threat intelligence", "Digital-risk and dark-web monitoring (SearchLight). Ownership changed; research required.", ("keyword", "domain", "email"), "UNKNOWN", "none", "research"),
    _e("zerofox", "ZeroFox", "Threat intelligence", "External threat monitoring: impersonation, leaked data and dark-web mentions for brands and executives.", ("domain", "email", "keyword", "url"), "ENTERPRISE_CONTRACT", "none", "research"),
    _e("cognitio", "Cognitio", "Dark web & leaks", "Not verified yet. Research required before use.", (), "UNKNOWN", "none", "research"),
    _e("flashpoint", "Flashpoint", "Threat intelligence", "Threat-intelligence platform covering dark-web forums, marketplaces and leaks. Enterprise access.", ("keyword", "email", "domain", "ip", "hash"), "ENTERPRISE_CONTRACT", "none", "research"),
    _e("echosec", "Echosec Beacon", "Dark web & leaks", "Geo-located social-media and dark-web monitoring. Current status not verified.", ("keyword",), "UNKNOWN", "none", "research"),
    _e("darktracer", "DarkTracer", "Dark web & leaks", "Not verified yet: the name may refer to Darktrace, a different company. Research required.", (), "UNKNOWN", "none", "research"),
    _e("id_agent", "ID Agent", "Breach data", "Not verified yet. Research required before use.", (), "UNKNOWN", "none", "research"),
    _e("blueliv", "Blueliv", "Threat intelligence", "Threat-intelligence and brand-protection platform, including dark-web and leak monitoring.", ("domain", "email", "keyword", "ip"), "ENTERPRISE_CONTRACT", "none", "research"),
    _e("cyberint", "Cyberint", "Threat intelligence", "External attack-surface and dark-web monitoring. Ownership changed; research required.", ("domain", "keyword", "ip"), "UNKNOWN", "none", "research"),
    _e("surfwatch", "SurfWatch Labs", "Threat intelligence", "Threat-intelligence platform. Status and access not verified.", ("keyword", "domain"), "UNKNOWN", "none", "research"),
    _e("sanction_scanner", "Sanction Scanner", "Threat intelligence", "Sanctions and AML screening: checks a name or company against watch lists. It answers a compliance question, not an online-footprint question.", ("keyword",), "UNKNOWN", "none", "research"),
    _e("torcrawl", "TorCrawl.py", "Dark web & leaks", "Python script that crawls .onion sites over Tor. Crawling hidden services can reach illegal content and can expose you, so the program never runs it automatically.", ("url", "keyword"), "CLI_OPEN_SOURCE", "none", "manual"),
    _e("deepdarkcti", "DeepDarkCTI", "Threat intelligence", "A collection of dark-web threat-intelligence sources and references. A reading list, not a search service.", (), "UNKNOWN", "none", "manual"),
    _e("onionscan", "OnionScan", "Dark web & leaks", "Scanner for .onion services that looks for misconfigurations and leaks. It contacts hidden services, so it stays manual.", ("url", "domain"), "CLI_OPEN_SOURCE", "none", "manual"),
    _e("robin", "Robin", "Dark web & leaks", "Not verified yet. It is described as a dark-web search tool; it would contact hidden services, so it stays manual even after research.", ("keyword",), "UNKNOWN", "none", "research"),
    _e("torbot", "TorBot", "Dark web & leaks", "Crawler and link mapper for .onion sites over Tor. It contacts hidden services, so it stays manual.", ("url", "keyword"), "CLI_OPEN_SOURCE", "none", "manual"),
    _e("ipinfo", "IPinfo", "IP & network", "IP geolocation, network (ASN) and company data for an IP address.", ("ip",), "UNKNOWN", "none", "research"),
    _e("censys", "Censys", "IP & network", "Internet-scan search: hosts, services and certificates seen on the internet. Needs an account.", ("ip", "domain"), "UNKNOWN", "none", "research"),
    _e("numverify", "NumVerify", "Phone", "Phone-number validation and carrier lookup API. Free-tier limits need checking before use.", ("phone",), "UNKNOWN", "none", "research"),
    _e("veriphone", "Veriphone", "Phone", "Phone-number validation and line-type API. Free-tier limits not read.", ("phone",), "UNKNOWN", "none", "research"),
    _e("malwarebazaar", "MalwareBazaar", "Threat intelligence", "Looks up a malware sample by its SHA-256, MD5 or SHA-1 hash in abuse.ch's sample database.", ("hash",), "FREE_KEY_API", "docs", "research",
       official="https://bazaar.abuse.ch/api/",
       note="Endpoint, POST form fields and the Auth-Key header were read. The response format is not verified yet, so it is not automated."),
    _e("tineye", "TinEye", "Reverse image", "Reverse image search: finds where an image appears on the web. The API is paid; not read in development.", ("image",), "UNKNOWN", "none", "research"),
    _e("securitytrails", "SecurityTrails", "Domain & DNS", "DNS records, subdomains and domain history for a domain.", ("domain", "ip"), "FREE_KEY_API", "docs", "research",
       official="https://docs.securitytrails.com/",
       note="Base URL and the APIKEY header were read. The domain endpoint path and the quotas are not verified yet."),
    _e("crtsh", "crt.sh", "Certificates", "Certificate-transparency search: lists TLS certificates issued for a domain, which can reveal subdomains.", ("domain",), "FREE_PUBLIC_API", "search", "research",
       note="Its JSON output is not in any vendor page read here. Not automated until the format is verified."),
    _e("archive_today", "archive.today", "Web archive", "Archived snapshots of web pages. No official API was found in this build; the website address is not verified yet.", ("url",), "WEB_ONLY", "none", "research"),
    _e("recon_ng", "Recon-ng", "Recon automation", "Modular recon framework for scripted OSINT workflows. Its modules contact targets and third-party services.", ("domain", "ip", "email", "username"), "CLI_OPEN_SOURCE", "none", "manual"),
    _e("nmap", "Nmap", "Active scanner", "Active port and service scanner. It sends probes that the target can detect, and must not be pointed at systems without permission.", ("ip", "domain"), "CLI_OPEN_SOURCE", "none", "manual",
       note="Never run by this program. It is listed so you know what it is, not as a search source."),
    _e("google_lens", "Google Lens", "Reverse image", "Reverse image search by Google (website only).", ("image",), "WEB_ONLY", "none", "research"),
    _e("yandex_images", "Yandex Images", "Reverse image", "Reverse image search by Yandex (website only).", ("image",), "WEB_ONLY", "none", "research"),
    _e("bing_visual", "Bing Visual Search", "Reverse image", "Reverse image search by Bing (website only).", ("image",), "WEB_ONLY", "none", "research"),
]

ENTRIES = REGISTRY_ENTRIES + OTHER_ENTRIES
BY_ID = {e.id: e for e in ENTRIES}
ID_OK = set("abcdefghijklmnopqrstuvwxyz0123456789_")


def validate(registry_ids) -> list:
    """Problems with the catalogue itself, compared with the connectors that are registered."""
    probs = []
    seen = set()
    for e in ENTRIES:
        if e.id in seen:
            probs.append(f"duplicate id {e.id}")
        seen.add(e.id)
        if not (2 <= len(e.id) <= 32) or not set(e.id) <= ID_OK:
            probs.append(f"bad id {e.id}")
        if not e.use.strip():
            probs.append(f"{e.id}: empty use text")
        if e.access not in ACCESS_INFO:
            probs.append(f"{e.id}: unknown access {e.access}")
        if e.check not in CHECKS:
            probs.append(f"{e.id}: unknown check {e.check}")
        for t in e.types:
            if t not in TYPE_INFO:
                probs.append(f"{e.id}: unknown search type {t}")
    for e in OTHER_ENTRIES:
        if e.status not in CAT_STATUS:
            probs.append(f"{e.id}: unknown status {e.status}")
        if e.status == "handoff" and not e.official:
            probs.append(f"{e.id}: handoff without an official address")
        if e.id in registry_ids:
            probs.append(f"{e.id}: has a connector but is listed as catalogue-only")
    reg_ids = {e.id for e in REGISTRY_ENTRIES}
    for rid in registry_ids:
        if rid not in reg_ids:
            probs.append(f"connector {rid} has no catalogue entry")
    for e in REGISTRY_ENTRIES:
        if e.id not in registry_ids:
            probs.append(f"{e.id}: catalogue entry without a connector")
    return probs


def status_for(e: Entry, kind: Optional[str]) -> str:
    """Status shown to people: connectors take it from their kind; the rest use the catalogue status."""
    if kind in ("api", "cli", "local"):
        return "automated"
    if kind in ("handoff", "export"):
        return kind
    return e.status


def search_types_for(e: Entry, targets: tuple) -> tuple:
    return tuple(targets) if targets else tuple(e.types)


def describe(e: Entry, targets: tuple = (), kind: Optional[str] = None) -> dict:
    """The fields the interface shows for a tool. targets/kind come from the connector when there is one."""
    types = search_types_for(e, targets)
    return {
        "use": e.use,
        "category": e.category,
        "search_types": list(types),
        "access": e.access,
        "access_label": ACCESS_INFO.get(e.access, e.access),
        "check": e.check,
        "catalog_status": status_for(e, kind),
        "official": e.official,
        "catalog_note": e.note,
    }


def for_type(ttype: str, registry: dict) -> list:
    """Every catalogue entry that can serve a search type, with its connector if it has one."""
    out = []
    for e in ENTRIES:
        conn = registry.get(e.id)
        targets = tuple(conn.meta.targets) if conn else ()
        types = search_types_for(e, targets)
        if ttype in types:
            out.append((e, conn))
    return out
