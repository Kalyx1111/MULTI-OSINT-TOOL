# MULTI-OSINT-TOOL

A privacy-first open-source-intelligence workbench that runs on your own computer. It searches public and
licensed sources for an email address, username or ID, IP address, phone number, domain, web address,
file hash, name, password or face photo, and shows which source produced each result.

Read `mot_SECURITY.md` before you use it on real targets.

## Start it

| System | Command |
|---|---|
| Windows | double-click `mot_launch.bat` |
| Linux / macOS | `./mot_launch.sh` |
| Any system (Python 3.10+) | `python mot_main.py run` |

The launcher creates a private Python environment inside this folder and changes nothing system-wide.
Other commands: `doctor` (health checks), `selftest` (offline self-checks of every connector),
`tools` (status of the optional command-line tools), `bootstrap` (installs the required packages when they
are missing), `version`.

Runtime dependencies are pinned in `mot_requirements.txt`. Offline installs check the wheels in `wheels/`
against `wheels/mot_wheels.sha256` before pip runs.

## What is in the folder

- `mot_main.py` launches the program under a supervisor that restarts it after a crash.
- `mot_server.py` is the local web server. It listens on the loopback address only.
- `mot_app.py` holds the application logic. `mot_orchestrator.py` runs searches.
- `mot_conn_api.py`, `mot_conn_cli.py`, `mot_conn_web.py`, `mot_conn_intel.py` are the connectors.
- `mot_catalog.py` describes every source: what it is used for, its search types, its access model and
  how far it was verified.
- `mot_netguard.py` is the network shield. It decides whether a search may send anything at all.
- `mot_vault.py`, `mot_store.py`, `mot_audit.py` hold the encrypted vault, cases and audit log.
- `mot_resilience.py` holds the job journal, heartbeat, health checks and recovery.
- `mot_ui/` is the interface (plain ES modules, no framework).
- `mot_tests/` holds the unit tests and the interface test harness.

## Search types

Email address · Username or ID · IP address · Phone number · Domain · Web address · File hash ·
Name or keyword · Password (checked, never stored) · Face or image (never uploaded).

The search screen shows, before anything is sent:

- which tools will search this kind of target, and whether each one is free or uses your key;
- which tools need a key, are off in Connections, or are not installed;
- which sources are never searched automatically (website-only, kept manual, or not yet verified), with the reason.

Each result line names the tool that produced it and says what that tool is used for.

## Sources

`mot_catalog.py` lists 74 sources:

- **21 run automatically** when they are enabled and ready (15 web APIs, 5 command-line tools, 1 local
  phone-number check). Epieos is one of the web APIs, but it runs only after you enter your Epieos contract details;
  until then it is not searched;
- **2 are connected in another way**: PimEyes opens its own website for you, and Maltego receives an
  export file to open there;
- **51 are listed but never sent your target**: kept manual on purpose (Google account lookups that need
  your own login, active scanners, crawlers of hidden services), or research required (the program does
  not use them until their access model and terms have been verified).

Connected sources that need a key read it from the vault, or from an environment variable named
`MOT_KEY_<TOOL>_<FIELD>`. Keys in the vault take precedence.

## Verification status

- RDAP (domain registration): the IANA bootstrap file was read; the registry servers for `.com` and `.org` were confirmed.
- AbuseIPDB: the documentation was read for the endpoint, the `Key` header and the look-back parameter.
  Field names in the response were **not** checked against a live response.
- GreyNoise Community: the documentation was read for the endpoint and the `key` header.
  Field names in the response were **not** checked against a live response.
- Hudson Rock Cavalier (free endpoint): implemented, but its response layout and its terms were not verified against a
  live reply. Its keyed v3 API is not implemented.
- MalwareBazaar: the endpoint, form fields and `Auth-Key` header were read. Not connected yet, because the
  response format has not been verified.
- Every other source: not verified enough to rely on, unless the catalogue says otherwise.

Live responses were not exercised in development. Run a connection test with a real key before you rely on a source.

## Tests

```
python -m unittest discover -s mot_tests -t . -p "mot_test_*.py"
```

The suite is offline. It covers the search pipeline, input validation, the local server and its request
guards, a full workflow, the idle lock, external links, the catalogue and the new connector parsers, the
bundle manifest, install pre-flight checks and safe archive extraction. The interface test harness
(`mot_tests/mot_ui_harness.py`) drives the screens with canned results, so no real site is contacted.
The vault and the shield do not yet have dedicated unit tests; that is listed as outstanding work.

## Limits you should know about

- Python cannot guarantee that secrets are wiped from memory.
- A program running as your user cannot stop leaks that the operating system or other software make.
- The shield only protects traffic that goes through it. Your VPN must be real and working.
- Some sites block Tor exit addresses, and some block VPN addresses. A blocked source returns "blocked", not a result.
- Public sources and the commercial platforms change their terms and endpoints. Re-check a source before you
  depend on it.
