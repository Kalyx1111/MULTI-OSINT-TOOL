# MULTI-OSINT-TOOL: security model

## Goal

Keep the investigator's identity, IP address, VPN, laptop and network out of the view of the sites and
people being searched. Keep the investigator's data on this computer, encrypted, unless they choose to export it.

## Threat model

In scope:
- the sites and services a search contacts (they must see only the shield's exit, never this computer);
- other people on the same network, and web pages the investigator might open in the same browser;
- a stolen or copied vault file;
- a malformed response, a hostile file name or a hostile page that tries to inject code into the interface.

Out of scope:
- malware or a user account that already controls this computer;
- the operating system, drivers or hardware leaking data outside the program's control;
- the investigator's own mistakes (for example, typing a real name into a search they should not run).

## Network shield (`mot_netguard.py`)

- Fail closed. A search sends nothing unless the shield is verified in one of its modes: Tor over VPN, Tor,
  VPN, or a proxy. Direct connections need an explicit allow.
- Proof is checked, not assumed: the Tor relay and exit are probed, the VPN adapter is detected, and the
  public address seen by the network is compared with a recorded baseline.
- Each outgoing request first checks that the VPN adapter is still up. If it is not, the request is refused and the shield reports the failure.
- Each connector uses its own Tor circuit (`socks5h`, so DNS resolves through the proxy).
- Command-line tools run only in VPN mode or better, with an environment scrubbed of proxy and identity variables.
- Target names are resolved through DNS over HTTPS through the shield, never through the local resolver.

## Local server (`mot_server.py`)

- Binds to the loopback address only. Requests with an unknown `Host` header are refused.
- A one-time launch token starts a session; the session cookie is HttpOnly and SameSite=Strict.
- Every state-changing request needs the CSRF header; `Origin` and `Sec-Fetch-Site` are checked.
- Every route has an input schema that checks types and lengths. Request bodies are limited to 1 MB.
- Rate limits per route group: searches, key tests, installs and exports each have their own limit.
- The content security policy allows scripts, styles and connections only from the program's own origin, with no inline script. The interface builds every element in code; it never uses `innerHTML`.
- Unexpected errors return a generic message and a correlation ID. Details go to the local log, redacted.
- The session locks after the idle time set in Settings.

## Vault and secrets (`mot_vault.py`, `mot_store.py`)

- Cases and keys are encrypted with AES-256-GCM. The master key is derived with Argon2id (scrypt fallback).
  Subkeys for the audit log, cases and the journal come from HKDF, so one compromised purpose does not expose the others.
- Writes are atomic and keep a `.bak` copy. Unlock attempts are throttled.
- API keys are never printed, logged or put in a URL. The interface shows the first character and the length only.
  Revealing a key needs the master password and disappears after 60 seconds.
- Passwords found by a search are hidden by default. Keeping them in a saved case is off unless you switch it on.
- The password checker sends only the first five hex characters of the SHA-1 hash (k-anonymity). The password is never sent, saved or logged.
- Face search never uploads a photo. The program only opens the vendor's website after you confirm consent.

## Audit log (`mot_audit.py`)

Each entry carries an HMAC and the hash of the previous entry, so an edited or removed line is detected.
The Health screen verifies the chain. Investigator-supplied purposes are written only to this log.

## Logs and redaction

Logs and exports pass through a redactor that removes keys, tokens, passwords and personal values before they are written.
Crash reports are written to the local logs folder with the same redaction.

## Supply chain

- Runtime dependencies are pinned in `mot_requirements.txt`.
- The offline bundle is checked against `wheels/mot_wheels.sha256` before installation.
- Downloaded tools are fetched only from allow-listed hosts and are pinned to tags, not to hashes.
  Hash pinning for GitHub archives is not in place yet.

## Known limits

- Python cannot guarantee that memory is wiped. Keys are kept in memory only while needed and are overwritten where possible.
- A process running as the same user can read this program's memory and files.
- The VPN is only as private as the VPN provider. The shield checks that a VPN adapter exists and that the exit address is different from the baseline; it cannot prove the provider keeps no logs.
- Some sites refuse Tor exit addresses. Those searches report "blocked".
- Commercial platforms are listed but not automated until their documentation has been read and their terms allow automation.

## Reporting a problem

Report security issues to the maintainer of this copy through the channel you use for the project. Include the
version (`python mot_main.py version`), what you did, and the log lines around the problem with any personal data removed.
