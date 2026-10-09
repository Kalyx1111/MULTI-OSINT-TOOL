# MULTI-OSINT-TOOL

---

#### 🔎 MULTI-OSINT-TOOL — MULTI-SOURCE INTELLIGENCE INVESTIGATION PLATFORM

**MULTI-OSINT-TOOL (MOT)** is a multi-source Open-Source Intelligence investigation platform designed to organize searches across public intelligence sources, web APIs, command-line tools and manual investigation workflows.

The platform provides a catalogue of **74 OSINT tools**, a unified search interface, per-tool execution status, encrypted vault functionality, case management, protected secret handling and structured results.

Its defining principle is transparency: every tool is classified according to what it can actually do, what credentials it requires and whether further research is necessary.

**One interface. Multiple intelligence sources. Explicit search status. Controlled case handling.**

---

#### 🎯 CORE CAPABILITIES

* Catalogue of **74 OSINT tools**
* Search across 10 input categories
* Automated API and command-line connectors
* Manual investigation workflows
* Website-only and export-based workflows
* Per-tool execution states
* Tool-specific explanations and purposes
* Result attribution to the tool that produced it
* Encrypted secrets vault
* Case management and controlled result disclosure
* Redacted logs and exports
* Local browser-based interface
* Offline installation-bundle builder
* Security-focused input validation and request controls

---

#### 🔍 SUPPORTED SEARCH TYPES

MULTI-OSINT-TOOL supports the following investigation input categories:

1. Email address
2. Username or online ID
3. IP address
4. Phone number
5. Domain
6. Web address / URL
7. File hash
8. Name or keyword
9. Password
10. Face or image

Available results depend on the selected tools, their supported capabilities, credentials, network access and the status of individual integrations.

---

#### 🧰 THE 74-TOOL CATALOGUE

The catalogue groups tools according to their actual integration state rather than treating every listed source as a working connector.

| Integration category  |  Count | Meaning                                                              |
| --------------------- | -----: | -------------------------------------------------------------------- |
| Automated             |     21 | 15 web APIs, 5 command-line tools and 1 local phone check            |
| Connected another way |      2 | PimEyes website workflow and Maltego export                          |
| Manual                |      9 | Deliberately manual workflows, including GHunt, Proton Mail and Nmap |
| Research required     |     42 | Integration or verification remains outstanding                      |
| **Total**             | **74** | Complete tool catalogue                                              |

**Important:** catalogue inclusion does not mean a tool has been fully integrated, tested or verified against a live service.

---

#### ⚙️ TRANSPARENT PER-TOOL STATUS

Before a search runs, the application presents each tool's status and explains its role.

Possible states include:

* **Will search** — selected and eligible to execute
* **Needs key** — required credentials or contract details are missing
* **Off** — the tool is disabled
* **Website only** — the workflow requires a website-based investigation
* **Export** — the workflow produces or uses an export
* **Manual** — operator action is required
* **Research** — the connector or its behavior still needs verification

The interface distinguishes tools that will actually execute from those that require additional setup or manual action.

Each tool has a **Used for** explanation, available on the Connections screen and beneath results.

Search results identify the tool responsible for producing them.

---

#### 🌐 API & SOURCE CONNECTORS

The project includes a set of automated integrations, with connector availability depending on the individual implementation and required credentials.

Research and implementation work described for the project includes:

* RDAP
* AbuseIPDB
* GreyNoise
* MalwareBazaar

Additional connectors and vendor integrations remain subject to response-schema verification, access requirements and testing.

**Connector verification is ongoing.** The catalogue must not be interpreted as proof that all 74 sources have working automated integrations.

---

#### 🖥️ USER INTERFACE

MULTI-OSINT-TOOL uses a browser-based interface served locally on loopback.

The frontend uses vanilla JavaScript ES modules.

The interface includes:

* Search screen
* Connections screen
* Tool-purpose descriptions
* Per-tool status and execution planning
* Searched-by information
* Not-searched explanations
* Results display
* Settings
* Encrypted vault
* Case management
* Controlled secret reveal
* Export functionality

The browser smoke test passed using canned results. It verifies the tested interface flow without contacting real intelligence sources.

---

#### 🔐 ENCRYPTED VAULT & CASE MANAGEMENT

The application includes a protected vault and case-handling functionality.

Security controls include:

* Vault unlock requirement for protected routes
* Session checks for vault, case, search and reveal operations
* Server-generated case IDs
* Pattern validation for case identifiers
* Redaction of sensitive fields from case views and exports
* Secret retrieval from the vault before environment-variable fallback
* Protected handling of credentials and investigation data

The vault uses **Argon2id** with configured parameters above the stated minimum settings. A scrypt fallback is available if `argon2-cffi` is missing.

The vault is locally encrypted; it is not a third-party secrets-management service.

---

#### 🛡️ APPLICATION SECURITY

The project incorporates a security-focused design with input validation, protected routes, redacted logging and request controls.

**Input validation**

* Type and length checks
* Pattern and choice validation
* Rejection of unknown fields
* Request-body limit of 1 MiB

**Access controls**

* Session verification
* Vault-unlock enforcement
* Controlled case access
* Server-side rebuilding of the permitted tool plan

**Browser protections**

* Content Security Policy (CSP)
* `X-Content-Type-Options: nosniff`
* `X-Frame-Options: DENY`
* Referrer policy
* COOP/CORP protections
* Permissions Policy
* No-store caching policy
* No CORS headers sent

**Logging and error handling**

* Secret-redaction filters for file and console handlers
* Generic HTTP 500 responses with correlation IDs
* Detailed errors retained in redacted local logs
* Logging of heartbeat, crash-report and native fault-log write failures

The service is intended for a single local user, rather than a multi-tenant deployment.

---

#### 🔑 SECRET MANAGEMENT

Credentials are retrieved from the encrypted vault first, then from the corresponding environment variable:

`MOT_KEY_<TOOL>_<FIELD>`

The application does not use a `.env` loader.

Security principles include:

* No hardcoded production secrets
* Runtime-generated test credentials
* Secret-field removal from case views and exports
* Redaction of sensitive log values
* Controlled reveal operations
* No silent assumption that a missing key means a successful search

Keep API keys and other credentials out of source control, screenshots, public logs and shared investigation exports.

---

#### 🔒 PASSWORD HASHING

The vault uses Argon2id with configured parameters:

* Time cost: 3
* Memory: 64, 128 or 256 MiB depending on available RAM
* Parallelism: up to 4

The fallback scrypt implementation uses a work factor of \(N = 2^{17}\).

The fallback is used only when Argon2 support is unavailable.

---

#### 🚦 RATE LIMITING

The application uses nine rate-limit buckets for sensitive operations.

Examples include:

* Search: 15 requests per minute
* Vault unlock: 8 requests per minute

Rate limits are enforced per process. They are designed for the local single-user deployment and should not be assumed to provide distributed or multi-user rate limiting.

---

#### 🗄️ CASES, RESULTS & EXPORTS

MULTI-OSINT-TOOL provides case handling to help organize investigation results.

The application enforces server-side search planning from its tool registry, refusing tools outside the permitted registry.

Sensitive fields are removed from case views and exports, while controlled reveal routes require the appropriate session and unlocked vault.

Future case synchronization is planned as an optional self-hosted mechanism rather than an assumed cloud feature.

---

#### 🧪 TESTING & VERIFICATION

The delivered build has undergone automated tests and a browser smoke test.

**Verification results:**

* **68 of 68 offline unit tests passed**
* Browser smoke test passed
* Zero browser-console errors during the smoke test
* Bandit: 38 findings, 0 High
* pip-audit: no known vulnerabilities in the six pinned runtime packages
* Installed versions matched the declared package pins

The browser smoke test used canned results. It did **not** contact real intelligence websites or prove that all external connectors work against live services.

---

#### 🔧 FIXES IMPLEMENTED DURING TESTING

Several issues were discovered and corrected during development and verification:

1. Removed literal secrets from tests, fixtures and production self-test code.
2. Changed secret generation to create credentials dynamically per run.
3. Replaced a vacuous test assertion with a check against the generated key.
4. Added logging for heartbeat, crash-report and native fault-log write failures.
5. Corrected the scrypt fallback to use the documented minimum work factor.
6. Escaped bidirectional override and zero-width characters in test data to mitigate Trojan Source-style risks.
7. Corrected tool-status presentation so website-only and research-status tools are not incorrectly shown as ready.
8. Removed an unverified Epieos execution path that presented a website link as though a search would run.

These changes were intended to improve correctness, transparency and defensive handling.

---

#### 📦 DEPENDENCY & SUPPLY-CHAIN STATUS

The project pins six runtime packages using exact versions.

Additional safeguards include:

* pip-audit checks
* Offline wheel verification against a SHA-256 manifest
* Review of Bandit findings
* Review of subprocess invocation patterns

**Remaining supply-chain limitations:**

* Requirements are version-pinned, not fully hash-pinned.
* An SBOM has not yet been provided.
* CI automation has not yet been implemented.
* GitHub tool archives are tag-pinned rather than hash-pinned.

Bandit reported 38 findings, with no High-severity findings. These results should not be interpreted as proof that the code is free of security vulnerabilities.

---

#### 🚀 INSTALLATION & LAUNCH

Extract the delivered archive:

`MULTI-OSINT-TOOL.zip`

**Windows**

Run:

`mot_launch.bat`

**Linux / macOS**

Run:

`./mot_launch.sh`

The launcher is intended to set up the required Python environment, install dependencies and open the local dashboard.

**Important:** the supplied ZIP does not contain offline wheels. A network connection may be required to install dependencies unless an offline bundle has been prepared separately.

---

#### 🧰 TECHNOLOGY STACK

* Python 3.10+
* Vanilla JavaScript ES modules
* Local loopback web server
* Encrypted local vault
* Argon2id password hashing
* scrypt fallback
* SQLite / local application storage components
* Automated API connectors
* Command-line tool integrations
* Bandit security analysis
* pip-audit dependency auditing

---

#### ⚠️ HONEST LIMITATIONS

The following limitations must be considered before operational use:

**Live service verification**

* No live API key was tested.
* No real Tor or VPN route was tested.
* Live output from Sherlock, Maigret, Holehe, theHarvester and SpiderFoot remains untested.
* AbuseIPDB and GreyNoise response fields require verification against real authenticated responses.
* Hudson Rock's free endpoint, response layout and terms remain unverified.
* Epieos requires verified contract endpoint details.
* Forty-two tools remain classified as requiring research.

**Network behavior**

* Some services block Tor exit nodes or VPN addresses.
* Such searches may return a blocked status.
* Live service access and rate limits depend on the provider.

**Memory handling**

Python cannot guarantee that sensitive values are completely erased from process memory. Exposure through the operating system or other software is outside the application's current guarantees.

**Offline deployment**

The ZIP does not include offline wheels. Offline installations require a prepared bundle.

---

#### 🔬 OUTSTANDING DEVELOPMENT WORK

The following items remain planned or pending:

1. Verify vendor documentation and implement additional connectors, including IPinfo, MalwareBazaar, SecurityTrails, crt.sh, EmailRep, XposedOrNot and LeakCheck.
2. Verify AbuseIPDB and GreyNoise response fields using real credentials.
3. Improve the results screen with activity indicators, grouping and relevance ranking.
4. Add dedicated vault and security-shield unit tests.
5. Ship the browser smoke test as `mot_test_ui.py`.
6. Implement hash-pinned requirements, an SBOM, CI and automated secret scanning.
7. Verify handoff URLs for Google Lens, TinEye and That's Them before adding them.

These are outstanding tasks, not claims about features already delivered.

---

#### 🔮 FUTURE EXPANSION

**Encrypted cross-device case synchronization**

A future version may support synchronization between the user's own Windows, Linux and macOS installations through a self-hosted relay over the user's VPN.

The intended design would transfer sealed `.motc` case files while allowing each device to retain its own key.

This is a future development goal and is not presented as a current feature.

---

#### 📋 PROJECT STATE SUMMARY

| Item                  | Status                                                  |
| --------------------- | ------------------------------------------------------- |
| Project               | MULTI-OSINT-TOOL                                        |
| Package               | `MULTI-OSINT-TOOL.zip`                                  |
| Package size          | 55 files                                                |
| Runtime               | Python 3.10+                                            |
| Interface             | Local browser-based UI                                  |
| Catalogue             | 74 tools                                                |
| Automated tests       | 68 passed                                               |
| Browser smoke test    | Passed with canned results                              |
| Bandit                | 38 findings, 0 High                                     |
| pip-audit             | No known vulnerabilities in six pinned runtime packages |
| Live API verification | Not completed for all connectors                        |
| Offline wheels        | Not included in ZIP                                     |
| Cross-device sync     | Future expansion                                        |

---

#### 🛡️ RESPONSIBLE USE

MULTI-OSINT-TOOL is intended for lawful and authorized open-source intelligence research, security analysis and investigation.

Users are responsible for respecting applicable laws, privacy requirements, platform terms, service quotas and the rights of individuals whose information may appear in public sources.

The presence of a tool in the catalogue does not authorize access to private accounts, restricted information or systems without permission.

---
