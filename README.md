# SOC Detection Rules (Sigma)

[![CI](https://github.com/JsonCMorgan/soc-detection-rules/actions/workflows/ci.yml/badge.svg)](https://github.com/JsonCMorgan/soc-detection-rules/actions/workflows/ci.yml)
![Rules](https://img.shields.io/badge/rules-12-blue)

## What this repo is

I'm Jason. This is my **detection-as-code** scratch pad: twelve [Sigma](https://github.com/SigmaHQ/sigma) rules aimed at the kind of alerts I want to be able to write and tune on a SOC floor. Windows 4625/4688, RDP, service installs, web SQLi, Linux SSH, DNS hints. CI loads every rule and converts it to **Splunk SPL** and **Microsoft Sentinel KQL** with pySigma so the YAML is not dead weight.

| SOC theme | Example rule file |
|-----------|-------------------|
| Credential attacks | `win_failed_logon_burst.yml` |
| Privilege / persistence | `win_new_local_admin.yml`, `win_service_install.yml` |
| Execution | `win_powershell_encoded.yml` |
| Defense evasion | `win_security_log_cleared.yml` |
| Lateral movement | `win_rdp_logon_type10.yml`, `fw_smb_egress.yml` |
| Cloud identity | `m365_risky_signin.yml` |
| App / Linux / DNS | `web_sqli_uri.yml`, `linux_ssh_bruteforce.yml`, `dns_long_subdomain.yml` |

**Spine of the stack:** [boundry-ai-soc-platform](https://github.com/JsonCMorgan/boundry-ai-soc-platform) (where I practice SIEM workflow and correlation).

---

## MITRE ATT&CK mapping

| Rule file | Title | Tactic (tag) | Technique ID |
|-----------|-------|----------------|--------------|
| `win_failed_logon_burst.yml` | Windows failed logon burst (4625) | Credential Access | T1110.001 |
| `win_new_local_admin.yml` | New local administrator account created | Persistence | T1136 |
| `win_powershell_encoded.yml` | Suspicious PowerShell encoded command | Execution | T1059.001 |
| `win_security_log_cleared.yml` | Security event log cleared | Defense Evasion | T1070.001 |
| `win_rdp_logon_type10.yml` | RDP interactive logon (type 10) | Lateral Movement | T1021.001 |
| `win_service_install.yml` | New Windows service installed | Persistence | T1543.003 |
| `win_special_privilege_logon.yml` | Special privileges assigned to new logon | Privilege Escalation | (tactic tag only) |
| `fw_smb_egress.yml` | Outbound SMB connection attempt | Lateral Movement | (tactic tag only) |
| `m365_risky_signin.yml` | Azure AD risky sign-in reported | Initial Access | (tactic tag only) |
| `web_sqli_uri.yml` | HTTP request with SQLi patterns in URI | Initial Access | T1190 |
| `linux_ssh_bruteforce.yml` | SSH authentication failure burst | Credential Access | T1110 |
| `dns_long_subdomain.yml` | DNS query for unusually long subdomain | Command and Control | (tactic tag only) |

Tags come from each rule's `tags:` block. I'd tune level and false positives per environment before any production use.

---

## Why I bother with Sigma

A **Sigma rule** is a vendor-neutral recipe for an alert. You write it once. A converter prints Splunk, Sentinel, Elastic, or other dialects. That's how real teams avoid maintaining ten copies of the same logic.

**How I think about it:** Sigma is the sheet music. Splunk and Sentinel are different bands playing the same song.

---

## Run tests locally

```bash
pip install -r requirements.txt
pytest -q
```

---

## Convert one rule (Splunk)

```python
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend

rule = SigmaCollection.load_ruleset([Path("rules/win_failed_logon_burst.yml")]).rules[0]
print("\n".join(SplunkBackend().convert_rule(rule)))
```

---

## How this ties to Boundry

In [boundry-ai-soc-platform](https://github.com/JsonCMorgan/boundry-ai-soc-platform), correlation rules in `siem_rules` and training scenarios raise events that **these rules are meant to detect**. Next step on my list: map each Sigma `id` to a Boundry `siem_rules` row and a MITRE tag in the SIEM UI.