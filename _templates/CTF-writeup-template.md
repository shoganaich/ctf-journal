# [CTF Number]: [CTF / Lab Name]
> **Date:** [YYYY-MM-DD]  
> **Platform:** [Azure, TryHackMe, Cyber Range, etc.]  
> **Category:** [Blue Team, Threat Hunt, IR, etc.]  
> **Author:** [Your Name or Alias]

---

## 📝 Fundamental Information

- **Hunt Name:**  
- **Initiated By:**  
- **Start / End Date:**  
- **Affected Asset(s):**  
    - Name:  
    - OS:  
    - IP:  
    - Main Account:  
    - First Seen:  
    - Last Seen:  
- **Tools/Tech Used:**  
    - Azure Log Analytics
    - Row Zero
	- Microsoft Defender for Endpoint
	- KQL
	- etc.

---

## 🚩 Flags & Investigation Timeline

> _For each flag or investigative milestone, add a section like below:_

### Flag X – [Short Name/Objective]
- **Objective:**  
- **What to Hunt:**  
- **Thoughts/Strategy:**  
- **Hints:** (if given)
- **Query/Process:**  
    ```kql
    // KQL/Command here
    ```
- **Finding:**  
    - _Describe exactly what was found and why it matters._
    - **FLAG:** `flag value or artifact`
    - Screenshots or data_dumps
---

## 🔎 TTPs (Tactics, Techniques & Procedures)

Summarize the tactics and techniques found, mapping to MITRE ATT&CK if possible.

| Flag | Tactic/Stage        | Technique/Behavior                        | Brief Summary                                        |
|------|---------------------|-------------------------------------------|------------------------------------------------------|
| 1    | Initial Access      | Obfuscated PowerShell via Explorer        |                                                      |
| 2    | Command & Control   | Outbound beacon to pipedream.net domain   |                                                      |
| ...  | ...                 | ...                                       | ...                                                  |

---

## 🛑 IOC (Indicators of Compromise)

List critical IOCs (VMs, files, domains, registry keys, scripts, etc).

| Type        | Value(s)                                             |
|-------------|------------------------------------------------------|
| VM Name     | ...                                                  |
| Registry    | ...                                                  |
| File/Script | ...                                                  |
| Domain      | ...                                                  |

---

## 🔖 MITRE ATT&CK Coverage

| Technique ID | Name                                       | Flags/Steps |
|--------------|--------------------------------------------|-------------|
| T1059.001    | PowerShell                                 | 1, 5, 6     |
| ...          | ...                                        | ...         |

---

## 🛡️ Response Recommendations

- **Containment:**  
    - Isolate affected assets
    - Block suspicious outbound domains
- **Forensics:**  
    - Memory dumps, event logs, collect artifacts
- **IOC Sweeping:**  
    - Search across environment for listed IOCs/behaviors
- **Persistence Audit:**  
    - Scheduled tasks, registry keys, WMI, etc.
- **Remediation:**  
    - Remove malicious artifacts and persistence, reimage if needed

---

## 🚀 Improvements & Lessons Learned

- **Detection Coverage:**  
    - Add alerts for [techniques, commands, domains]
- **Hunting SOP:**  
    - What worked well? Any new baseline strategies?
- **Tooling:**  
    - Tools that were effective or new tips
- **Knowledge Sharing:**  
    - Ideas for turning the hunt into a learning/training exercise

---

## 📁 Artifacts

- [Screenshots, configs, sample logs] (optional, link here)

---

## 🔗 References

- [Docs, blogs, related links, tools, platform links]

---

> _Template v1.0 inspired by Shoganaich's blue team hunt style_
