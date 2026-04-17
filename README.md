# Mysterious Elephant - DFIR Investigation

## Overview
This repository contains my full forensic analysis of the **Mysterious Elephant** Sherlock from Hack The Box. The investigation focused on identifying the tactics, techniques, and procedures (TTPs) of an APT (Advanced Persistent Threat) group.

## Skills & Tools Used
* **Platform:** Kali Linux
* **Forensics:** Log analysis (`auth.log`), Registry analysis, Artifact recovery
* **Tools:** `grep`, `sha256sum`, `pandoc`, `rclone`
* **Documentation:** Markdown to PDF conversion for professional reporting

## Repository Structure
* `Final_Sherlock_Report.pdf`: The finalized professional report.
* `fortyseven-1.md`: Raw investigation notes and solutions.
* `checksum.txt`: SHA256 hash of the final report for integrity.
* `/*.png`: Captured forensic evidence and screenshots.

## Key Findings
* Identified malicious entry points and persistence mechanisms.
* Traced exfiltration methods back to C2 infrastructure.
* Mapped attacker activity to the MITRE ATT&CK framework.

---
*Disclaimer: This project was completed as part of the Hack The Box "Sherlocks" forensic path.*
