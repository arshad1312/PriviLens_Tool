# Local Privilege Escalation (LPE) Detection Tool

A lightweight **security auditing tool** that scans Linux and Windows systems for common **Local Privilege Escalation (LPE) misconfigurations**.

This script performs several checks on the host system to identify weak permissions, suspicious processes, insecure configurations and other conditions that may allow a normal user to gain elevated privileges.

The goal of this project is to provide a **simple and readable security scanner** that can help security learners, system administrators and penetration testers quickly review potential privilege escalation risks.

---

# Overview

Privilege escalation is one of the most common steps in post-exploitation.
After gaining initial access to a system, attackers typically look for misconfigurations that allow them to escalate privileges to **administrator or root**.

This tool automates several of those checks and highlights potential security issues with categorized severity levels.

The script runs directly on the target system and prints findings to the terminal.
Optionally, it can also generate a **JSON report** for further analysis.

---

# Features

The tool includes the following analysis modules:

### 1. User Privilege Analysis

Checks the privileges of the current user.

Detects:

* Root or Administrator execution
* Dangerous sudo permissions
* Membership in privileged groups
* SUID binaries
* Linux capabilities on binaries
* Windows token privileges

---

### 2. File & Directory Permission Scan

Scans sensitive files and directories for insecure permissions.

Detects:

* World-writable system files
* Group-writable critical files
* PATH directory hijacking risks
* Weak Windows ACL permissions
* Unquoted Windows service paths

---

### 3. Process Analysis

Reviews running processes to identify suspicious privilege usage.

Detects:

* Processes with elevated **effective UID**
* Unexpected root-level processes
* Root cron jobs that may execute unsafe scripts
* Windows services with weak security descriptors

---

### 4. Registry Analysis (Windows Only)

Analyzes registry keys commonly abused for privilege escalation.

Checks:

* Autorun entries
* Suspicious executable locations
* `AlwaysInstallElevated` misconfiguration
* Privileged startup entries

---

### 5. Log Analysis

Searches system logs for suspicious activity related to privilege escalation attempts.

Examples include:

* Failed sudo authentication
* SSH brute force attempts
* Privileged command execution
* Suspicious cron activity

---

# Severity Levels

Each finding is categorized with a severity level.

| Level  | Meaning                                     |
| ------ | ------------------------------------------- |
| HIGH   | High probability privilege escalation risk  |
| MEDIUM | Potential misconfiguration requiring review |
| LOW    | Minor security observation                  |
| INFO   | Informational output                        |

---

# Installation

Clone the repository:

```
git clone https://github.com/yourusername/lpe-detector.git
cd lpe-detector
```

Install optional dependencies:

```
pip install colorama
```

`colorama` is used only for colored terminal output.

---

# Usage

Run the scanner:

```
python3 lpe_detector.py
```

Run specific modules:

```
python3 lpe_detector.py --modules user files processes
```

Generate a JSON report:

```
python3 lpe_detector.py --output report.json
```

Example:

```
python3 lpe_detector.py --modules user files logs --output scan_report.json
```

---

# Example Output

```
[ HIGH ] User: Unrestricted or NOPASSWD sudo rights detected
[ MEDIUM ] Permissions: Group-writable sensitive file: /etc/passwd
[ INFO ] Processes: No unexpected privilege-escalated processes found
```

At the end of the scan, a **summary report** is displayed.

```
SCAN SUMMARY
HIGH    : 2
MEDIUM  : 3
LOW     : 0
INFO    : 12
```

---

# Supported Platforms

The tool supports:

* Linux distributions
* Windows systems

Some modules are platform-specific:

| Module                  | Linux | Windows |
| ----------------------- | ----- | ------- |
| User Privilege Analysis | ✔     | ✔       |
| File Permission Scan    | ✔     | ✔       |
| Process Analysis        | ✔     | ✔       |
| Registry Analysis       | ✘     | ✔       |
| Log Analysis            | ✔     | ✔       |

---

# Limitations

This tool is intended as a **basic security auditing script** and does not replace professional vulnerability scanners.

Some checks may require:

* elevated privileges
* access to system logs
* installed system utilities (`find`, `getcap`, etc.)

Results should always be reviewed manually.

---

# Project Structure

```
lpe_detector.py
README.md
```

The script is written in **Python** and designed to remain easy to read and modify.

---

# Educational Purpose

This project was created as part of a learning exercise in:

* Linux security
* Windows privilege escalation
* System auditing
* Python security scripting

It is intended for **educational and defensive security purposes only**.

---

# Disclaimer

This tool should only be used on systems you own or have explicit permission to test.

The author is not responsible for misuse.

---

# License

This project is released under the **MIT License**.

---

# Author

Arshad
Cybersecurity Enthusiast
