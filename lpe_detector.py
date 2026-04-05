#!/usr/bin/env python3
"""
=============================================================
  Local Privilege Escalation (LPE) Detection Tool
  Author  : Security Audit Script
  Platform: Linux / Windows
  Usage   : python3 lpe_detector.py [--full] [--output report.txt]
=============================================================

Modules
-------
1. User Privilege Analysis
2. File & Directory Permission Scan
3. Process Analysis
4. Registry Analysis  (Windows only)
5. Log Analysis
"""

import os
import sys
import stat
import platform
import subprocess
import argparse
import datetime
import re
import json
from pathlib import Path

# ──────────────────────────────────────────────
#  Colour helpers (graceful fallback on Windows)
# ──────────────────────────────────────────────
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    RED    = Fore.RED
    YELLOW = Fore.YELLOW
    GREEN  = Fore.GREEN
    CYAN   = Fore.CYAN
    BOLD   = Style.BRIGHT
    RESET  = Style.RESET_ALL
except ImportError:
    RED = YELLOW = GREEN = CYAN = BOLD = RESET = ""

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"

findings: list[dict] = []   # Accumulated findings


def banner() -> None:
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗
║   Local Privilege Escalation Detection Tool (LPE-Scan)   ║
║   Platform : {platform.system():<45}║
║   Date     : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<45}║
╚══════════════════════════════════════════════════════════╝{RESET}
""")


def log(severity: str, category: str, message: str, detail: str = "") -> None:
    """Record a finding and print it."""
    color = {
        "HIGH":   RED,
        "MEDIUM": YELLOW,
        "LOW":    GREEN,
        "INFO":   CYAN,
    }.get(severity, RESET)

    tag = f"[{severity:^6}]"
    print(f"  {color}{BOLD}{tag}{RESET} {BOLD}{category}{RESET}: {message}")
    if detail:
        for line in detail.strip().splitlines():
            print(f"           {line}")

    findings.append({
        "severity": severity,
        "category": category,
        "message": message,
        "detail": detail,
        "timestamp": datetime.datetime.now().isoformat(),
    })


def run(cmd: list[str], timeout: int = 10) -> str:
    """Run a command and return stdout, ignoring errors."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""


# ══════════════════════════════════════════════
#  MODULE 1 – User Privilege Analysis
# ══════════════════════════════════════════════
def analyze_user_privileges() -> None:
    print(f"\n{BOLD}{'─'*60}")
    print(f"  MODULE 1 · User Privilege Analysis")
    print(f"{'─'*60}{RESET}")

    if IS_WINDOWS:
        _user_privileges_windows()
    else:
        _user_privileges_linux()


def _user_privileges_linux() -> None:
    import pwd, grp

    uid  = os.getuid()
    gid  = os.getgid()
    user = os.environ.get("USER", pwd.getpwuid(uid).pw_name)

    log("INFO", "User", f"Running as: {user}  (uid={uid}, gid={gid})")

    # Root check
    if uid == 0:
        log("HIGH", "User", "Process is running as root (uid=0)!")

    # sudo group membership
    groups = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]
    if "sudo" in groups or "wheel" in groups:
        log("MEDIUM", "User", f"{user} belongs to privileged groups: {groups}")
    else:
        log("INFO", "User", f"Group memberships: {groups}")

    # sudo rights
    sudo_out = run(["sudo", "-l", "-n"])
    if sudo_out:
        if "(ALL)" in sudo_out or "NOPASSWD" in sudo_out:
            log("HIGH", "User", "Unrestricted or NOPASSWD sudo rights detected!", sudo_out[:400])
        else:
            log("MEDIUM", "User", "Some sudo rights found.", sudo_out[:400])

    # SUID binaries
    suid_bins = run(["find", "/", "-perm", "-4000", "-type", "f",
                     "-not", "-path", "/proc/*"], timeout=30)
    known_suid = {"/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
                  "/bin/su", "/usr/bin/newgrp"}
    unusual = [b for b in suid_bins.splitlines() if b not in known_suid]
    if unusual:
        log("HIGH", "User", f"{len(unusual)} unusual SUID binaries found!",
            "\n".join(unusual[:20]))
    else:
        log("INFO", "User", "No unusual SUID binaries detected.")

    # Capabilities
    getcap = run(["getcap", "-r", "/usr/bin", "/usr/sbin", "/bin", "/sbin"])
    if getcap:
        log("MEDIUM", "User", "Linux capabilities found on binaries:", getcap[:400])


def _user_privileges_windows() -> None:
    whoami  = run(["whoami"])
    groups  = run(["whoami", "/groups"])
    privs   = run(["whoami", "/priv"])

    log("INFO", "User", f"Current user: {whoami}")

    if "S-1-5-32-544" in groups or "Administrators" in groups:
        log("HIGH", "User", "Current user is a member of the Administrators group!")
    if "SeDebugPrivilege" in privs and "Enabled" in privs:
        log("HIGH", "User", "SeDebugPrivilege is ENABLED – allows reading/writing any process memory!")
    if "SeImpersonatePrivilege" in privs and "Enabled" in privs:
        log("HIGH", "User", "SeImpersonatePrivilege ENABLED – token impersonation attacks possible!")

    log("INFO", "User", "Token privileges summary:", privs[:600])


# ══════════════════════════════════════════════
#  MODULE 2 – File & Directory Permissions
# ══════════════════════════════════════════════
def analyze_file_permissions() -> None:
    print(f"\n{BOLD}{'─'*60}")
    print(f"  MODULE 2 · File & Directory Permissions")
    print(f"{'─'*60}{RESET}")

    if IS_WINDOWS:
        _file_permissions_windows()
    else:
        _file_permissions_linux()


def _file_permissions_linux() -> None:
    CRITICAL_FILES = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/crontab", "/etc/ssh/sshd_config",
        "/root", "/etc/cron.d", "/var/spool/cron",
    ]

    for path in CRITICAL_FILES:
        p = Path(path)
        if not p.exists():
            continue
        try:
            s = p.stat()
            mode = stat.filemode(s.st_mode)
            owner_uid = s.st_uid

            # World-writable?
            if s.st_mode & stat.S_IWOTH:
                log("HIGH", "Permissions",
                    f"World-writable path detected: {path}  ({mode})")
            # Group-writable on sensitive files?
            elif s.st_mode & stat.S_IWGRP and path in ("/etc/passwd", "/etc/shadow", "/etc/sudoers"):
                log("MEDIUM", "Permissions",
                    f"Group-writable sensitive file: {path}  ({mode})")
            # /etc/shadow readable by non-root?
            elif path == "/etc/shadow" and os.access(path, os.R_OK) and os.getuid() != 0:
                log("HIGH", "Permissions", "/etc/shadow is readable by current user!")
            else:
                log("INFO", "Permissions", f"{path} → {mode}  uid={owner_uid}")
        except PermissionError:
            log("INFO", "Permissions", f"{path} → (permission denied, expected)")

    # World-writable dirs in PATH
    path_env = os.environ.get("PATH", "").split(":")
    for d in path_env:
        try:
            s = Path(d).stat()
            if s.st_mode & stat.S_IWOTH:
                log("HIGH", "Permissions",
                    f"World-writable directory in PATH: {d}  – PATH hijack risk!")
        except Exception:
            pass


def _file_permissions_windows() -> None:
    SENSITIVE_PATHS = [
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\ProgramData",
    ]
    for path in SENSITIVE_PATHS:
        p = Path(path)
        if not p.exists():
            continue
        acl = run(["icacls", path])
        if "Everyone:(F)" in acl or "Everyone:(W)" in acl:
            log("HIGH", "Permissions",
                f"Everyone has write/full-control on: {path}")
        elif "BUILTIN\\Users:(W)" in acl or "BUILTIN\\Users:(F)" in acl:
            log("MEDIUM", "Permissions",
                f"Authenticated Users can write to: {path}", acl[:300])
        else:
            log("INFO", "Permissions", f"{path} – permissions appear appropriate.")

    # Unquoted service paths
    services_out = run(
        ["wmic", "service", "get", "name,pathname,startmode", "/format:csv"],
        timeout=20
    )
    for line in services_out.splitlines():
        m = re.search(r',([A-Za-z]:\\.+\.exe)', line)
        if m:
            path_val = m.group(1)
            if " " in path_val and not path_val.startswith('"'):
                log("HIGH", "Permissions",
                    f"Unquoted service path: {path_val}")


# ══════════════════════════════════════════════
#  MODULE 3 – Process Analysis
# ══════════════════════════════════════════════
def analyze_processes() -> None:
    print(f"\n{BOLD}{'─'*60}")
    print(f"  MODULE 3 · Process Analysis")
    print(f"{'─'*60}{RESET}")

    if IS_WINDOWS:
        _processes_windows()
    else:
        _processes_linux()


def _processes_linux() -> None:
    import pwd

    proc_dir = Path("/proc")
    elevated = []

    for pid_path in proc_dir.iterdir():
        if not pid_path.name.isdigit():
            continue
        try:
            status_path = pid_path / "status"
            cmdline_path = pid_path / "cmdline"
            status = status_path.read_text()
            cmdline = cmdline_path.read_text().replace("\x00", " ").strip()

            uid_match = re.search(r"Uid:\s+(\d+)\s+(\d+)", status)
            if not uid_match:
                continue
            ruid, euid = int(uid_match.group(1)), int(uid_match.group(2))

            # Effective UID = 0 while real UID ≠ 0  →  privilege escalation indicator
            if euid == 0 and ruid != 0:
                try:
                    owner = pwd.getpwuid(ruid).pw_name
                except KeyError:
                    owner = str(ruid)
                name_m = re.search(r"Name:\s+(\S+)", status)
                name = name_m.group(1) if name_m else "unknown"
                elevated.append(f"PID {pid_path.name:>6}  name={name:<20} ruid={owner}  euid=root  cmd={cmdline[:60]}")
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue

    if elevated:
        log("HIGH", "Processes",
            f"{len(elevated)} processes with elevated effective UID detected!",
            "\n".join(elevated[:15]))
    else:
        log("INFO", "Processes", "No unexpected privilege-escalated processes found.")

    # Cron jobs running as root
    crontabs = run(["cat", "/etc/crontab"])
    root_crons = [l for l in crontabs.splitlines()
                  if "root" in l and not l.startswith("#")]
    if root_crons:
        log("MEDIUM", "Processes",
            f"{len(root_crons)} root cron jobs found – verify scripts are not world-writable.",
            "\n".join(root_crons[:10]))


def _processes_windows() -> None:
    tasklist = run(["tasklist", "/v", "/fo", "csv"])
    system_procs = [l for l in tasklist.splitlines() if "SYSTEM" in l]
    if system_procs:
        log("INFO", "Processes",
            f"{len(system_procs)} processes running as SYSTEM (normal, listing sample):",
            "\n".join(system_procs[:8]))

    # Services with weak permissions (sc sdshow)
    sc_query = run(["sc", "query", "type=", "all", "state=", "all"], timeout=20)
    service_names = re.findall(r"SERVICE_NAME:\s+(\S+)", sc_query)
    vuln_services = []
    for svc in service_names[:40]:   # limit scan time
        sd = run(["sc", "sdshow", svc])
        if "D:(A;;CCLCSWRPWPDTLOCRRC;;;WD)" in sd:  # Everyone has write
            vuln_services.append(svc)
    if vuln_services:
        log("HIGH", "Processes",
            "Services with Everyone-writable security descriptors!",
            "\n".join(vuln_services))
    else:
        log("INFO", "Processes", "No obviously vulnerable service ACLs found.")


# ══════════════════════════════════════════════
#  MODULE 4 – Registry Analysis (Windows only)
# ══════════════════════════════════════════════
def analyze_registry() -> None:
    print(f"\n{BOLD}{'─'*60}")
    print(f"  MODULE 4 · Registry Analysis")
    print(f"{'─'*60}{RESET}")

    if not IS_WINDOWS:
        log("INFO", "Registry", "Registry analysis skipped – Linux/macOS platform.")
        return

    try:
        import winreg
    except ImportError:
        log("INFO", "Registry", "winreg module unavailable.")
        return

    AUTORUN_KEYS = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    for hive, subkey in AUTORUN_KEYS:
        try:
            key = winreg.OpenKey(hive, subkey)
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    path_lower = str(data).lower()
                    suspicious = any(k in path_lower for k in
                                     ["temp", "appdata", "programdata", "public", "%"])
                    sev = "HIGH" if suspicious else "INFO"
                    log(sev, "Registry",
                        f"Autorun entry: {name}", f"Value: {data}")
                    i += 1
                except OSError:
                    break
        except PermissionError:
            log("INFO", "Registry", f"Access denied to {subkey}")
        except FileNotFoundError:
            pass

    # AlwaysInstallElevated
    def check_aie(hive, hive_name):
        try:
            key = winreg.OpenKey(hive,
                r"SOFTWARE\Policies\Microsoft\Windows\Installer")
            val, _ = winreg.QueryValueEx(key, "AlwaysInstallElevated")
            if val == 1:
                log("HIGH", "Registry",
                    f"AlwaysInstallElevated=1 in {hive_name} – MSI privilege escalation possible!")
        except (FileNotFoundError, OSError):
            pass

    check_aie(winreg.HKEY_LOCAL_MACHINE, "HKLM")
    check_aie(winreg.HKEY_CURRENT_USER,  "HKCU")


# ══════════════════════════════════════════════
#  MODULE 5 – Log Analysis
# ══════════════════════════════════════════════
def analyze_logs() -> None:
    print(f"\n{BOLD}{'─'*60}")
    print(f"  MODULE 5 · Log Analysis")
    print(f"{'─'*60}{RESET}")

    if IS_WINDOWS:
        _logs_windows()
    else:
        _logs_linux()


def _logs_linux() -> None:
    LOG_PATTERNS = {
        "sudo abuse / failed auth":
            r"(sudo.*incorrect password|authentication failure|FAILED su)",
        "su / privilege switch":
            r"(session opened for user root|su\[.*\] \+ )",
        "SSH brute-force indicators":
            r"(Failed password|Invalid user|maximum authentication attempts)",
        "Cron privilege execution":
            r"(CRON.*\(root\) CMD)",
    }

    LOG_FILES = [
        "/var/log/auth.log",   # Debian/Ubuntu
        "/var/log/secure",     # RHEL/CentOS
        "/var/log/syslog",
        "/var/log/messages",
    ]

    found_any = False
    for lf in LOG_FILES:
        p = Path(lf)
        if not p.exists() or not os.access(lf, os.R_OK):
            continue
        try:
            lines = p.read_text(errors="replace").splitlines()
            recent = lines[-2000:]  # last ~2000 lines
            for label, pattern in LOG_PATTERNS.items():
                matches = [l for l in recent if re.search(pattern, l, re.IGNORECASE)]
                if matches:
                    found_any = True
                    sev = "HIGH" if "abuse" in label or "brute" in label else "MEDIUM"
                    log(sev, "Logs",
                        f"{len(matches)} log entries matched «{label}» in {lf}",
                        "\n".join(matches[-5:]))
        except Exception as exc:
            log("INFO", "Logs", f"Could not read {lf}: {exc}")

    if not found_any:
        log("INFO", "Logs", "No suspicious privilege-escalation indicators in logs.")


def _logs_windows() -> None:
    # Query Windows Security event log for relevant event IDs
    EVENTS = {
        "4672": "Special privileges assigned (admin logon)",
        "4648": "Explicit credentials logon attempt",
        "4728": "User added to privileged group",
        "4732": "User added to local Administrators",
        "7045": "New service installed",
    }
    for eid, desc in EVENTS.items():
        out = run([
            "wevtutil", "qe", "Security",
            f"/q:*[System[EventID={eid}]]",
            "/c:5", "/rd:true", "/f:text"
        ], timeout=15)
        if out:
            log("MEDIUM", "Logs", f"EventID {eid} – {desc}  (last 5 occurrences):", out[:400])
        else:
            log("INFO", "Logs", f"EventID {eid} – {desc}: no recent occurrences.")


# ══════════════════════════════════════════════
#  Report Generation
# ══════════════════════════════════════════════
def generate_report(output_file: str | None) -> None:
    print(f"\n{BOLD}{'═'*60}")
    print(f"  SCAN SUMMARY")
    print(f"{'═'*60}{RESET}")

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"  {RED}{BOLD}HIGH  : {counts['HIGH']:>3}{RESET}")
    print(f"  {YELLOW}{BOLD}MEDIUM: {counts['MEDIUM']:>3}{RESET}")
    print(f"  {GREEN}{BOLD}LOW   : {counts['LOW']:>3}{RESET}")
    print(f"  {CYAN}INFO  : {counts['INFO']:>3}{RESET}")
    print()

    if output_file:
        report = {
            "scan_date": datetime.datetime.now().isoformat(),
            "platform": platform.platform(),
            "summary": counts,
            "findings": findings,
        }
        with open(output_file, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"  {GREEN}Report saved → {output_file}{RESET}\n")


# ══════════════════════════════════════════════
#  Entry Point
# ══════════════════════════════════════════════
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Local Privilege Escalation Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE",
        help="Save JSON report to FILE (e.g. report.json)"
    )
    parser.add_argument(
        "--modules", "-m", nargs="+",
        choices=["user", "files", "processes", "registry", "logs"],
        default=["user", "files", "processes", "registry", "logs"],
        help="Select specific modules to run (default: all)"
    )
    args = parser.parse_args()

    banner()

    module_map = {
        "user":      analyze_user_privileges,
        "files":     analyze_file_permissions,
        "processes": analyze_processes,
        "registry":  analyze_registry,
        "logs":      analyze_logs,
    }

    for mod in args.modules:
        try:
            module_map[mod]()
        except Exception as exc:
            log("INFO", mod.capitalize(), f"Module error: {exc}")

    generate_report(args.output)


if __name__ == "__main__":
    main()
