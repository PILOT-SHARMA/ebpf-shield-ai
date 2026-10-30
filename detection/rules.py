"""
rules.py — Rule-based threat detection engine.
Owner: Arpit Sharma (ML / security)

Each rule inspects a normalized event and returns (is_match, severity, reason).
Rules are based on well-known container escape and attack indicators.
"""

from typing import Tuple, Optional


# ──────────────────────────────────────────────
# Rule definitions
# ──────────────────────────────────────────────

RULES = []


def rule(rule_id: str, severity: str):
    """Decorator to register a detection rule."""
    def decorator(fn):
        fn.rule_id = rule_id
        fn.severity = severity
        RULES.append(fn)
        return fn
    return decorator


@rule("R001", "critical")
def detect_container_escape_tools(event: dict) -> Tuple[bool, str]:
    """Detect known container escape tools being executed."""
    escape_tools = [
        "nsenter", "unshare", "chroot", "pivot_root",
        "runc", "ctr", "crictl", "docker"
    ]
    exe = event.get("executable", "").lower()
    exe_basename = exe.rsplit("/", 1)[-1] if "/" in exe else exe
    if exe_basename in escape_tools:
        return True, f"Container escape tool detected: {exe_basename}"
    return False, ""


@rule("R002", "high")
def detect_sensitive_file_access(event: dict) -> Tuple[bool, str]:
    """Detect access to sensitive system files."""
    sensitive_paths = [
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        "/proc/self/ns/", "/proc/1/", "/var/run/docker.sock",
        "/run/containerd/", "/var/run/secrets/kubernetes.io",
        "/root/.ssh/", "/root/.kube/config"
    ]
    args = event.get("args", "").lower()
    exe = event.get("executable", "").lower()
    target = args + " " + exe
    for path in sensitive_paths:
        if path.lower() in target:
            return True, f"Sensitive file access: {path}"
    return False, ""


@rule("R003", "critical")
def detect_reverse_shell(event: dict) -> Tuple[bool, str]:
    """Detect common reverse shell patterns."""
    shell_indicators = [
        "bash -i >& /dev/tcp/",
        "/dev/tcp/",
        "nc -e /bin/",
        "ncat -e",
        "python -c 'import socket,subprocess",
        "python3 -c 'import socket",
        "perl -e 'use Socket",
        "mkfifo /tmp/",
        "0<&196;exec 196<>/dev/tcp/",
    ]
    args = event.get("args", "")
    for pattern in shell_indicators:
        if pattern in args:
            return True, f"Reverse shell pattern detected: {pattern[:40]}..."
    return False, ""


@rule("R004", "high")
def detect_privilege_escalation(event: dict) -> Tuple[bool, str]:
    """Detect privilege escalation attempts."""
    priv_tools = ["sudo", "su", "pkexec", "doas"]
    exe = event.get("executable", "").lower()
    exe_basename = exe.rsplit("/", 1)[-1] if "/" in exe else exe
    if exe_basename in priv_tools:
        # Check if this is running inside a container (non-empty container_id)
        if event.get("container_id", ""):
            return True, f"Privilege escalation in container: {exe_basename}"
    return False, ""


@rule("R005", "medium")
def detect_crypto_mining(event: dict) -> Tuple[bool, str]:
    """Detect potential cryptocurrency mining activity."""
    mining_indicators = [
        "xmrig", "minerd", "cpuminer", "stratum+tcp://",
        "stratum+ssl://", "nicehash", "minergate",
        "--donate-level", "cryptonight"
    ]
    args = (event.get("args", "") + " " + event.get("executable", "")).lower()
    for indicator in mining_indicators:
        if indicator in args:
            return True, f"Cryptocurrency mining indicator: {indicator}"
    return False, ""


@rule("R006", "high")
def detect_suspicious_network(event: dict) -> Tuple[bool, str]:
    """Detect suspicious outbound network connections."""
    if event.get("event_type") != "net_connect":
        return False, ""
    args = event.get("args", "")
    # Unusual ports from containers
    suspicious_ports = ["4444", "5555", "6666", "1337", "31337", "9001"]
    for port in suspicious_ports:
        if f":{port}" in args:
            return True, f"Suspicious outbound connection to port {port}"
    return False, ""


@rule("R007", "medium")
def detect_reconnaissance(event: dict) -> Tuple[bool, str]:
    """Detect reconnaissance commands inside containers."""
    recon_tools = [
        "nmap", "masscan", "zmap", "curl", "wget",
        "whoami", "id", "uname", "hostname", "ifconfig",
        "ip addr", "cat /proc/", "ls /proc/"
    ]
    exe = event.get("executable", "").lower()
    args = event.get("args", "").lower()
    combined = exe + " " + args
    if event.get("container_id", ""):
        for tool in recon_tools:
            if tool in combined:
                return True, f"Reconnaissance in container: {tool}"
    return False, ""


# ──────────────────────────────────────────────
# Engine
# ──────────────────────────────────────────────

def evaluate_rules(event: dict) -> dict:
    """
    Run all rules against an event.
    Returns the highest-severity match, or no match.
    """
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    best_match = None
    best_rank = 0

    for rule_fn in RULES:
        try:
            matched, reason = rule_fn(event)
            if matched:
                rank = severity_rank.get(rule_fn.severity, 0)
                if rank > best_rank:
                    best_rank = rank
                    best_match = {
                        "rule_id": rule_fn.rule_id,
                        "severity": rule_fn.severity,
                        "reason": reason,
                        "score": rank / 4.0,  # normalize to 0-1
                    }
        except Exception:
            continue

    if best_match:
        return best_match

    return {
        "rule_id": "",
        "severity": "none",
        "reason": "",
        "score": 0.0,
    }
