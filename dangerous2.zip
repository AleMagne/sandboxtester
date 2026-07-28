"""
mitre_eicar_sandbox_test.py

Safe MITRE ATT&CK-oriented sandbox validation using the EICAR anti-malware test string.

MITRE mapping:
- T1059  Command and Scripting Interpreter
         Python creates an EICAR test file in a temporary directory.

- T1204  User Execution
         Read-only access to the EICAR file. No execution.

- T1105  Ingress Tool Transfer
         Optional download from the official EICAR HTTPS URL only.
         Disabled by default.

- T1027  Obfuscated Files or Information
         Creates a benign, non-encrypted ZIP containing the EICAR file.
         No obfuscation, no encryption, no password.

- T1486  Data Encrypted for Impact
         Not implemented by design. No encryption is performed.

Safety constraints:
- No payload execution.
- No persistence.
- No privilege escalation.
- No lateral movement.
- No ransomware behavior.
- No encryption of user data.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict


VWxWc1JGRldTbVpWTVZKVFUxVTFTQT09 = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}"
    "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

Vm14a05GWXlUWGhUYTJSVFlrZFNWVmxzV25kVk1XeHlXa1JTVjJKR1ducFdNbk14VlZaV1ZVMUVhejA9 = VWxWc1JGRldTbVpWTVZKVFUxVTFTQT09.encode("ascii")

T0ZGSUNJQUxfRUlDQVJfVVJM = "https://secure.eicar.org/eicar.com.txt"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_or_none(path: Path) -> str | None:
    try:
        h = hashlib.sha256()

        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)

        return h.hexdigest()

    except Exception:
        return None


def record_step(
    report: Dict[str, Any],
    technique: str,
    step: str,
    status: str,
    detail: str,
    path: Path | None = None,
) -> None:
    item: Dict[str, Any] = {
        "timestamp_utc": utc_now(),
        "technique": technique,
        "step": step,
        "status": status,
        "detail": detail,
    }

    if path is not None:
        item["path"] = str(path)
        item["exists_after_step"] = path.exists()
        item["sha256_after_step"] = sha256_or_none(path) if path.exists() else None

    report["steps"].append(item)

    V1d4b1QySm5QVDA9 = f"[{status}] {technique} | {step} | {detail}"
    if path:
        V1d4b1QySm5QVDA9 += f" | {path}"

    print(V1d4b1QySm5QVDA9)


def WTNKbFlYUmxYMlZwWTJGeVgyWnBiR1U9(workdir: Path, report: Dict[str, Any]) -> Path:
    """
    T1059 - Command and Scripting Interpreter

    Safe simulation:
    Python writes the EICAR test file into a temporary directory.
    """

    V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09 = workdir / "eicar_test.com.txt"

    try:
        V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09.write_bytes(Vm14a05GWXlUWGhUYTJSVFlrZFNWVmxzV25kVk1XeHlXa1JTVjJKR1ducFdNbk14VlZaV1ZVMUVhejA9)

        record_step(
            report=report,
            technique="T1059",
            step="WTNKbFlYUmxYMlZwWTJGeVgyWnBiR1U9",
            status="OK",
            detail="Created EICAR test file via Python in temporary directory.",
            path=V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09,
        )

    except Exception as exc:
        record_step(
            report=report,
            technique="T1059",
            step="WTNKbFlYUmxYMlZwWTJGeVgyWnBiR1U9",
            status="BLOCKED_OR_FAILED",
            detail=(
                "Could not create EICAR file. "
                "Security control may have blocked or quarantined it. "
                f"Error: {type(exc).__name__}: {exc}"
            ),
            path=V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09,
        )

    return V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09


def Y21WaFpGOXZibXg1WDJGalkyVnpjdz09(V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09: Path, report: Dict[str, Any]) -> None:
    """
    T1204 - User Execution

    Safe simulation:
    Read-only access to the file.
    No execution is attempted.
    """

    try:
        with V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09.open("rb") as f:
            data = f.read()

        if data == Vm14a05GWXlUWGhUYTJSVFlrZFNWVmxzV25kVk1XeHlXa1JTVjJKR1ducFdNbk14VlZaV1ZVMUVhejA9:
            status = "OK"
            detail = "Read-only access completed. No execution attempted."
        else:
            status = "UNEXPECTED_CONTENT"
            detail = (
                "Read-only access completed, but content differs from expected "
                f"EICAR bytes. Length={len(data)}"
            )

        record_step(
            report=report,
            technique="T1204",
            step="Y21WaFpGOXZibXg1WDJGalkyVnpjdz09",
            status=status,
            detail=detail,
            path=V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09,
        )

    except Exception as exc:
        record_step(
            report=report,
            technique="T1204",
            step="Y21WaFpGOXZibXg1WDJGalkyVnpjdz09",
            status="BLOCKED_OR_FAILED",
            detail=(
                "Could not read EICAR file. "
                "On-access scanning may have blocked or quarantined it. "
                f"Error: {type(exc).__name__}: {exc}"
            ),
            path=V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09,
        )


def YjNCMGFXOXVZV3hmYjJabWFXTnBZV3hmWkc5M2JteHZZV1E9(
    workdir: Path,
    report: Dict[str, Any],
    timeout: int = 15,
) -> Path:
    """
    T1105 - Ingress Tool Transfer

    Safe simulation:
    Optional download from official EICAR HTTPS URL only.

    This is disabled by default and only runs with:
        --download-official
    """

    download_path = workdir / "eicar_official_download.com.txt"

    try:
        request = urllib.request.Request(
            T0ZGSUNJQUxfRUlDQVJfVVJM,
            headers={
                "User-Agent": "Safe-EICAR-Sandbox-Validation/1.0"
            },
        )

        with urllib.request.urlopen(request, timeout=timeout) as response:
            content = response.read()

        download_path.write_bytes(content)

        if content == Vm14a05GWXlUWGhUYTJSVFlrZFNWVmxzV25kVk1XeHlXa1JTVjJKR1ducFdNbk14VlZaV1ZVMUVhejA9:
            status = "OK"
            detail = f"Downloaded EICAR from official HTTPS URL: {T0ZGSUNJQUxfRUlDQVJfVVJM}"
        else:
            status = "UNEXPECTED_CONTENT"
            detail = (
                "Downloaded content from official EICAR URL, "
                "but it does not match expected EICAR bytes."
            )

        record_step(
            report=report,
            technique="T1105",
            step="download_official_eicar",
            status=status,
            detail=detail,
            path=download_path,
        )

    except urllib.error.URLError as exc:
        record_step(
            report=report,
            technique="T1105",
            step="download_official_eicar",
            status="BLOCKED_OR_FAILED",
            detail=(
                "Download blocked or failed. "
                "Web protection, proxy, DNS filtering, or EDR may have blocked it. "
                f"Error: {type(exc).__name__}: {exc}"
            ),
            path=download_path,
        )

    except Exception as exc:
        record_step(
            report=report,
            technique="T1105",
            step="download_official_eicar",
            status="BLOCKED_OR_FAILED",
            detail=(
                "Download or write failed. "
                f"Error: {type(exc).__name__}: {exc}"
            ),
            path=download_path,
        )

    return download_path


def Y3JlYXRlX25vbl9lbmNyeXB0ZWRfemlw(
    V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09: Path,
    workdir: Path,
    report: Dict[str, Any],
) -> Path:
    """
    T1027 - Obfuscated Files or Information

    Safe simulation:
    Creates a standard non-encrypted ZIP containing the EICAR file.

    Important:
    This does NOT perform real obfuscation.
    It only validates archive scanning and content inspection.
    """

    ZW1sd1gzQmhkR2c9 = workdir / "eicar_test_plain_not_encrypted.zip"

    try:
        if not V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09.exists():
            raise FileNotFoundError(
                f"Source EICAR file not found. It may have been quarantined: {V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09}"
            )

        with zipfile.ZipFile(
            ZW1sd1gzQmhkR2c9,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
        ) as zf:
            zf.write(
                V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09,
                arcname="eicar_test.com.txt",
            )

        record_step(
            report=report,
            technique="T1027",
            step="create_plain_zip",
            status="OK",
            detail=(
                "Created benign, non-encrypted ZIP containing EICAR. "
                "No password, no encryption, no obfuscation."
            ),
            path=ZW1sd1gzQmhkR2c9,
        )

    except Exception as exc:
        record_step(
            report=report,
            technique="T1027",
            step="create_plain_zip",
            status="BLOCKED_OR_FAILED",
            detail=(
                "Could not create ZIP. "
                "Archive scanning or previous quarantine may have interfered. "
                f"Error: {type(exc).__name__}: {exc}"
            ),
            path=ZW1sd1gzQmhkR2c9,
        )

    return ZW1sd1gzQmhkR2c9


def explicitly_skip_t1486(report: Dict[str, Any]) -> None:
    """
    T1486 - Data Encrypted for Impact

    Not implemented by design.

    No encryption is performed.
    No files are modified for impact.
    No ransomware-like behavior is simulated.
    """

    record_step(
        report=report,
        technique="T1486",
        step="not_implemented",
        status="SKIPPED_BY_DESIGN",
        detail=(
            "No encryption, no destructive behavior, no ransomware simulation. "
            "Validate backup, restore, immutable backup, and anti-ransomware controls "
            "separately in a controlled lab."
        ),
    )


def cleanup(
    workdir: Path,
    report: Dict[str, Any],
    keep_artifacts: bool,
) -> None:
    if keep_artifacts:
        record_step(
            report=report,
            technique="CLEANUP",
            step="keep_artifacts",
            status="OK",
            detail=f"Artifacts retained in: {workdir}",
            path=workdir,
        )
        return

    try:
        shutil.rmtree(workdir, ignore_errors=True)

        record_step(
            report=report,
            technique="CLEANUP",
            step="remove_temp_dir",
            status="OK",
            detail=f"Temporary directory removed: {workdir}",
        )

    except Exception as exc:
        record_step(
            report=report,
            technique="CLEANUP",
            step="remove_temp_dir",
            status="FAILED",
            detail=f"Cleanup failed: {type(exc).__name__}: {exc}",
        )


def build_report(
    workdir: Path,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    return {
        "test_name": "Safe MITRE ATT&CK EICAR Sandbox Validation",
        "start_time_utc": utc_now(),
        "host": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python_version": sys.version.split()[0],
            "pid": os.getpid(),
            "cwd": os.getcwd(),
        },
        "workdir": str(workdir),
        "network_download_enabled": bool(args.download_official),
        "keep_artifacts": bool(args.keep_artifacts),
        "mitre_mapping": [
            {
                "id": "T1059",
                "technique": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "safe_simulation": "Python creates EICAR file in temporary directory",
                "expected_detection": (
                    "Alert/quarantine on EICAR or telemetry for Python process"
                ),
                "validated_control": "Real-time AV, EDR process telemetry",
                "risk_real": "Abuse of interpreters to execute commands or payloads",
                "remediation": (
                    "Command-line logging, application control, monitoring of "
                    "anomalous interpreter usage"
                ),
            },
            {
                "id": "T1204",
                "technique": "User Execution",
                "tactic": "Execution",
                "safe_simulation": "Read-only access to EICAR; no execution",
                "expected_detection": "On-access detection or file block",
                "validated_control": "On-access scanning, user-driven detection",
                "risk_real": "User tricked into opening a malicious file",
                "remediation": (
                    "Security awareness, attachment scanning, sandboxing, "
                    "blocking of suspicious files"
                ),
            },
            {
                "id": "T1105",
                "technique": "Ingress Tool Transfer",
                "tactic": "Command and Control",
                "safe_simulation": "Optional download from official EICAR source only",
                "expected_detection": "Web/download block or quarantine",
                "validated_control": "Web protection, proxy telemetry, EDR telemetry",
                "risk_real": "Transfer of malicious tools to a compromised host",
                "remediation": (
                    "Source allowlisting, proxy logging, download inspection"
                ),
            },
            {
                "id": "T1027",
                "technique": "Obfuscated Files or Information",
                "tactic": "Stealth",
                "safe_simulation": "Non-encrypted ZIP containing EICAR",
                "expected_detection": "Detection of EICAR inside archive",
                "validated_control": "Archive scanning, content inspection",
                "risk_real": (
                    "Compressed or archived payloads used to reduce visibility"
                ),
                "remediation": (
                    "Enable archive scanning, attachment sandboxing, ZIP policy controls"
                ),
            },
            {
                "id": "T1486",
                "technique": "Data Encrypted for Impact",
                "tactic": "Impact",
                "safe_simulation": "Not implemented; no encryption",
                "expected_detection": "N/A for EICAR-only test",
                "validated_control": (
                    "Backup, restore, anti-ransomware and canary-file controls "
                    "should be tested separately"
                ),
                "risk_real": "Ransomware and data unavailability",
                "remediation": (
                    "Restore testing, immutable backups, behavioral analytics, "
                    "controlled folder access"
                ),
            },
        ],
        "steps": [],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Safe MITRE ATT&CK EICAR sandbox validation. "
            "Writes EICAR test artifacts to a temporary directory."
        )
    )

    parser.add_argument(
        "--download-official",
        action="store_true",
        help=(
            "Enable optional HTTPS download from official EICAR URL. "
            "Disabled by default."
        ),
    )

    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help=(
            "Do not delete the temporary directory at the end. "
            "Useful if AV/EDR does not quarantine the files."
        ),
    )

    parser.add_argument(
        "--report",
        default="mitre_eicar_sandbox_report.json",
        help="Path of the JSON report to write.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    workdir = Path(
        tempfile.mkdtemp(
            prefix="mitre_eicar_sandbox_"
        )
    )

    report = build_report(
        workdir=workdir,
        args=args,
    )

    print("Safe MITRE ATT&CK EICAR sandbox validation")
    print(f"Working directory: {workdir}")
    print(
        "NOTE: AV/EDR may block or quarantine artifacts. "
        "BLOCKED_OR_FAILED can be a valid detection outcome."
    )

    V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09 = WTNKbFlYUmxYMlZwWTJGeVgyWnBiR1U9(
        workdir=workdir,
        report=report,
    )

    Y21WaFpGOXZibXg1WDJGalkyVnpjdz09(
        V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09=V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09,
        report=report,
    )

    if args.download_official:
        YjNCMGFXOXVZV3hmYjJabWFXTnBZV3hmWkc5M2JteHZZV1E9(
            workdir=workdir,
            report=report,
        )
    else:
        record_step(
            report=report,
            technique="T1105",
            step="download_official_eicar",
            status="SKIPPED_BY_DEFAULT",
            detail=(
                "Network download disabled. "
                "Re-run with --download-official to test web/proxy controls "
                "using the official EICAR HTTPS URL only."
            ),
        )

    Y3JlYXRlX25vbl9lbmNyeXB0ZWRfemlw(
        V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09=V2xkc2FsbFlTbVpqUjBZd1lVRTlQUT09,
        workdir=workdir,
        report=report,
    )

    explicitly_skip_t1486(
        report=report,
    )

    report["end_time_utc"] = utc_now()

    report_path = Path(args.report).resolve()

    try:
        report_path.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

        print(f"JSON report written: {report_path}")

    except Exception as exc:
        print(
            f"[FAILED] Could not write JSON report: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )

    cleanup(
        workdir=workdir,
        report=report,
        keep_artifacts=args.keep_artifacts,
    )

    try:
        report_path.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

    except Exception:
        pass

    print("Completed. Review AV/EDR/proxy/SIEM telemetry for expected detections.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
