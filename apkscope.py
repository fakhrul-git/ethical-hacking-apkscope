#!/usr/bin/env python3
"""
APKScope - Android Manifest Security Analyzer
Category: Mobile Application Attack
Performs static analysis of AndroidManifest.xml for common security misconfigurations.
"""

import argparse
import json
import os
import signal
import sys
from datetime import datetime

KILL_SWITCH = False

def signal_handler(sig, frame):
    global KILL_SWITCH
    print("\n[!] Kill switch activated. Aborting cleanly...")
    KILL_SWITCH = True
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

DISCLAIMER = """
================================================================================
LEGAL DISCLAIMER - COMPUTER CRIMES ACT 1997 (MALAYSIA)
================================================================================
This tool is for educational and authorized security analysis purposes only.
Analyzing APKs you do not own or have permission to inspect may violate laws,
including the Computer Crimes Act 1997 (Act 563).

This tool only performs static analysis. It never installs, executes, or modifies the APK.
By continuing you confirm you own the APK or have explicit authorization to analyze it.

The authors accept no liability for misuse.
================================================================================
"""

HIGH_RISK_PERMISSIONS = [
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
]

def display_disclaimer():
    print(DISCLAIMER)
    confirm = input("Do you own this APK or have explicit authorization to analyze it? (yes/no): ").strip().lower()
    if confirm not in ("yes", "y"):
        print("[!] Authorization not confirmed. Exiting.")
        sys.exit(1)
    print("[+] Authorization confirmed. Starting static analysis only.\n")

def analyze_apk(apk_path):
    """Analyze APK using androguard."""
    try:
        from androguard.core.apk import APK
    except ImportError:
        print("[-] androguard is not installed.")
        print("    Install it with: pip3 install androguard")
        sys.exit(1)

    if not os.path.isfile(apk_path):
        print(f"[-] File not found: {apk_path}")
        sys.exit(1)

    print(f"[*] Analyzing: {apk_path}")
    try:
        a = APK(apk_path)
    except Exception as e:
        print(f"[-] Failed to parse APK: {e}")
        sys.exit(1)

    findings = []
    report = {
        "apk_path": apk_path,
        "package_name": a.get_package(),
        "app_name": a.get_app_name(),
        "version_name": a.get_androidversion_name(),
        "version_code": a.get_androidversion_code(),
        "min_sdk": a.get_min_sdk_version(),
        "target_sdk": a.get_target_sdk_version(),
        "findings": findings
    }

    # Check debuggable
    if a.is_debuggable():
        findings.append({
            "issue": "android:debuggable=\"true\"",
            "severity": "High",
            "description": "Application is debuggable. Attackers can attach a debugger and inspect runtime behavior."
        })
        print("  [High] debuggable = true")

    # Check allowBackup
    if a.get_attribute_value("application", "allowBackup") != "false":
        findings.append({
            "issue": "android:allowBackup is not false",
            "severity": "Medium",
            "description": "Application data may be backed up via adb backup, potentially exposing sensitive information."
        })
        print("  [Medium] allowBackup is not explicitly false")

    # Check usesCleartextTraffic
    cleartext = a.get_attribute_value("application", "usesCleartextTraffic")
    if cleartext == "true" or (cleartext is None and int(a.get_target_sdk_version() or 0) < 28):
        findings.append({
            "issue": "Cleartext traffic allowed",
            "severity": "Medium",
            "description": "Application may allow unencrypted HTTP traffic."
        })
        print("  [Medium] Cleartext traffic possible")

    # Exported components
    exported_activities = [act for act in a.get_activities() if a.get_attribute_value("activity", "exported", act) == "true" or (a.get_intent_filters("activity", act) and a.get_attribute_value("activity", "exported", act) != "false")]
    # Simpler approach using androguard methods
    activities = a.get_activities()
    services = a.get_services()
    receivers = a.get_receivers()
    providers = a.get_providers()

    exported_count = 0
    for comp_type, components in [("activity", activities), ("service", services), ("receiver", receivers), ("provider", providers)]:
        for comp in components:
            exported = a.get_attribute_value(comp_type, "exported", comp)
            if exported == "true":
                exported_count += 1
                findings.append({
                    "issue": f"Exported {comp_type}: {comp}",
                    "severity": "Medium",
                    "description": f"This {comp_type} is explicitly exported and may be accessible by other applications."
                })

    if exported_count:
        print(f"  [Medium] Found {exported_count} explicitly exported components")

    # Permissions
    permissions = a.get_permissions()
    high_risk = [p for p in permissions if p in HIGH_RISK_PERMISSIONS]
    report["permissions"] = permissions
    report["high_risk_permissions"] = high_risk

    if high_risk:
        findings.append({
            "issue": "High-risk permissions requested",
            "severity": "Medium",
            "description": f"App requests {len(high_risk)} high-risk permissions: {', '.join(high_risk[:5])}{'...' if len(high_risk) > 5 else ''}",
            "permissions": high_risk
        })
        print(f"  [Medium] {len(high_risk)} high-risk permissions")

    # SDK versions
    min_sdk = a.get_min_sdk_version()
    target_sdk = a.get_target_sdk_version()
    if min_sdk and int(min_sdk) < 21:
        findings.append({
            "issue": f"Low minSdkVersion: {min_sdk}",
            "severity": "Low",
            "description": "Supports very old Android versions which may have known security issues."
        })
        print(f"  [Low] minSdkVersion = {min_sdk}")

    if not findings:
        print("  [OK] No major manifest issues detected")

    report["total_findings"] = len(findings)
    return report

def save_report(report, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(output_dir, f"apkscope_report_{timestamp}.json")
    txt_path = os.path.join(output_dir, f"apkscope_report_{timestamp}.txt")

    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    with open(txt_path, "w") as f:
        f.write(f"APKScope Report - {report.get('package_name', 'Unknown')}\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Package: {report.get('package_name')}\n")
        f.write(f"App Name: {report.get('app_name')}\n")
        f.write(f"Version: {report.get('version_name')} ({report.get('version_code')})\n")
        f.write(f"Min SDK: {report.get('min_sdk')} | Target SDK: {report.get('target_sdk')}\n\n")
        f.write(f"Total Findings: {report.get('total_findings', 0)}\n\n")
        for i, finding in enumerate(report.get("findings", []), 1):
            f.write(f"{i}. [{finding['severity']}] {finding['issue']}\n")
            f.write(f"   {finding['description']}\n\n")

    print(f"\n[+] JSON report: {json_path}")
    print(f"[+] Text report: {txt_path}")
    return json_path

def main():
    parser = argparse.ArgumentParser(
        description="APKScope - Android Manifest Security Analyzer (Mobile Application Attack)",
        epilog="Static analysis only. Never installs or executes the APK."
    )
    parser.add_argument("apk", help="Path to the APK file to analyze")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    args = parser.parse_args()

    display_disclaimer()
    report = analyze_apk(args.apk)
    save_report(report, args.output)
    print("\n[!] Analysis complete. Review the local report. Do not misuse this tool.")

if __name__ == "__main__":
    main()
