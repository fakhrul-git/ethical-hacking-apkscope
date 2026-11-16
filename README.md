# APKScope

**Android Manifest Security Analyzer**

## Description
APKScope is an original ethical hacking tool for the Mobile Application Attack category. It performs static analysis of Android APK files, focusing on security weaknesses in AndroidManifest.xml. The APK is never installed or executed.

## Attack Category
Mobile Application Attack

## Attack Lifecycle Mapping
- **Reconnaissance**: Collect package info, permissions, SDK versions.
- **Enumeration**: Identify exported components.
- **Vulnerability Assessment**: Flag insecure manifest settings (debuggable, allowBackup, cleartext, etc.).
- **Reporting**: Local JSON and text reports with severity levels.

## Installation
```bash
git clone <your-repo-url>
cd apkscope
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
chmod +x apkscope.py
```

## Usage
```bash
python3 apkscope.py path/to/app.apk
python3 apkscope.py path/to/app.apk -o ./my_reports
```

## Ethical Considerations
Static analysis only. Requires confirmation that you own the APK or have authorization. Includes legal disclaimer and kill switch.

## Rules of Engagement (RoE)
- **Authorized Scope**: Only APKs you own or have explicit permission to analyze.
- **Permitted Techniques**: Static manifest analysis only.
- **Prohibited Actions**: No installation, execution, modification, or exploitation of the APK. No analysis of unauthorized APKs.
- **Emergency Stop**: Ctrl+C.

## Responsible Disclosure
If analyzing a third-party app with permission, report findings privately to the developer.

## Legal Disclaimer
References Computer Crimes Act 1997 (Malaysia). Unauthorized analysis may be illegal.

## Limitations
- Requires androguard.
- Focuses on manifest-level issues only.
- Some exported component detection is basic.
- Educational use.

## License
MIT

## Output
JSON and text reports saved in the output directory.
