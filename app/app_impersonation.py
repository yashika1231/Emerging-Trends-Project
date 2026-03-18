"""
Enterprise application impersonation detection module.
Verifies whether files, network traffic, or email communications
claiming to be from known enterprise apps (Zoom, Google Meet,
TeamViewer, Microsoft Teams, Slack, WebEx) are legitimate or
potentially malicious impersonation attempts.
"""
import re
from typing import Dict, List, Optional




APP_PROFILES: Dict[str, Dict] = {
    "zoom": {
        "display_name": "Zoom",
        "legitimate_domains": [
            "zoom.us", "zoom.com", "zoomgov.com", "zoom.ai",
            "zoomcdn.com", "cloudflare.com",
        ],
        "legitimate_sender_patterns": [
            r".*@zoom\.us$", r".*@zoom\.com$", r"no-reply@zoom\.us$",
        ],
        "legitimate_urls": [
            r"https?://([\w-]+\.)?zoom\.us/", r"https?://([\w-]+\.)?zoom\.com/",
        ],
        "legitimate_installer_names": [
            r"^ZoomInstaller\.exe$", r"^Zoom\.pkg$", r"^zoom_.*\.deb$",
            r"^zoom_.*\.rpm$", r"^ZoomInstallerFull\.msi$",
        ],
        "known_network_domains": [
            "zoom.us", "zoom.com", "zoomgov.com", "amazonaws.com",
            "cloudfront.net", "akamaized.net",
        ],
        "known_ports": [443, 8801, 8802],
        "known_processes": ["zoom", "zoom.exe", "zoomit.exe", "cpthost.exe"],
        "certificate_orgs": ["Zoom Video Communications, Inc."],
        "suspicious_impostor_patterns": [
            r"zo+m", r"z00m", r"zooom", r"z0om", r"zroorm",
            r"zoom-meeting", r"zoom.*update", r"zoom.*security",
        ],
    },
    "google_meet": {
        "display_name": "Google Meet",
        "legitimate_domains": [
            "meet.google.com", "google.com", "googleapis.com",
            "gstatic.com", "googleusercontent.com",
        ],
        "legitimate_sender_patterns": [
            r".*@google\.com$", r".*@calendar-notification\.google\.com$",
            r"calendar-notification@google\.com$",
        ],
        "legitimate_urls": [
            r"https?://meet\.google\.com/[a-z]{3}-[a-z]{4}-[a-z]{3}",
            r"https?://([\w-]+\.)?google\.com/",
        ],
        "legitimate_installer_names": [],  # Web-based, no installer
        "known_network_domains": [
            "meet.google.com", "google.com", "googleapis.com",
            "gstatic.com", "googlevideo.com",
        ],
        "known_ports": [443, 19302, 19305],
        "known_processes": [],
        "certificate_orgs": ["Google Trust Services LLC"],
        "suspicious_impostor_patterns": [
            r"go+gle.*meet", r"g00gle.*meet", r"google-meet",
            r"googlemeet.*login", r"meet.*go+gle",
        ],
    },
    "teamviewer": {
        "display_name": "TeamViewer",
        "legitimate_domains": [
            "teamviewer.com", "teamviewer.us",
        ],
        "legitimate_sender_patterns": [
            r".*@teamviewer\.com$",
        ],
        "legitimate_urls": [
            r"https?://([\w-]+\.)?teamviewer\.com/",
        ],
        "legitimate_installer_names": [
            r"^TeamViewer_Setup\.exe$", r"^TeamViewerQS\.exe$",
            r"^TeamViewer\.dmg$", r"^teamviewer.*\.deb$",
            r"^TeamViewer_Setup_x64\.exe$",
        ],
        "known_network_domains": [
            "teamviewer.com", "dyngate.com", "teamviewer.us",
        ],
        "known_ports": [443, 5938],
        "known_processes": ["teamviewer.exe", "teamviewer", "TeamViewer_Service.exe"],
        "certificate_orgs": ["TeamViewer Germany GmbH"],
        "suspicious_impostor_patterns": [
            r"team.?viewer", r"teamview+er", r"t[e3]amvi[e3]w[e3]r",
            r"teamvlewer", r"teamviewer.*update", r"teamviewer.*crack",
        ],
    },
    "microsoft_teams": {
        "display_name": "Microsoft Teams",
        "legitimate_domains": [
            "teams.microsoft.com", "microsoft.com", "live.com",
            "microsoftonline.com", "office.com", "office365.com",
            "sharepoint.com", "skype.com",
        ],
        "legitimate_sender_patterns": [
            r".*@teams\.microsoft\.com$", r".*@microsoft\.com$",
            r".*@email\.teams\.microsoft\.com$", r"noreply@email\.teams\.microsoft\.com$",
        ],
        "legitimate_urls": [
            r"https?://teams\.microsoft\.com/",
            r"https?://([\w-]+\.)?microsoft\.com/",
            r"https?://teams\.live\.com/",
        ],
        "legitimate_installer_names": [
            r"^Teams_windows_x64\.exe$", r"^Teams_windows\.exe$",
            r"^Teams\.msix$", r"^Microsoft_Teams\.dmg$",
            r"^teams_.*\.deb$",
        ],
        "known_network_domains": [
            "teams.microsoft.com", "microsoft.com", "office.com",
            "microsoftonline.com", "skype.com", "live.com",
            "trouter.teams.microsoft.com",
        ],
        "known_ports": [443, 3478, 3479, 3480, 3481],
        "known_processes": ["teams.exe", "ms-teams.exe", "msteams.exe"],
        "certificate_orgs": ["Microsoft Corporation"],
        "suspicious_impostor_patterns": [
            r"micros[o0]ft.*teams", r"microsft.*teams", r"ms-teams.*update",
            r"teams.*micr[o0]s[o0]ft", r"teams.*login",
            r"teams.*verify", r"teams-update",
        ],
    },
    "slack": {
        "display_name": "Slack",
        "legitimate_domains": [
            "slack.com", "slack-edge.com", "slack-msgs.com",
            "slack-imgs.com", "slack-files.com", "slack-core.com",
        ],
        "legitimate_sender_patterns": [
            r".*@slack\.com$", r"no-reply@slack\.com$",
            r"feedback@slack\.com$",
        ],
        "legitimate_urls": [
            r"https?://([\w-]+\.)?slack\.com/",
        ],
        "legitimate_installer_names": [
            r"^SlackSetup\.exe$", r"^Slack\.dmg$",
            r"^slack-desktop-.*\.deb$", r"^slack-.*\.rpm$",
            r"^SlackSetup\.msi$",
        ],
        "known_network_domains": [
            "slack.com", "slack-edge.com", "slack-msgs.com",
            "slack-imgs.com", "wss-primary.slack.com",
        ],
        "known_ports": [443],
        "known_processes": ["slack.exe", "slack"],
        "certificate_orgs": ["Slack Technologies, LLC"],
        "suspicious_impostor_patterns": [
            r"s[l1]ack", r"sl[a@]ck", r"slack.*update", r"slack.*verify",
            r"slack.*login", r"slack-desktop.*crack",
        ],
    },
    "webex": {
        "display_name": "Cisco WebEx",
        "legitimate_domains": [
            "webex.com", "cisco.com", "ciscospark.com",
            "wbx2.com", "webexapis.com",
        ],
        "legitimate_sender_patterns": [
            r".*@webex\.com$", r".*@cisco\.com$",
            r"messenger@webex\.com$",
        ],
        "legitimate_urls": [
            r"https?://([\w-]+\.)?webex\.com/",
            r"https?://([\w-]+\.)?cisco\.com/",
        ],
        "legitimate_installer_names": [
            r"^webexapp\.msi$", r"^Cisco_Webex\.dmg$",
            r"^webex\.deb$", r"^CiscoWebexStart\.exe$",
        ],
        "known_network_domains": [
            "webex.com", "cisco.com", "ciscospark.com",
            "wbx2.com", "webexapis.com", "webexcontent.com",
        ],
        "known_ports": [443, 5004, 9000],
        "known_processes": ["ciscocollabhost.exe", "webexmta.exe", "atmgr.exe"],
        "certificate_orgs": ["Cisco Systems, Inc."],
        "suspicious_impostor_patterns": [
            r"w[e3]b[e3]x", r"web-ex", r"webex.*update",
            r"cisco.*webex.*verify", r"webex.*login",
        ],
    },
}


def get_supported_apps() -> List[Dict[str, str]]:
    """Return a list of supported application profiles."""
    return [
        {"id": app_id, "name": profile["display_name"]}
        for app_id, profile in APP_PROFILES.items()
    ]


def verify_application(
    app_name: str,
    file_name: Optional[str] = None,
    file_hash: Optional[str] = None,
    network_domains: Optional[List[str]] = None,
    email_sender: Optional[str] = None,
    email_urls: Optional[List[str]] = None,
    process_name: Optional[str] = None,
) -> Dict:
    """
    Verify whether the provided artifacts match a known legitimate
    enterprise application or indicate a potential impersonation attack.

    Args:
        app_name: Application to verify against (e.g., 'zoom', 'microsoft_teams')
        file_name: Name of the executable/installer file
        file_hash: SHA-256 hash of the file (for future signature DB)
        network_domains: List of domains the application is connecting to
        email_sender: Sender email address from a notification claiming to be this app
        email_urls: URLs found in an email claiming to be from this app
        process_name: Running process name to verify

    Returns:
        dict with is_legitimate, confidence, risk_level, findings, expected_signatures
    """
    app_key = app_name.lower().replace(" ", "_").replace("-", "_")

    if app_key not in APP_PROFILES:
        return {
            "is_legitimate": None,
            "confidence": 0.0,
            "risk_level": "unknown",
            "app_name": app_name,
            "findings": [f"Application '{app_name}' is not in our verification database."],
            "recommendation": "Manual verification recommended.",
            "expected_signatures": {},
            "checks_performed": [],
        }

    profile = APP_PROFILES[app_key]
    findings: List[str] = []
    suspicious_score = 0
    legitimate_score = 0
    checks_performed: List[Dict] = []

    # ── 1. File name verification ──
    if file_name:
        file_legitimate = False
        for pattern in profile["legitimate_installer_names"]:
            if re.match(pattern, file_name, re.IGNORECASE):
                file_legitimate = True
                break

        if file_legitimate:
            legitimate_score += 20
            checks_performed.append({
                "check": "file_name",
                "result": "pass",
                "detail": f"File name '{file_name}' matches known legitimate installer pattern"
            })
        else:
            # Check for impersonation patterns
            file_lower = file_name.lower()
            is_impostor = False
            for pattern in profile["suspicious_impostor_patterns"]:
                if re.search(pattern, file_lower):
                    is_impostor = True
                    break

            if is_impostor:
                suspicious_score += 30
                findings.append(f"⚠️ File name '{file_name}' matches a known impersonation pattern for {profile['display_name']}")
                checks_performed.append({
                    "check": "file_name",
                    "result": "fail",
                    "detail": f"File name matches impersonation pattern"
                })
            else:
                suspicious_score += 10
                findings.append(f"File name '{file_name}' does not match known legitimate installers for {profile['display_name']}")
                checks_performed.append({
                    "check": "file_name",
                    "result": "warning",
                    "detail": f"File name not recognized as official installer"
                })

        # Check for double extensions (e.g., zoom.pdf.exe)
        if re.search(r'\.\w+\.\w+$', file_name) and re.search(r'\.(exe|bat|cmd|scr|js|vbs|ps1|msi)$', file_name, re.IGNORECASE):
            suspicious_score += 25
            findings.append(f"🚨 Double file extension detected in '{file_name}' — common malware evasion technique")
            checks_performed.append({
                "check": "double_extension",
                "result": "fail",
                "detail": "Double file extension detected"
            })

    # ── 2. Network domain verification ──
    if network_domains:
        unknown_domains = []
        known_count = 0
        for domain in network_domains:
            domain_lower = domain.lower().strip()
            is_known = False
            for legit_domain in profile["known_network_domains"]:
                if domain_lower == legit_domain or domain_lower.endswith("." + legit_domain):
                    is_known = True
                    break
            if is_known:
                known_count += 1
            else:
                unknown_domains.append(domain_lower)

        if known_count > 0:
            legitimate_score += 15
            checks_performed.append({
                "check": "network_domains",
                "result": "pass",
                "detail": f"{known_count}/{len(network_domains)} domains match known legitimate domains"
            })

        if unknown_domains:
            suspicious_score += len(unknown_domains) * 10
            findings.append(
                f"⚠️ Unknown network domains detected: {', '.join(unknown_domains[:5])} — "
                f"legitimate {profile['display_name']} should connect to: {', '.join(profile['known_network_domains'][:5])}"
            )
            checks_performed.append({
                "check": "network_domains_unknown",
                "result": "fail",
                "detail": f"{len(unknown_domains)} unrecognized domain(s)"
            })

    # ── 3. Email sender verification ──
    if email_sender:
        sender_legitimate = False
        for pattern in profile["legitimate_sender_patterns"]:
            if re.match(pattern, email_sender, re.IGNORECASE):
                sender_legitimate = True
                break

        if sender_legitimate:
            legitimate_score += 20
            checks_performed.append({
                "check": "email_sender",
                "result": "pass",
                "detail": f"Sender '{email_sender}' matches known legitimate pattern"
            })
        else:
            sender_domain = ""
            match = re.search(r'@([\w.-]+)', email_sender)
            if match:
                sender_domain = match.group(1).lower()

            domain_is_legit = sender_domain in [d.lower() for d in profile["legitimate_domains"]]

            if domain_is_legit:
                legitimate_score += 10
                checks_performed.append({
                    "check": "email_sender",
                    "result": "warning",
                    "detail": f"Sender domain is legitimate but exact pattern not recognized"
                })
            else:
                suspicious_score += 25
                findings.append(
                    f"⚠️ Sender '{email_sender}' does not match known {profile['display_name']} sender addresses. "
                    f"Expected domains: {', '.join(profile['legitimate_domains'][:3])}"
                )
                checks_performed.append({
                    "check": "email_sender",
                    "result": "fail",
                    "detail": f"Sender does not match legitimate patterns"
                })

    # ── 4. URL verification ──
    if email_urls:
        suspicious_urls = []
        legitimate_urls = []
        for url in email_urls:
            url_legitimate = False
            for pattern in profile["legitimate_urls"]:
                if re.search(pattern, url, re.IGNORECASE):
                    url_legitimate = True
                    break
            if url_legitimate:
                legitimate_urls.append(url)
            else:
                # Check for impersonation in URL
                url_lower = url.lower()
                for pattern in profile["suspicious_impostor_patterns"]:
                    if re.search(pattern, url_lower):
                        suspicious_urls.append(url)
                        break
                else:
                    suspicious_urls.append(url)

        if legitimate_urls:
            legitimate_score += 15
            checks_performed.append({
                "check": "email_urls",
                "result": "pass",
                "detail": f"{len(legitimate_urls)} URL(s) match known legitimate patterns"
            })

        if suspicious_urls:
            suspicious_score += len(suspicious_urls) * 15
            findings.append(
                f"⚠️ Suspicious URLs found: {', '.join(suspicious_urls[:3])} — "
                f"do not match known {profile['display_name']} domains"
            )
            checks_performed.append({
                "check": "email_urls_suspicious",
                "result": "fail",
                "detail": f"{len(suspicious_urls)} URL(s) don't match legitimate patterns"
            })

    # ── 5. Process name verification ──
    if process_name:
        proc_lower = process_name.lower()
        is_known = proc_lower in [p.lower() for p in profile["known_processes"]]

        if is_known:
            legitimate_score += 15
            checks_performed.append({
                "check": "process_name",
                "result": "pass",
                "detail": f"Process '{process_name}' matches known legitimate process"
            })
        else:
            suspicious_score += 15
            findings.append(f"Process '{process_name}' is not a known {profile['display_name']} process. "
                            f"Expected: {', '.join(profile['known_processes'][:3])}")
            checks_performed.append({
                "check": "process_name",
                "result": "fail",
                "detail": f"Process name not recognized"
            })

    # ── Calculate final verdict ──
    total = suspicious_score + legitimate_score
    if total == 0:
        confidence = 0.0
        is_legitimate = None
        risk_level = "unknown"
        recommendation = "Insufficient data to determine legitimacy. Provide more artifacts for analysis."
    elif suspicious_score > legitimate_score:
        confidence = min(suspicious_score / max(total, 1), 0.99)
        is_legitimate = False
        if confidence > 0.7:
            risk_level = "critical"
            recommendation = (
                f"🚨 HIGH RISK: This appears to be a malicious application impersonating {profile['display_name']}. "
                f"Do NOT run this file or click any links. Report to your IT security team immediately."
            )
        elif confidence > 0.4:
            risk_level = "high"
            recommendation = (
                f"⚠️ SUSPICIOUS: Multiple indicators suggest this is not a genuine {profile['display_name']} application. "
                f"Verify through official channels before proceeding."
            )
        else:
            risk_level = "medium"
            recommendation = (
                f"Exercise caution. Some indicators don't match known {profile['display_name']} signatures. "
                f"Download only from official sources."
            )
    else:
        confidence = min(legitimate_score / max(total, 1), 0.99)
        is_legitimate = True
        risk_level = "low"
        recommendation = (
            f"Indicators are consistent with a legitimate {profile['display_name']} application. "
            f"Continue with normal caution."
        )

    if not findings:
        findings.append(f"All checked indicators are consistent with legitimate {profile['display_name']} artifacts.")

    return {
        "is_legitimate": is_legitimate,
        "confidence": round(confidence, 2),
        "risk_level": risk_level,
        "app_name": profile["display_name"],
        "findings": findings,
        "recommendation": recommendation,
        "checks_performed": checks_performed,
        "expected_signatures": {
            "legitimate_domains": profile["legitimate_domains"],
            "legitimate_installers": profile["legitimate_installer_names"],
            "known_network_domains": profile["known_network_domains"],
            "known_ports": profile["known_ports"],
            "certificate_orgs": profile["certificate_orgs"],
        },
    }
