from typing import Optional, List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

# Silence androguard verbose debug logging to keep service output clean
try:
    from loguru import logger as loguru_logger
    loguru_logger.disable("androguard")
except Exception:
    pass

from androguard.core.apk import APK
from app.services.certificate_service import extract_certificate_fingerprint, extract_certificate_details
from app.services.tlsh_service import calculate_tlsh
from app.core.logging import logger

# Configurable Deterministic Indicator Rules for Android Permissions & Capabilities
INDICATOR_RULES = {
    # Accessibility & Overlays
    'android.permission.BIND_ACCESSIBILITY_SERVICE': {
        "title": "Accessibility Service Abuse Potential",
        "description": "App requests Accessibility Service, frequently abused by malware for keylogging, overlay attacks, or consent injection.",
        "severity": "HIGH",
        "category": "Accessibility",
        "mitre_technique_id": "T1628",
        "weight": 40
    },
    'android.permission.SYSTEM_ALERT_WINDOW': {
        "title": "System Alert Window Requested",
        "description": "App can draw overlays on top of foreground applications, enabling Cloak & Dagger or credential phishing attacks.",
        "severity": "HIGH",
        "category": "Overlay",
        "mitre_technique_id": "T1626",
        "weight": 20
    },

    # SMS & OTP Interception
    'android.permission.SEND_SMS': {
        "title": "SMS Transmission Capability",
        "description": "App can send SMS messages autonomously, commonly leveraged for premium SMS or toll fraud.",
        "severity": "HIGH",
        "category": "SMS Fraud",
        "mitre_technique_id": "T1636",
        "weight": 20
    },
    'android.permission.RECEIVE_SMS': {
        "title": "SMS Interception Potential",
        "description": "App can intercept incoming SMS messages, typically exploited to steal banking OTPs and 2FA tokens.",
        "severity": "HIGH",
        "category": "SMS Fraud",
        "mitre_technique_id": "T1636",
        "weight": 20
    },
    'android.permission.READ_SMS': {
        "title": "SMS Inbox Read Potential",
        "description": "App has access to read stored SMS messages on the device.",
        "severity": "HIGH",
        "category": "SMS Fraud",
        "mitre_technique_id": "T1636",
        "weight": 20
    },

    # Device Admin & Persistence
    'android.permission.BIND_DEVICE_ADMIN': {
        "title": "Device Admin Privileges",
        "description": "App requests device administrator privileges, often used by ransomware to prevent uninstallation.",
        "severity": "CRITICAL",
        "category": "Permission",
        "mitre_technique_id": "T1624",
        "weight": 50
    },
    'android.permission.RECEIVE_BOOT_COMPLETED': {
        "title": "Boot Persistence",
        "description": "App can automatically start components on device boot.",
        "severity": "MEDIUM",
        "category": "Permission",
        "mitre_technique_id": "T1547.001",
        "weight": 10
    },

    # Sideloading & Installation
    'android.permission.REQUEST_INSTALL_PACKAGES': {
        "title": "Arbitrary Package Sideloading",
        "description": "App can prompt user to install external packages, characteristic of multi-stage droppers.",
        "severity": "HIGH",
        "category": "Installation",
        "mitre_technique_id": "T1475",
        "weight": 25
    },
    'android.permission.INSTALL_PACKAGES': {
        "title": "Direct Package Installation",
        "description": "App requests direct package installation privilege without standard installer flow.",
        "severity": "CRITICAL",
        "category": "Installation",
        "mitre_technique_id": "T1475",
        "weight": 35
    },

    # Notification & OTP Interception
    'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE': {
        "title": "Notification Listener Interception",
        "description": "App can observe all notifications, enabling interception of push OTPs and messages.",
        "severity": "HIGH",
        "category": "Interception",
        "mitre_technique_id": "T1636",
        "weight": 30
    },

    # Telephony & Calls
    'android.permission.READ_CALL_LOG': {
        "title": "Call Log Harvesting Potential",
        "description": "App can read user call history.",
        "severity": "MEDIUM",
        "category": "Privacy",
        "mitre_technique_id": "T1636.002",
        "weight": 15
    },
    'android.permission.PROCESS_OUTGOING_CALLS': {
        "title": "Call Redirection Potential",
        "description": "App can monitor or redirect outgoing telephone calls.",
        "severity": "HIGH",
        "category": "Telephony",
        "mitre_technique_id": "T1636.002",
        "weight": 20
    },
    'android.permission.CALL_PHONE': {
        "title": "Direct Call Placement",
        "description": "App can initiate phone calls without user confirmation.",
        "severity": "MEDIUM",
        "category": "Telephony",
        "mitre_technique_id": "T1636",
        "weight": 15
    },

    # Reconnaissance
    'android.permission.QUERY_ALL_PACKAGES': {
        "title": "Installed Application Enumeration",
        "description": "App queries inventory of installed apps, frequently used to identify targeted banking or crypto apps.",
        "severity": "MEDIUM",
        "category": "Reconnaissance",
        "mitre_technique_id": "T1418",
        "weight": 15
    },

    # Sensor & Data Exfiltration
    'android.permission.ACCESS_FINE_LOCATION': {
        "title": "Fine Location Access",
        "description": "App requests precise location access, which could be used for tracking.",
        "severity": "MEDIUM",
        "category": "Permission",
        "mitre_technique_id": "T1636.001",
        "weight": 10
    },
    'android.permission.READ_CONTACTS': {
        "title": "Contacts Exfiltration Potential",
        "description": "App can read user contacts.",
        "severity": "MEDIUM",
        "category": "Permission",
        "mitre_technique_id": "T1636.003",
        "weight": 15
    },
    'android.permission.WRITE_CONTACTS': {
        "title": "Contacts Modification",
        "description": "App can modify user contacts.",
        "severity": "LOW",
        "category": "Permission",
        "mitre_technique_id": "T1636.003",
        "weight": 5
    },
    'android.permission.RECORD_AUDIO': {
        "title": "Audio Capture Potential",
        "description": "App can record audio, potentially eavesdropping on the user.",
        "severity": "HIGH",
        "category": "Permission",
        "mitre_technique_id": "T1125",
        "weight": 20
    },
    'android.permission.CAMERA': {
        "title": "Camera Access",
        "description": "App can access the device camera.",
        "severity": "MEDIUM",
        "category": "Permission",
        "mitre_technique_id": "T1125",
        "weight": 15
    },
    'android.permission.WRITE_SETTINGS': {
        "title": "System Settings Modification",
        "description": "App can modify system settings, potentially altering security thresholds.",
        "severity": "MEDIUM",
        "category": "Defense Evasion",
        "mitre_technique_id": "T1546",
        "weight": 15
    }
}


def analyze_apk_static(file_path: str, db: AsyncSession) -> dict:
    """
    Performs deterministic static analysis on the APK using Androguard.
    Extracts manifest metadata, components, permissions, signing certificate,
    fuzzy TLSH hash, static indicators, and composite threat patterns.
    """
    try:
        a = APK(file_path)

        # Basic Manifest Info
        package_name = a.get_package()
        app_name = a.get_app_name()
        version_name = a.get_androidversion_name()
        version_code = a.get_androidversion_code()
        min_sdk = a.get_min_sdk_version()
        target_sdk = a.get_target_sdk_version()

        # Components
        activities = a.get_activities() or []
        services = a.get_services() or []
        receivers = a.get_receivers() or []
        providers = a.get_providers() or []

        # Permissions
        raw_perms = a.get_permissions() or []
        permissions = set(raw_perms)

        # Certificate Extraction & Inspection
        cert_fingerprint = extract_certificate_fingerprint(a)
        cert_details = extract_certificate_details(a)

        # TLSH Fuzzy Hashing
        tlsh_hash = calculate_tlsh(file_path)

        # Calculate Deterministic Risk Score and Findings
        risk_score = 0
        findings_data: List[Dict[str, Any]] = []
        risk_factors: List[Dict[str, Any]] = []

        # 1. Evaluate Individual Permission Rules
        for perm in sorted(permissions):
            if perm in INDICATOR_RULES:
                rule = INDICATOR_RULES[perm]
                risk_score += rule["weight"]

                findings_data.append({
                    "title": rule["title"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "evidence": perm,
                    "mitre_technique_id": rule.get("mitre_technique_id"),
                    "confidence": 1.0
                })

                risk_factors.append({
                    "indicator": perm,
                    "weight": rule["weight"],
                    "evidence": f"Declared in manifest: {perm}"
                })

        # 2. Evaluate Composite Threat Patterns
        # Pattern A: Cloak & Dagger Banking Trojan Overlay
        if 'android.permission.SYSTEM_ALERT_WINDOW' in permissions and (
            'android.permission.BIND_ACCESSIBILITY_SERVICE' in permissions or 
            'android.permission.BIND_DEVICE_ADMIN' in permissions
        ):
            weight = 25
            risk_score += weight
            findings_data.append({
                "title": "Cloak & Dagger Attack Combination",
                "description": "System alert overlay combined with accessibility or device admin privileges represents high-risk banking trojan behavior.",
                "severity": "CRITICAL",
                "category": "Composite Pattern",
                "evidence": "SYSTEM_ALERT_WINDOW + (ACCESSIBILITY or DEVICE_ADMIN)",
                "mitre_technique_id": "T1626",
                "confidence": 1.0
            })
            risk_factors.append({
                "indicator": "pattern.cloak_and_dagger",
                "weight": weight,
                "evidence": "Overlay permission combined with Accessibility or Device Admin privilege"
            })

        # Pattern B: 2FA SMS Interception & Network Exfiltration
        if ('android.permission.RECEIVE_SMS' in permissions or 'android.permission.READ_SMS' in permissions) and 'android.permission.INTERNET' in permissions:
            weight = 20
            risk_score += weight
            findings_data.append({
                "title": "SMS Interception & Network Exfiltration Pipeline",
                "description": "Application pairs SMS reading/interception with network transmission capability, typical of banking 2FA token theft.",
                "severity": "HIGH",
                "category": "Composite Pattern",
                "evidence": "SMS Permissions + android.permission.INTERNET",
                "mitre_technique_id": "T1636",
                "confidence": 1.0
            })
            risk_factors.append({
                "indicator": "pattern.sms_exfiltration",
                "weight": weight,
                "evidence": "SMS reading/reception paired with INTERNET access for exfiltration"
            })

        # Pattern C: Dynamic Dropper / Payload Delivery
        if 'android.permission.REQUEST_INSTALL_PACKAGES' in permissions and 'android.permission.INTERNET' in permissions:
            weight = 20
            risk_score += weight
            findings_data.append({
                "title": "Remote Dropper / Sideloading Capability",
                "description": "Application pairs internet connectivity with arbitrary package installation requests, allowing remote staging of secondary payloads.",
                "severity": "HIGH",
                "category": "Composite Pattern",
                "evidence": "REQUEST_INSTALL_PACKAGES + android.permission.INTERNET",
                "mitre_technique_id": "T1475",
                "confidence": 1.0
            })
            risk_factors.append({
                "indicator": "pattern.dropper_pipeline",
                "weight": weight,
                "evidence": "REQUEST_INSTALL_PACKAGES paired with INTERNET access"
            })

        # Pattern D: Persistent Sensor Surveillance
        if 'android.permission.RECEIVE_BOOT_COMPLETED' in permissions and (
            'android.permission.RECORD_AUDIO' in permissions or 
            'android.permission.CAMERA' in permissions or 
            'android.permission.ACCESS_FINE_LOCATION' in permissions
        ):
            weight = 15
            risk_score += weight
            findings_data.append({
                "title": "Persistent Sensor Surveillance",
                "description": "Application maintains reboot persistence while accessing microphone, camera, or fine location sensors.",
                "severity": "HIGH",
                "category": "Composite Pattern",
                "evidence": "RECEIVE_BOOT_COMPLETED + (RECORD_AUDIO / CAMERA / LOCATION)",
                "mitre_technique_id": "T1547.001",
                "confidence": 1.0
            })
            risk_factors.append({
                "indicator": "pattern.persistent_surveillance",
                "weight": weight,
                "evidence": "Boot persistence paired with covert sensors/location access"
            })

        # Pattern E: Debug Certificate in Non-Dev APK
        if cert_details.get("is_debug"):
            weight = 10
            risk_score += weight
            findings_data.append({
                "title": "Debug Signing Certificate Detected",
                "description": "App is signed with an Android Debug key rather than a production release key, indicating test build or amateur repackaging.",
                "severity": "MEDIUM",
                "category": "Certificate",
                "evidence": f"Issuer: {cert_details.get('issuer')}",
                "mitre_technique_id": "T1478",
                "confidence": 1.0
            })
            risk_factors.append({
                "indicator": "certificate.debug_key",
                "weight": weight,
                "evidence": "Signed with Android Debug / testkey certificate"
            })

        return {
            "status": "COMPLETED",
            "package_name": package_name,
            "app_name": app_name,
            "version_name": version_name,
            "version_code": str(version_code) if version_code is not None else None,
            "min_sdk": str(min_sdk) if min_sdk is not None else None,
            "target_sdk": str(target_sdk) if target_sdk is not None else None,
            "tlsh": tlsh_hash,
            "certificate_fingerprint": cert_fingerprint,
            "risk_score": min(risk_score, 100),
            "findings_data": findings_data,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "risk_factors": risk_factors
        }

    except Exception as e:
        logger.error(f"Static analysis failed for {file_path}: {e}")
        return {
            "status": "FAILED",
            "error_message": str(e)
        }
