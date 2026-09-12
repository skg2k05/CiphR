from typing import Optional, List, Dict, Any, Tuple, Union
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

# Category Tier Caps to prevent linear inflation of benign capabilities
TIER_CAPS = {
    "system_admin": 80,       # High-impact abuse vectors: Device Admin, Accessibility, Silent Install
    "attack_vector": 30,      # Suspicious staging capabilities: Overlays, Sideloading prompts, Notification Listener
    "telephony": 15,          # SMS & Call APIs (normal in messengers, capped so benign SMS apps aren't labeled malware)
    "standard_runtime": 12,   # Standard dangerous permissions: Camera, Audio, Contacts, Location (capped for legitimate apps)
}

def calculate_risk_level(score: int) -> str:
    """Calculates standardized categorical threat severity from 0-100 score."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "SAFE"

# Configurable Deterministic Indicator Rules for Android Permissions & Capabilities
# Configurable Deterministic Indicator Rules for Android Permissions & Capabilities
# All MITRE ATT&CK mappings are strictly audited against the official MITRE ATT&CK Mobile matrix.
INDICATOR_RULES = {
    # System Admin & Structural Privileges (Tier: system_admin)
    'android.permission.BIND_DEVICE_ADMIN': {
        "title": "Device Admin Privileges",
        "description": "App requests device administrator privileges, frequently abused by ransomware to prevent uninstallation and enforce screen locks.",
        "severity": "CRITICAL",
        "category": "Administrative Control",
        "mitre_technique_id": "T1626.001",
        "mitre_technique_name": "Device Administrator Permissions",
        "mapping_type": "direct",
        "weight": 50,
        "tier": "system_admin"
    },
    'android.permission.BIND_ACCESSIBILITY_SERVICE': {
        "title": "Accessibility Service Abuse Potential",
        "description": "App requests Accessibility Service, frequently abused by banking trojans for keylogging, overlay injection, or consent theft.",
        "severity": "HIGH",
        "category": "Accessibility",
        "mitre_technique_id": "T1453",
        "mitre_technique_name": "Abuse Accessibility Features",
        "mapping_type": "direct",
        "weight": 40,
        "tier": "system_admin"
    },
    'android.permission.INSTALL_PACKAGES': {
        "title": "Direct Package Installation",
        "description": "App requests direct package installation privilege without standard user installer verification.",
        "severity": "CRITICAL",
        "category": "Installation",
        "mitre_technique_id": "T1476",
        "mitre_technique_name": "Deliver Malicious App via Other Means",
        "mapping_type": "direct",
        "weight": 35,
        "tier": "system_admin"
    },

    # High-Risk Attack Vectors (Tier: attack_vector)
    'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE': {
        "title": "Notification Listener Interception",
        "description": "App can observe all notifications, enabling interception of push OTPs and messages.",
        "severity": "HIGH",
        "category": "Interception",
        "mitre_technique_id": "T1517",
        "mitre_technique_name": "Access Notifications",
        "mapping_type": "direct",
        "weight": 25,
        "tier": "attack_vector"
    },
    'android.permission.SYSTEM_ALERT_WINDOW': {
        "title": "System Alert Window Requested",
        "description": "App can draw overlays on top of foreground applications, enabling Cloak & Dagger or credential phishing attacks.",
        "severity": "MEDIUM",
        "category": "Overlay",
        "mitre_technique_id": "T1411",
        "mitre_technique_name": "Input Prompt",
        "mapping_type": "direct",
        "weight": 15,
        "tier": "attack_vector"
    },
    'android.permission.REQUEST_INSTALL_PACKAGES': {
        "title": "Arbitrary Package Sideloading",
        "description": "App can prompt user to install external packages, characteristic of multi-stage droppers.",
        "severity": "MEDIUM",
        "category": "Installation",
        "mitre_technique_id": "T1476",
        "mitre_technique_name": "Deliver Malicious App via Other Means",
        "mapping_type": "direct",
        "weight": 15,
        "tier": "attack_vector"
    },

    # Telephony & Communications (Tier: telephony - Capped at 15)
    'android.permission.SEND_SMS': {
        "title": "SMS Transmission Capability",
        "description": "App can send SMS messages autonomously, commonly leveraged for premium SMS or toll fraud.",
        "severity": "MEDIUM",
        "category": "SMS Fraud",
        "mitre_technique_id": "T1582",
        "mitre_technique_name": "SMS Control",
        "mapping_type": "direct",
        "weight": 8,
        "tier": "telephony"
    },
    'android.permission.RECEIVE_SMS': {
        "title": "SMS Interception Potential",
        "description": "App can intercept incoming SMS messages, typically exploited to steal banking OTPs and 2FA tokens.",
        "severity": "MEDIUM",
        "category": "SMS Fraud",
        "mitre_technique_id": "T1582",
        "mitre_technique_name": "SMS Control",
        "mapping_type": "direct",
        "weight": 8,
        "tier": "telephony"
    },
    'android.permission.READ_SMS': {
        "title": "SMS Inbox Read Potential",
        "description": "App has access to read stored SMS messages on the device.",
        "severity": "MEDIUM",
        "category": "SMS Fraud",
        "mitre_technique_id": "T1636.004",
        "mitre_technique_name": "Protected User Data: SMS Messages",
        "mapping_type": "direct",
        "weight": 8,
        "tier": "telephony"
    },
    'android.permission.PROCESS_OUTGOING_CALLS': {
        "title": "Call Redirection Potential",
        "description": "App can monitor or redirect outgoing telephone calls.",
        "severity": "MEDIUM",
        "category": "Telephony",
        "mitre_technique_id": "T1616",
        "mitre_technique_name": "Call Control",
        "mapping_type": "direct",
        "weight": 8,
        "tier": "telephony"
    },
    'android.permission.READ_CALL_LOG': {
        "title": "Call Log Harvesting Potential",
        "description": "App can read user call history.",
        "severity": "LOW",
        "category": "Privacy",
        "mitre_technique_id": "T1636.002",
        "mitre_technique_name": "Protected User Data: Call Log",
        "mapping_type": "direct",
        "weight": 6,
        "tier": "telephony"
    },
    'android.permission.CALL_PHONE': {
        "title": "Direct Call Placement",
        "description": "App can initiate phone calls without user confirmation.",
        "severity": "LOW",
        "category": "Telephony",
        "mitre_technique_id": "T1616",
        "mitre_technique_name": "Call Control",
        "mapping_type": "direct",
        "weight": 4,
        "tier": "telephony"
    },
    'android.permission.QUERY_ALL_PACKAGES': {
        "title": "Installed Application Enumeration",
        "description": "App queries inventory of installed apps, frequently used to identify targeted banking or crypto apps.",
        "severity": "LOW",
        "category": "Reconnaissance",
        "mitre_technique_id": "T1418",
        "mitre_technique_name": "Software Discovery",
        "mapping_type": "direct",
        "weight": 10,
        "tier": "attack_vector"
    },

    # Standard Runtime Permissions (Tier: standard_runtime - Capped at 12)
    'android.permission.RECORD_AUDIO': {
        "title": "Audio Capture Potential",
        "description": "App can record audio, potentially eavesdropping on the user.",
        "severity": "LOW",
        "category": "Media",
        "mitre_technique_id": "T1429",
        "mitre_technique_name": "Audio Capture",
        "mapping_type": "direct",
        "weight": 5,
        "tier": "standard_runtime"
    },
    'android.permission.CAMERA': {
        "title": "Camera Access",
        "description": "App can access the device camera.",
        "severity": "LOW",
        "category": "Media",
        "mitre_technique_id": "T1512",
        "mitre_technique_name": "Video Capture",
        "mapping_type": "direct",
        "weight": 4,
        "tier": "standard_runtime"
    },
    'android.permission.READ_CONTACTS': {
        "title": "Contacts Exfiltration Potential",
        "description": "App can read user contacts.",
        "severity": "LOW",
        "category": "Contacts",
        "mitre_technique_id": "T1636.003",
        "mitre_technique_name": "Protected User Data: Contact List",
        "mapping_type": "direct",
        "weight": 4,
        "tier": "standard_runtime"
    },
    'android.permission.WRITE_CONTACTS': {
        "title": "Contacts Modification",
        "description": "App can modify user contacts.",
        "severity": "LOW",
        "category": "Contacts",
        "mitre_technique_id": None,  # Contact modification alone is not a substantiated ATT&CK technique
        "mitre_technique_name": None,
        "mapping_type": None,
        "weight": 2,
        "tier": "standard_runtime"
    },
    'android.permission.ACCESS_FINE_LOCATION': {
        "title": "Fine Location Access",
        "description": "App requests precise location access, which could be used for tracking.",
        "severity": "LOW",
        "category": "Location",
        "mitre_technique_id": "T1430",
        "mitre_technique_name": "Location Tracking",
        "mapping_type": "direct",
        "weight": 4,
        "tier": "standard_runtime"
    },
    'android.permission.ACCESS_COARSE_LOCATION': {
        "title": "Coarse Location Access",
        "description": "App requests approximate network-based location.",
        "severity": "LOW",
        "category": "Location",
        "mitre_technique_id": "T1430",
        "mitre_technique_name": "Location Tracking",
        "mapping_type": "direct",
        "weight": 2,
        "tier": "standard_runtime"
    },
    'android.permission.RECEIVE_BOOT_COMPLETED': {
        "title": "Boot Persistence",
        "description": "App can automatically start components on device boot.",
        "severity": "LOW",
        "category": "Persistence",
        "mitre_technique_id": "T1624.001",
        "mitre_technique_name": "Event Triggered Execution: Broadcast Receivers",
        "mapping_type": "direct",
        "weight": 4,
        "tier": "standard_runtime"
    },
    'android.permission.WRITE_SETTINGS': {
        "title": "System Settings Modification",
        "description": "App can modify system settings, potentially altering security thresholds.",
        "severity": "LOW",
        "category": "System",
        "mitre_technique_id": None,  # Standard settings alteration is not an adversary persistence technique
        "mitre_technique_name": None,
        "mapping_type": None,
        "weight": 4,
        "tier": "standard_runtime"
    }
}

# Defined Multi-Signal Composite Threat Pattern Rules
COMPOSITE_RULES = {
    "pattern.overlay_accessibility_abuse": {
        "title": "Cloak & Dagger Attack Combination",
        "description": "System alert overlay combined with accessibility or device admin privileges represents high-risk banking trojan behavior.",
        "severity": "CRITICAL",
        "category": "Composite Pattern",
        "mitre_technique_id": "T1411",
        "mitre_technique_name": "Input Prompt",
        "mapping_type": "heuristic",
        "weight": 30,
        "evidence": "SYSTEM_ALERT_WINDOW + (ACCESSIBILITY or DEVICE_ADMIN)"
    },
    "pattern.sms_exfiltration": {
        "title": "Stealth SMS Interception & Exfiltration Pipeline",
        "description": "Application pairs SMS reading/reception with network access and boot persistence/notification listener for autonomous token harvesting.",
        "severity": "HIGH",
        "category": "Composite Pattern",
        "mitre_technique_id": "T1582",
        "mitre_technique_name": "SMS Control",
        "mapping_type": "heuristic",
        "weight": 20,
        "evidence": "SMS Permissions + INTERNET + (BOOT_COMPLETED or NOTIFICATION_LISTENER)"
    },
    "pattern.dropper_pipeline": {
        "title": "Remote Dropper / Sideloading Pipeline",
        "description": "Application pairs internet connectivity with arbitrary package installation requests and background persistence/overlay, typical of secondary payload staging.",
        "severity": "HIGH",
        "category": "Composite Pattern",
        "mitre_technique_id": "T1476",
        "mitre_technique_name": "Deliver Malicious App via Other Means",
        "mapping_type": "heuristic",
        "weight": 20,
        "evidence": "REQUEST_INSTALL_PACKAGES + INTERNET + (BOOT_COMPLETED or OVERLAY)"
    },
    "pattern.persistent_surveillance": {
        "title": "Persistent Sensor Surveillance",
        "description": "Application maintains reboot persistence and internet connectivity while accessing microphone, camera, or fine location sensors.",
        "severity": "HIGH",
        "category": "Composite Pattern",
        "mitre_technique_id": "T1624.001",
        "mitre_technique_name": "Event Triggered Execution: Broadcast Receivers",
        "mapping_type": "heuristic",
        "weight": 20,
        "evidence": "RECEIVE_BOOT_COMPLETED + INTERNET + (RECORD_AUDIO / CAMERA / LOCATION)"
    },
    "certificate.debug_key": {
        "title": "Debug Signing Certificate Detected",
        "description": "App is signed with an Android Debug key rather than a production release key, indicating test build or amateur repackaging.",
        "severity": "LOW",
        "category": "Certificate",
        "mitre_technique_id": None,  # Signing key anomaly is an integrity finding, not an adversary profile installation
        "mitre_technique_name": None,
        "mapping_type": None,
        "weight": 5,
        "evidence": "Signed with Android Debug / testkey certificate"
    }
}


def calculate_risk_evaluation(
    permissions: Any,
    cert_details: Optional[Dict[str, Any]] = None
) -> Tuple[int, List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Evaluates permissions and certificate metadata using tier-capped scoring
    and multi-signal composite threat detection.
    
    Returns:
        (risk_score, risk_factors, findings_data)
    """
    perms_set = set(permissions or [])
    cert_dict = cert_details or {}

    findings_data: List[Dict[str, Any]] = []
    risk_factors: List[Dict[str, Any]] = []
    tier_raw_weights = {
        "system_admin": 0,
        "attack_vector": 0,
        "telephony": 0,
        "standard_runtime": 0
    }

    # 1. Evaluate Individual Permission Rules with Category Tracking
    for perm in sorted(perms_set):
        if perm in INDICATOR_RULES:
            rule = INDICATOR_RULES[perm]
            tier = rule.get("tier", "standard_runtime")
            tier_raw_weights[tier] += rule["weight"]

            findings_data.append({
                "title": rule["title"],
                "description": rule["description"],
                "severity": rule["severity"],
                "category": rule["category"],
                "evidence": f"Manifest declared permission: {perm}",
                "mitre_technique_id": rule.get("mitre_technique_id"),
                "mitre_technique_name": rule.get("mitre_technique_name"),
                "mapping_type": rule.get("mapping_type"),
                "confidence": 1.0 if rule.get("mapping_type") == "direct" else (0.85 if rule.get("mapping_type") == "heuristic" else 0.5)
            })

            risk_factors.append({
                "indicator": perm,
                "weight": rule["weight"],
                "severity": rule["severity"],
                "evidence": f"Declared in manifest: {perm}",
                "mitre_technique_id": rule.get("mitre_technique_id"),
                "mitre_technique_name": rule.get("mitre_technique_name"),
                "mapping_type": rule.get("mapping_type"),
                "confidence": 1.0 if rule.get("mapping_type") == "direct" else (0.85 if rule.get("mapping_type") == "heuristic" else 0.5)
            })

    # Apply category tier caps to prevent runaway linear score inflation
    permission_subtotal = sum(
        min(tier_raw_weights[t], TIER_CAPS[t])
        for t in tier_raw_weights
    )

    # 2. Evaluate Composite Threat Patterns (Genuine Multi-Signal Synergies)
    composite_score = 0

    # Pattern A: Cloak & Dagger Banking Trojan Overlay
    if 'android.permission.SYSTEM_ALERT_WINDOW' in perms_set and (
        'android.permission.BIND_ACCESSIBILITY_SERVICE' in perms_set or 
        'android.permission.BIND_DEVICE_ADMIN' in perms_set
    ):
        rule = COMPOSITE_RULES["pattern.overlay_accessibility_abuse"]
        weight = rule["weight"]
        composite_score += weight
        findings_data.append({
            "title": rule["title"],
            "description": rule["description"],
            "severity": rule["severity"],
            "category": rule["category"],
            "evidence": rule["evidence"],
            "mitre_technique_id": rule.get("mitre_technique_id"),
            "mitre_technique_name": rule.get("mitre_technique_name"),
            "mapping_type": rule.get("mapping_type"),
            "confidence": 0.85
        })
        risk_factors.append({
            "indicator": "pattern.overlay_accessibility_abuse",
            "weight": weight,
            "severity": rule["severity"],
            "evidence": rule["evidence"],
            "mitre_technique_id": rule.get("mitre_technique_id"),
            "mitre_technique_name": rule.get("mitre_technique_name"),
            "mapping_type": rule.get("mapping_type"),
            "confidence": 0.85
        })

    # Pattern B: Stealth 2FA SMS Interception Pipeline
    if ('android.permission.RECEIVE_SMS' in perms_set or 'android.permission.READ_SMS' in perms_set) and \
       'android.permission.INTERNET' in perms_set and \
       ('android.permission.RECEIVE_BOOT_COMPLETED' in perms_set or 'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE' in perms_set):
        rule = COMPOSITE_RULES["pattern.sms_exfiltration"]
        weight = rule["weight"]
        composite_score += weight
        findings_data.append({
            "title": rule["title"],
            "description": rule["description"],
            "severity": rule["severity"],
            "category": rule["category"],
            "evidence": rule["evidence"],
            "mitre_technique_id": rule.get("mitre_technique_id"),
            "mitre_technique_name": rule.get("mitre_technique_name"),
            "mapping_type": rule.get("mapping_type"),
            "confidence": 0.85
        })
        risk_factors.append({
            "indicator": "pattern.sms_exfiltration",
            "weight": weight,
            "severity": rule["severity"],
            "evidence": rule["evidence"],
            "mitre_technique_id": rule.get("mitre_technique_id"),
            "mitre_technique_name": rule.get("mitre_technique_name"),
            "mapping_type": rule.get("mapping_type"),
            "confidence": 0.85
        })

    # Pattern C: Dynamic Dropper / Payload Delivery
    if 'android.permission.REQUEST_INSTALL_PACKAGES' in perms_set and \
       'android.permission.INTERNET' in perms_set and \
       ('android.permission.RECEIVE_BOOT_COMPLETED' in perms_set or 'android.permission.SYSTEM_ALERT_WINDOW' in perms_set or 'android.permission.INSTALL_PACKAGES' in perms_set):
        rule = COMPOSITE_RULES["pattern.dropper_pipeline"]
        weight = rule["weight"]
        composite_score += weight
        findings_data.append({
            "title": rule["title"],
            "description": rule["description"],
            "severity": rule["severity"],
            "category": rule["category"],
            "evidence": rule["evidence"],
            "mitre_technique_id": rule.get("mitre_technique_id"),
            "mitre_technique_name": rule.get("mitre_technique_name"),
            "mapping_type": rule.get("mapping_type"),
            "confidence": 0.85
        })
        risk_factors.append({
            "indicator": "pattern.dropper_pipeline",
            "weight": weight,
            "severity": rule["severity"],
            "evidence": rule["evidence"],
            "mitre_technique_id": rule.get("mitre_technique_id"),
            "mitre_technique_name": rule.get("mitre_technique_name"),
            "mapping_type": rule.get("mapping_type"),
            "confidence": 0.85
        })

    # Pattern D: Persistent Covert Surveillance
    if 'android.permission.RECEIVE_BOOT_COMPLETED' in perms_set and 'android.permission.INTERNET' in perms_set and (
        'android.permission.RECORD_AUDIO' in perms_set or 
        'android.permission.CAMERA' in perms_set or 
        'android.permission.ACCESS_FINE_LOCATION' in perms_set
    ):
        rule = COMPOSITE_RULES["pattern.persistent_surveillance"]
        weight = rule["weight"]
        composite_score += weight
        findings_data.append({
            "title": rule["title"],
            "description": rule["description"],
            "severity": rule["severity"],
            "category": rule["category"],
            "evidence": rule["evidence"],
            "mitre_technique_id": rule.get("mitre_technique_id"),
            "mitre_technique_name": rule.get("mitre_technique_name"),
            "mapping_type": rule.get("mapping_type"),
            "confidence": 0.85
        })
        risk_factors.append({
            "indicator": "pattern.persistent_surveillance",
            "weight": weight,
            "severity": rule["severity"],
            "evidence": rule["evidence"],
            "mitre_technique_id": rule.get("mitre_technique_id"),
            "mitre_technique_name": rule.get("mitre_technique_name"),
            "mapping_type": rule.get("mapping_type"),
            "confidence": 0.85
        })

    # Pattern E: Debug Signing Certificate in Production Build
    if cert_dict.get("is_debug"):
        rule = COMPOSITE_RULES["certificate.debug_key"]
        weight = rule["weight"]
        composite_score += weight
        findings_data.append({
            "title": rule["title"],
            "description": rule["description"],
            "severity": rule["severity"],
            "category": rule["category"],
            "evidence": f"Issuer: {cert_dict.get('issuer')}",
            "mitre_technique_id": rule.get("mitre_technique_id"),
            "mitre_technique_name": rule.get("mitre_technique_name"),
            "mapping_type": rule.get("mapping_type"),
            "confidence": 1.0
        })
        risk_factors.append({
            "indicator": "certificate.debug_key",
            "weight": weight,
            "severity": rule["severity"],
            "evidence": f"Issuer: {cert_dict.get('issuer')}",
            "mitre_technique_id": rule.get("mitre_technique_id"),
            "mitre_technique_name": rule.get("mitre_technique_name"),
            "mapping_type": rule.get("mapping_type"),
            "confidence": 1.0
        })

    total_risk = permission_subtotal + composite_score
    risk_score = min(max(total_risk, 0), 100)

    return risk_score, risk_factors, findings_data


def calculate_risk_factors(
    permissions: Any,
    cert_details: Optional[Dict[str, Any]] = None
) -> Tuple[int, List[Dict[str, Any]]]:
    """Convenience helper returning (risk_score, risk_factors)."""
    risk_score, risk_factors, _ = calculate_risk_evaluation(permissions, cert_details)
    return risk_score, risk_factors


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

        # Deterministic Risk Evaluation & Findings
        risk_score, risk_factors, findings_data = calculate_risk_evaluation(permissions, cert_details)
        risk_level = calculate_risk_level(risk_score)

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
            "risk_score": risk_score,
            "risk_level": risk_level,
            "findings_data": findings_data,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "permissions": sorted(list(permissions)),
            "certificate_details": cert_details,
            "risk_factors": risk_factors
        }

    except Exception as e:
        logger.error(f"Static analysis failed for {file_path}: {e}")
        return {
            "status": "FAILED",
            "error_message": str(e)
        }
