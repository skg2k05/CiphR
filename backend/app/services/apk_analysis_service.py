from androguard.core.apk import APK
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.certificate_service import extract_certificate_fingerprint
from app.services.tlsh_service import calculate_tlsh
from app.core.logging import logger

# Configurable Deterministic Indicator Rules
INDICATOR_RULES = {
    'android.permission.BIND_ACCESSIBILITY_SERVICE': {
        "title": "Accessibility Service Abuse Potential",
        "description": "App requests Accessibility Service, which is often used by malware for overlay attacks or keylogging.",
        "severity": "HIGH",
        "category": "Permission",
        "mitre_technique_id": "T1628",
        "weight": 40
    },
    'android.permission.SEND_SMS': {
        "title": "SMS Permission Requested",
        "description": "App can send SMS messages, often used for premium SMS fraud.",
        "severity": "HIGH",
        "category": "Permission",
        "mitre_technique_id": "T1636",
        "weight": 20
    },
    'android.permission.RECEIVE_SMS': {
        "title": "SMS Interception Potential",
        "description": "App can receive SMS messages, often used for 2FA interception.",
        "severity": "HIGH",
        "category": "Permission",
        "mitre_technique_id": "T1636",
        "weight": 20
    },
    'android.permission.READ_SMS': {
        "title": "SMS Read Potential",
        "description": "App can read stored SMS messages.",
        "severity": "HIGH",
        "category": "Permission",
        "mitre_technique_id": "T1636",
        "weight": 20
    },
    'android.permission.SYSTEM_ALERT_WINDOW': {
        "title": "System Alert Window Requested",
        "description": "App can draw over other apps, often used for overlay attacks (Cloak and Dagger).",
        "severity": "HIGH",
        "category": "Permission",
        "mitre_technique_id": "T1626",
        "weight": 20
    },
    'android.permission.RECEIVE_BOOT_COMPLETED': {
        "title": "Boot Persistence",
        "description": "App can automatically start components on device boot.",
        "severity": "MEDIUM",
        "category": "Permission",
        "mitre_technique_id": "T1547.001",
        "weight": 10
    },
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
    'android.permission.BIND_DEVICE_ADMIN': {
        "title": "Device Admin Privileges",
        "description": "App requests device administrator privileges, often used by ransomware to prevent uninstallation.",
        "severity": "CRITICAL",
        "category": "Permission",
        "mitre_technique_id": "T1624",
        "weight": 50
    }
}

def analyze_apk_static(file_path: str, db: AsyncSession) -> dict:
    """Performs static analysis on the APK using Androguard."""
    try:
        a = APK(file_path)
        
        # Basic Info
        package_name = a.get_package()
        app_name = a.get_app_name()
        version_name = a.get_androidversion_name()
        version_code = a.get_androidversion_code()
        min_sdk = a.get_min_sdk_version()
        target_sdk = a.get_target_sdk_version()
        
        # Components (bounded)
        activities = a.get_activities()[:500]
        services = a.get_services()[:500]
        receivers = a.get_receivers()[:500]
        
        # Permissions (bounded)
        permissions = set(list(a.get_permissions())[:500])
        
        # Certificate
        cert_fingerprint = extract_certificate_fingerprint(a)
        
        # TLSH
        tlsh_hash = calculate_tlsh(file_path)
        
        # Calculate Base Risk Score based on static heuristics
        risk_score = 0
        findings_data = []
        risk_factors = []
        
        for perm in permissions:
            if perm in INDICATOR_RULES:
                rule = INDICATOR_RULES[perm]
                risk_score += int(rule.get("weight", 0))
                
                # Add to findings (will map to Finding DB model)
                findings_data.append({
                    "title": rule["title"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "evidence": perm,
                    "mitre_technique_id": rule.get("mitre_technique_id"),
                    "confidence": 1.0
                })
                
                # Expose specific contributing factor
                risk_factors.append({
                    "indicator": perm,
                    "weight": rule["weight"],
                    "evidence": f"Declared in manifest: {perm}"
                })
                
        # --- DEX / Smali Intelligence Phase ---
        try:
            from app.services.dex_analysis_service import analyze_dex
            dex_results = analyze_dex(a.get_all_dex())
            
            # Merge DEX findings and risk factors
            if "findings_data" in dex_results:
                findings_data.extend(dex_results.pop("findings_data"))
            if "risk_factors" in dex_results:
                dex_risks = dex_results.pop("risk_factors")
                risk_factors.extend(dex_risks)
                for r in dex_risks:
                    risk_score += r.get("weight", 0)
        except Exception as e:
            logger.error(f"DEX analysis failed during static analysis: {e}")
            dex_results = {"error": str(e)}
            
        return {
            "status": "COMPLETED",
            "package_name": package_name,
            "app_name": app_name,
            "version_name": version_name,
            "version_code": version_code,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "tlsh": tlsh_hash,
            "certificate_fingerprint": cert_fingerprint,
            "risk_score": min(risk_score, 100),
            "findings_data": findings_data,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "risk_factors": risk_factors,
            "dex_data": dex_results
        }
        
    except Exception as e:
        logger.error(f"Static analysis failed for {file_path}: {e}")
        return {
            "status": "FAILED",
            "error_message": str(e)
        }
