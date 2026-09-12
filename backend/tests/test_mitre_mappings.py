import pytest
from app.services.apk_analysis_service import (
    INDICATOR_RULES,
    COMPOSITE_RULES,
    calculate_risk_evaluation,
    analyze_apk_static
)

# Known deprecated or enterprise-only techniques that MUST NOT be present in Android Mobile mappings
FORBIDDEN_ENTERPRISE_TECHNIQUES = {
    "T1125",      # Enterprise: Video Capture (PC/Workstation)
    "T1547.001",  # Enterprise: Registry Run Keys / Startup Folder (Windows)
    "T1546",      # Enterprise: Event Triggered Execution (WMI/OS)
    "T1475",      # Mobile: Deliver Malicious App via Authorized App Store (Google Play - cannot be proven by static APK analysis)
    "T1628",      # Mobile: Hide Artifacts (mismapped for accessibility)
}

# The verified MITRE ATT&CK Mobile techniques actively utilized in CiphR
EXPECTED_MOBILE_TECHNIQUES = {
    "T1626.001": "Device Administrator Permissions",
    "T1453": "Abuse Accessibility Features",
    "T1476": "Deliver Malicious App via Other Means",
    "T1517": "Access Notifications",
    "T1411": "Input Prompt",
    "T1582": "SMS Control",
    "T1636.004": "Protected User Data: SMS Messages",
    "T1636.003": "Protected User Data: Contact List",
    "T1636.002": "Protected User Data: Call Log",
    "T1616": "Call Control",
    "T1418": "Software Discovery",
    "T1429": "Audio Capture",
    "T1512": "Video Capture",
    "T1430": "Location Tracking",
    "T1624.001": "Event Triggered Execution: Broadcast Receivers",
}


class TestMitreAttackMobileAudit:
    """Audit verification for MITRE ATT&CK Mobile mappings."""

    def test_no_enterprise_or_deprecated_techniques_present(self):
        """Ensure no enterprise-only or invalid techniques are produced."""
        all_rules = list(INDICATOR_RULES.values()) + list(COMPOSITE_RULES.values())
        for rule in all_rules:
            tid = rule.get("mitre_technique_id")
            if tid:
                assert tid not in FORBIDDEN_ENTERPRISE_TECHNIQUES, (
                    f"Forbidden or enterprise technique {tid} found in rule: {rule['title']}"
                )

    def test_all_mapped_techniques_belong_to_verified_mobile_matrix(self):
        """Ensure all non-None technique IDs belong to the curated Android Mobile matrix."""
        all_rules = list(INDICATOR_RULES.values()) + list(COMPOSITE_RULES.values())
        for rule in all_rules:
            tid = rule.get("mitre_technique_id")
            if tid is not None:
                assert tid in EXPECTED_MOBILE_TECHNIQUES, f"Unexpected technique {tid} found in rule: {rule['title']}"
                assert rule.get("mitre_technique_name") == EXPECTED_MOBILE_TECHNIQUES[tid]

    def test_unsubstantiated_capabilities_have_no_mitre_mapping(self):
        """Ensure routine capabilities that do not prove adversary techniques have mitre_technique_id set to None."""
        assert INDICATOR_RULES['android.permission.WRITE_CONTACTS']['mitre_technique_id'] is None
        assert INDICATOR_RULES['android.permission.WRITE_SETTINGS']['mitre_technique_id'] is None
        assert COMPOSITE_RULES['certificate.debug_key']['mitre_technique_id'] is None

    def test_critical_privileges_have_exact_subtechniques(self):
        """Ensure high-privilege Android APIs map to precise modern sub-techniques."""
        # Device Admin
        admin_rule = INDICATOR_RULES['android.permission.BIND_DEVICE_ADMIN']
        assert admin_rule['mitre_technique_id'] == 'T1626.001'
        assert admin_rule['mapping_type'] == 'direct'

        # Accessibility Service
        a11y_rule = INDICATOR_RULES['android.permission.BIND_ACCESSIBILITY_SERVICE']
        assert a11y_rule['mitre_technique_id'] == 'T1453'
        assert a11y_rule['mapping_type'] == 'direct'

        # Notification Listener
        notif_rule = INDICATOR_RULES['android.permission.BIND_NOTIFICATION_LISTENER_SERVICE']
        assert notif_rule['mitre_technique_id'] == 'T1517'
        assert notif_rule['mapping_type'] == 'direct'

        # System Alert Window Overlay
        overlay_rule = INDICATOR_RULES['android.permission.SYSTEM_ALERT_WINDOW']
        assert overlay_rule['mitre_technique_id'] == 'T1411'
        assert overlay_rule['mapping_type'] == 'direct'

        # Boot Completed
        boot_rule = INDICATOR_RULES['android.permission.RECEIVE_BOOT_COMPLETED']
        assert boot_rule['mitre_technique_id'] == 'T1624.001'
        assert boot_rule['mapping_type'] == 'direct'

    def test_telephony_and_sensor_mobile_accuracy(self):
        """Ensure telephony and media sensors map to mobile-specific techniques."""
        # SMS sending/receiving -> SMS Control (T1582)
        assert INDICATOR_RULES['android.permission.SEND_SMS']['mitre_technique_id'] == 'T1582'
        assert INDICATOR_RULES['android.permission.RECEIVE_SMS']['mitre_technique_id'] == 'T1582'

        # Reading SMS DB -> Protected User Data: SMS Messages (T1636.004)
        assert INDICATOR_RULES['android.permission.READ_SMS']['mitre_technique_id'] == 'T1636.004'

        # Audio -> T1429 (not T1125 video capture)
        assert INDICATOR_RULES['android.permission.RECORD_AUDIO']['mitre_technique_id'] == 'T1429'

        # Camera -> T1512
        assert INDICATOR_RULES['android.permission.CAMERA']['mitre_technique_id'] == 'T1512'

        # Location -> T1430 (not T1636.001 calendar)
        assert INDICATOR_RULES['android.permission.ACCESS_FINE_LOCATION']['mitre_technique_id'] == 'T1430'
        assert INDICATOR_RULES['android.permission.ACCESS_COARSE_LOCATION']['mitre_technique_id'] == 'T1430'

    def test_evidence_and_confidence_distinction(self):
        """Verify API/findings output distinguishes technique, evidence, confidence, and mapping type."""
        permissions = [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.INTERNET"
        ]
        score, factors, findings = calculate_risk_evaluation(permissions, cert_details=None)

        # Check individual direct indicators
        overlay_finding = next(f for f in findings if "SYSTEM_ALERT_WINDOW" in f["evidence"])
        assert overlay_finding["mitre_technique_id"] == "T1411"
        assert overlay_finding["mitre_technique_name"] == "Input Prompt"
        assert overlay_finding["mapping_type"] == "direct"
        assert overlay_finding["confidence"] == 1.0

        # Check composite heuristic pattern
        composite_finding = next(f for f in findings if f.get("category") == "Composite Pattern")
        assert composite_finding["mitre_technique_id"] == "T1411"
        assert composite_finding["mitre_technique_name"] == "Input Prompt"
        assert composite_finding["mapping_type"] == "heuristic"
        assert composite_finding["confidence"] == 0.85
        assert "SYSTEM_ALERT_WINDOW" in composite_finding["evidence"]

    def test_real_apidemos_mitre_mappings(self):
        """Verify ApiDemos fixture produces only legitimate, justified MITRE Mobile techniques."""
        result = analyze_apk_static("tests/fixtures/ApiDemos-debug.apk", None)
        assert result["status"] == "COMPLETED"

        techniques_found = {
            f.get("mitre_technique_id")
            for f in result["findings_data"]
            if f.get("mitre_technique_id") is not None
        }

        # Expected techniques for ApiDemos:
        # SEND_SMS / RECEIVE_SMS -> T1582 (SMS Control)
        # RECORD_AUDIO -> T1429 (Audio Capture)
        # CAMERA -> T1512 (Video Capture)
        # READ_CONTACTS -> T1636.003 (Contact List)
        # ACCESS_FINE_LOCATION / ACCESS_COARSE_LOCATION -> T1430 (Location Tracking)
        expected = {"T1582", "T1429", "T1512", "T1636.003", "T1430"}
        assert techniques_found == expected

        # Check that WRITE_CONTACTS finding has None for technique ID
        write_contacts_finding = next(
            f for f in result["findings_data"]
            if "WRITE_CONTACTS" in f["evidence"]
        )
        assert write_contacts_finding["mitre_technique_id"] is None
