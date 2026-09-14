import pytest
from app.services.apk_analysis_service import (
    calculate_risk_level,
    calculate_risk_factors,
    analyze_apk_static,
    INDICATOR_RULES,
    COMPOSITE_RULES,
    TIER_CAPS,
)


class TestRiskScoringSystem:
    """Audit and validation tests for the calibrated CiphR risk scoring engine."""

    def test_scenario_1_benign_apk_with_common_permissions(self):
        """1. Benign APK with common permissions (INTERNET, ACCESS_NETWORK_STATE, VIBRATE).
        
        Common utility permissions should not be marked as malware indicators,
        and routine runtime permissions (like CAMERA alone) should yield a SAFE severity.
        """
        # Case A: Standard utility permissions without malicious intent
        benign_permissions = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.ACCESS_WIFI_STATE",
            "android.permission.VIBRATE",
            "android.permission.WAKE_LOCK",
        ]
        score_a, factors_a = calculate_risk_factors(benign_permissions, cert_details=None)
        assert score_a == 0
        assert calculate_risk_level(score_a) == "SAFE"
        assert len(factors_a) == 0

        # Case B: Benign app with single standard user-facing capability (e.g., photo app)
        photo_permissions = benign_permissions + ["android.permission.CAMERA"]
        score_b, factors_b = calculate_risk_factors(photo_permissions, cert_details=None)
        assert score_b == 4
        assert calculate_risk_level(score_b) == "SAFE"
        assert len(factors_b) == 1
        assert factors_b[0]["indicator"] == "android.permission.CAMERA"
        assert factors_b[0]["severity"] == "LOW"

    def test_scenario_2_apk_with_one_suspicious_permission(self):
        """2. APK with one suspicious permission (e.g. SEND_SMS).
        
        A single sensitive permission is evidence of potential capability,
        not proof of malware. It must stay in SAFE / LOW range without triggering composites.
        """
        permissions = [
            "android.permission.INTERNET",
            "android.permission.SEND_SMS",
        ]
        score, factors = calculate_risk_factors(permissions, cert_details=None)
        
        # SEND_SMS has weight 8 (telephony tier cap 15)
        assert score == 8
        assert calculate_risk_level(score) == "SAFE"
        assert len(factors) == 1
        assert factors[0]["indicator"] == "android.permission.SEND_SMS"
        assert factors[0]["mitre_technique_id"] == "T1582"
        assert factors[0]["mitre_technique_name"] == "SMS Control"
        assert factors[0]["weight"] == 8

    def test_scenario_3_apk_with_multiple_independent_suspicious_indicators(self):
        """3. APK with multiple independent suspicious indicators.
        
        Tests tier-capping: multiple permissions in the same category (e.g. telephony,
        standard runtime) should cap out rather than inflate to 100 artificially.
        Without composite orchestrations, independent indicators should register MEDIUM risk.
        """
        permissions = [
            # Telephony tier: SEND_SMS (8) + RECEIVE_SMS (8) + READ_SMS (8) -> sum 24, capped at 15
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            # Standard runtime tier: RECORD_AUDIO (5) + CAMERA (4) + READ_CONTACTS (4) -> sum 13, capped at 12
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            # Attack vector tier: QUERY_ALL_PACKAGES (10) + SYSTEM_ALERT_WINDOW (15) -> sum 25 (under 30 cap)
            "android.permission.QUERY_ALL_PACKAGES",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ]
        score, factors = calculate_risk_factors(permissions, cert_details=None)
        
        # Expected score: 15 (telephony cap) + 12 (standard runtime cap) + 25 (attack vector) = 52
        assert score == 52
        assert calculate_risk_level(score) == "MEDIUM"
        assert len(factors) == 8
        
        # Verify deterministic behavior
        score_repeat, factors_repeat = calculate_risk_factors(permissions, cert_details=None)
        assert score == score_repeat
        assert factors == factors_repeat

    def test_scenario_4_apk_with_composite_suspicious_pattern(self):
        """4. APK with composite suspicious pattern.
        
        A composite pattern (e.g. Cloak & Dagger: SYSTEM_ALERT_WINDOW + BIND_ACCESSIBILITY_SERVICE)
        represents coordinated weaponization and should escalate the risk to CRITICAL (80-100).
        """
        permissions = [
            "android.permission.SYSTEM_ALERT_WINDOW",          # Attack vector tier: 15
            "android.permission.BIND_ACCESSIBILITY_SERVICE",     # System admin tier: 40
            "android.permission.INTERNET",
        ]
        score, factors = calculate_risk_factors(permissions, cert_details=None)
        
        # Permission subtotal: 15 + 40 = 55
        # Composite rule: pattern.overlay_accessibility_abuse = 30
        # Total: 55 + 30 = 85
        assert score == 85
        assert calculate_risk_level(score) == "CRITICAL"
        
        # Verify composite pattern is present in risk factors
        composite_factors = [f for f in factors if f["indicator"].startswith("pattern.")]
        assert len(composite_factors) == 1
        assert composite_factors[0]["indicator"] == "pattern.overlay_accessibility_abuse"
        assert composite_factors[0]["weight"] == 30
        assert composite_factors[0]["severity"] == "CRITICAL"
        assert composite_factors[0]["mitre_technique_id"] == "T1411"
        assert composite_factors[0]["mitre_technique_name"] == "Input Prompt"

    def test_scenario_5_harmless_apidemos_fixture(self):
        """5. Harmless ApiDemos fixture.
        
        ApiDemos-debug.apk contains several demonstration capabilities (SMS, Contacts, Camera,
        Audio, etc.) but NO malicious composite pattern (no background boot persistence, no
        device admin, no accessibility listener, no stealth 2FA intercept).
        
        Previous score: 100/100 (CRITICAL) - Credibility failure.
        Calibrated score: 27/100 (LOW) - Explainable and defensible.
        """
        result = analyze_apk_static("tests/fixtures/ApiDemos-debug.apk", None)
        
        assert result["status"] == "COMPLETED"
        assert result["package_name"] == "io.appium.android.apis"
        
        # 1. Score verification
        assert result["risk_score"] == 27
        
        # 2. Severity verification
        severity = calculate_risk_level(result["risk_score"])
        assert severity == "LOW"
        
        # 3. Risk factors and evidence verification
        indicators = {f["indicator"] for f in result["risk_factors"]}
        expected_indicators = {
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
        }
        assert expected_indicators.issubset(indicators)
        
        # Verify NO composite attack pattern was falsely triggered
        composite_factors = [f for f in result["risk_factors"] if f["indicator"].startswith("pattern.")]
        assert len(composite_factors) == 0, f"False positive composite patterns triggered: {composite_factors}"
        
        # 4. Deterministic behavior verification
        repeat_result = analyze_apk_static("tests/fixtures/ApiDemos-debug.apk", None)
        assert result["risk_score"] == repeat_result["risk_score"]
        assert len(result["risk_factors"]) == len(repeat_result["risk_factors"])
        assert [f["indicator"] for f in result["risk_factors"]] == [f["indicator"] for f in repeat_result["risk_factors"]]

    def test_risk_level_thresholds(self):
        """Verify severity threshold classification is exhaustive and correct."""
        assert calculate_risk_level(0) == "SAFE"
        assert calculate_risk_level(19) == "SAFE"
        assert calculate_risk_level(20) == "LOW"
        assert calculate_risk_level(39) == "LOW"
        assert calculate_risk_level(40) == "MEDIUM"
        assert calculate_risk_level(59) == "MEDIUM"
        assert calculate_risk_level(60) == "HIGH"
        assert calculate_risk_level(79) == "HIGH"
        assert calculate_risk_level(80) == "CRITICAL"
        assert calculate_risk_level(100) == "CRITICAL"
