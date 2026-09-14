import pytest
import base64
from app.services.dex_analysis_service import analyze_dex

class MockMethod:
    def __init__(self, class_name, name):
        self._class_name = class_name
        self._name = name
    def get_class_name(self): return self._class_name
    def get_name(self): return self._name

class MockDEX:
    def __init__(self, strings=None, methods=None, throw=False):
        self._strings = strings or []
        self._methods = methods or []
        self._throw = throw
        if self._throw:
            raise Exception("Malformed DEX format!")

    def get_strings(self): return self._strings
    def get_methods(self): return self._methods

@pytest.fixture
def mock_dex_parser(monkeypatch):
    def fake_dex(data):
        if data == b"malformed":
            return MockDEX(throw=True)
        elif data == b"dex1":
            return MockDEX(
                strings=[
                    "http://malicious.com/payload",
                    "192.168.1.100",
                    "256.0.0.1", # Invalid IP
                    "just a normal string",
                    b"bytes string",
                    base64.b64encode(b"http://hidden.url.com").decode('utf-8')
                ],
                methods=[
                    MockMethod("Ljava/lang/Runtime;", "exec"),
                    MockMethod("Ldalvik/system/DexClassLoader;", "<init>")
                ]
            )
        elif data == b"dex2":
            return MockDEX(
                strings=["login.example.com", "8.8.8.8"]
            )
        elif data == b"dex_no_command":
            return MockDEX(
                strings=["normal string", "another string"],
                methods=[MockMethod("Ljava/lang/Runtime;", "exec")]
            )
        elif data == b"dex_with_command":
            return MockDEX(
                strings=["normal string", "/system/bin/sh -c id"],
                methods=[MockMethod("Ljava/lang/Runtime;", "exec")]
            )
        elif data == b"dex_with_shell_word":
            return MockDEX(
                strings=["command shell example"],
                methods=[MockMethod("Ljava/lang/Runtime;", "exec")]
            )
        elif data == b"dex_no_payload":
            return MockDEX(
                strings=["normal string"],
                methods=[MockMethod("Ldalvik/system/DexClassLoader;", "<init>")]
            )
        elif data == b"dex_with_url_payload":
            return MockDEX(
                strings=["http://evil.com/payload.dex"],
                methods=[MockMethod("Ldalvik/system/DexClassLoader;", "<init>")]
            )
        elif data == b"dex_with_ip_payload":
            return MockDEX(
                strings=["192.168.1.100"],
                methods=[MockMethod("Ldalvik/system/DexClassLoader;", "<init>")]
            )
        elif data == b"dex_with_base64_text":
            return MockDEX(
                strings=[base64.b64encode(b"just normal text").decode('utf-8')],
                methods=[MockMethod("Ldalvik/system/DexClassLoader;", "<init>")]
            )
        elif data == b"dex_with_base64_url":
            return MockDEX(
                strings=[base64.b64encode(b"http://hidden.com/drop").decode('utf-8')],
                methods=[MockMethod("Ldalvik/system/DexClassLoader;", "<init>")]
            )
        elif data == b"dex_reflection":
            return MockDEX(
                strings=[base64.b64encode(b"obfuscated").decode('utf-8')],
                methods=[MockMethod("Ljava/lang/reflect/Method;", "invoke")]
            )
        else:
            return MockDEX()
    monkeypatch.setattr("app.services.dex_analysis_service.DEX", fake_dex)

def test_analyze_dex_no_dex(mock_dex_parser):
    result = analyze_dex([])
    assert result["dex_files_analyzed"] == 0

def test_analyze_dex_malformed(mock_dex_parser):
    result = analyze_dex([b"malformed"])
    assert result["dex_files_analyzed"] == 1
    assert len(result["hardcoded_ips"]) == 0

def test_analyze_dex_valid_and_multiple(mock_dex_parser):
    result = analyze_dex([b"dex1", b"dex2"])

    # Files analyzed
    assert result["dex_files_analyzed"] == 2

    # IPs
    ips = [ip["indicator"] for ip in result["hardcoded_ips"]]
    assert "192.168.1.100" in ips
    assert "8.8.8.8" in ips
    assert "256.0.0.1" not in ips # Invalid IPv4 rejection

    # URLs
    urls = [url["indicator"] for url in result["urls"]]
    assert "http://malicious.com/payload" in urls

    # Encoded Strings
    encoded = result["encoded_strings"]
    assert len(encoded) == 1
    assert "http://hidden.url.com" in encoded[0]["decoded"]
    assert "URL: http://hidden.url.com" in encoded[0]["detected_indicators"]

    # Suspicious APIs & MITRE
    apis = [api["api"] for api in result["suspicious_apis"]]
    assert "java.lang.Runtime.exec" in apis
    assert "dalvik.system.DexClassLoader.<init>" in apis

    # Risk factors
    risks = [r["indicator"] for r in result["risk_factors"]]
    assert "java.lang.Runtime.exec" in risks

    # MITRE mappings
    mitre = [f["mitre_technique_id"] for f in result["findings_data"]]
    assert "T1059" in mitre # Execution
    assert "T1628" in mitre # Dynamic Loading

def test_behavioral_heuristic_runtime_exec_no_command(mock_dex_parser):
    result = analyze_dex([b"dex_no_command"])
    heuristics = [h["heuristic"] for h in result["behavioral_heuristics"]]
    assert "PROCESS_EXECUTION_WITH_COMMAND_CONTENT" not in heuristics

def test_behavioral_heuristic_runtime_exec_with_command(mock_dex_parser):
    result = analyze_dex([b"dex_with_command"])
    heuristics = [h["heuristic"] for h in result["behavioral_heuristics"]]
    assert "PROCESS_EXECUTION_WITH_COMMAND_CONTENT" in heuristics

    # We explicitly verify risk double counting is prevented
    risks = [r["indicator"] for r in result["risk_factors"]]
    assert "PROCESS_EXECUTION_WITH_COMMAND_CONTENT" not in risks
    assert "java.lang.Runtime.exec" in risks

def test_behavioral_heuristic_runtime_exec_shell_word(mock_dex_parser):
    # 'command shell example' should not qualify
    result = analyze_dex([b"dex_with_shell_word"])
    heuristics = [h["heuristic"] for h in result["behavioral_heuristics"]]
    assert "PROCESS_EXECUTION_WITH_COMMAND_CONTENT" not in heuristics

def test_behavioral_heuristic_dynamic_loading_no_payload(mock_dex_parser):
    result = analyze_dex([b"dex_no_payload"])
    heuristics = [h["heuristic"] for h in result["behavioral_heuristics"]]
    assert "DYNAMIC_LOADING_WITH_PAYLOAD_INDICATOR" not in heuristics

def test_behavioral_heuristic_dynamic_loading_with_url(mock_dex_parser):
    result = analyze_dex([b"dex_with_url_payload"])
    heuristics = [h["heuristic"] for h in result["behavioral_heuristics"]]
    assert "DYNAMIC_LOADING_WITH_PAYLOAD_INDICATOR" in heuristics

    risks = [r["indicator"] for r in result["risk_factors"]]
    assert "DYNAMIC_LOADING_WITH_PAYLOAD_INDICATOR" not in risks

def test_behavioral_heuristic_dynamic_loading_with_ip(mock_dex_parser):
    result = analyze_dex([b"dex_with_ip_payload"])
    heuristics = [h["heuristic"] for h in result["behavioral_heuristics"]]
    assert "DYNAMIC_LOADING_WITH_PAYLOAD_INDICATOR" in heuristics

def test_behavioral_heuristic_dynamic_loading_with_base64_text(mock_dex_parser):
    # Base64 string that decodes to ordinary text should NOT trigger payload
    result = analyze_dex([b"dex_with_base64_text"])
    heuristics = [h["heuristic"] for h in result["behavioral_heuristics"]]
    assert "DYNAMIC_LOADING_WITH_PAYLOAD_INDICATOR" not in heuristics

def test_behavioral_heuristic_dynamic_loading_with_base64_url(mock_dex_parser):
    # Base64 string that decodes to a URL SHOULD trigger payload
    result = analyze_dex([b"dex_with_base64_url"])
    heuristics = [h["heuristic"] for h in result["behavioral_heuristics"]]
    assert "DYNAMIC_LOADING_WITH_PAYLOAD_INDICATOR" in heuristics

def test_behavioral_heuristic_reflection_no_obfuscation(mock_dex_parser):
    # The reflection heuristic was removed completely due to lack of a defensible static signal
    result = analyze_dex([b"dex_reflection"])
    heuristics = [h["heuristic"] for h in result["behavioral_heuristics"]]
    assert "REFLECTION_WITH_OBFUSCATION_INDICATOR" not in heuristics
