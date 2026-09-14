"""
Dataset Builder for CiphR Controlled Multi-APK Demo Dataset.

Generates 10 deterministic, safe, synthetic APK fixtures without live malware:
- Group 1 (3 APKs): FinSteal Trojan Family (High/Critical Risk, shared Cert A)
- Group 2 (3 APKs): AgentSMS Harvester Family (Medium Risk, shared Cert B)
- Independent 1 (1 APK): Benign Calculator (Safe, Cert C)
- Independent 2 (1 APK): Photo Viewer (Safe, Cert D)
- Independent 3 (1 APK): System Monitor (Low Risk, Cert E / Debug Key)
- Independent 4 (1 APK): Stealth Dropper (Low/Medium Risk, Cert F)
"""

import os
import io
import struct
import zipfile
import datetime
from pathlib import Path
from typing import Dict, List, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7, Encoding

FIXTURES_DIR = Path(__file__).resolve().parent
BASE_APK_PATH = FIXTURES_DIR / "ApiDemos-debug.apk"
OUTPUT_DIR = FIXTURES_DIR / "demo_dataset"

def _modify_axml_strings(manifest_bytes: bytes, replacements: Dict[str, str]) -> bytes:
    """Modifies string table entries in binary AndroidManifest.xml."""
    root_type, root_size = struct.unpack('<II', manifest_bytes[0:8])
    sb_header = manifest_bytes[8:36]
    sb_type, orig_sb_size, str_count, style_count, flags, strings_offset, styles_offset = struct.unpack('<IIIIIII', sb_header)
    
    offsets = list(struct.unpack(f'<{str_count}I', manifest_bytes[36:36 + str_count*4]))
    strings_start = 8 + strings_offset
    
    orig_strings = []
    for i in range(str_count):
        off = strings_start + offsets[i]
        char_len = struct.unpack('<H', manifest_bytes[off:off+2])[0]
        s_bytes = manifest_bytes[off+2 : off+2+char_len*2]
        orig_strings.append(s_bytes.decode('utf-16le', errors='replace'))
        
    new_strings = [replacements.get(s, s) for s in orig_strings]
    
    new_offsets = []
    new_str_bytes = bytearray()
    for s in new_strings:
        new_offsets.append(len(new_str_bytes))
        char_len = len(s)
        new_str_bytes.extend(struct.pack('<H', char_len))
        new_str_bytes.extend(s.encode('utf-16le'))
        new_str_bytes.extend(b'\x00\x00')
        
    while len(new_str_bytes) % 4 != 0:
        new_str_bytes.append(0)
        
    offsets_bytes = struct.pack(f'<{str_count}I', *new_offsets)
    styles_bytes = b''
    if style_count > 0:
        styles_start = 8 + styles_offset
        styles_end = 8 + orig_sb_size
        styles_bytes = manifest_bytes[styles_start:styles_end]
        
    new_strings_offset = 28 + len(offsets_bytes)
    new_sb_size = new_strings_offset + len(new_str_bytes) + len(styles_bytes)
    
    new_sb_header = struct.pack(
        '<IIIIIII',
        sb_type,
        new_sb_size,
        str_count,
        style_count,
        flags,
        new_strings_offset,
        styles_offset if style_count == 0 else (new_strings_offset + len(new_str_bytes))
    )
    
    rest_of_manifest = manifest_bytes[8 + orig_sb_size:]
    new_root_size = 8 + new_sb_size + len(rest_of_manifest)
    new_root_header = struct.pack('<II', root_type, new_root_size)
    
    return new_root_header + new_sb_header + offsets_bytes + new_str_bytes + styles_bytes + rest_of_manifest

# Cache generated keys and certs deterministically
_CERT_CACHE: Dict[str, Tuple[bytes, bytes]] = {}

def _get_cert_signature(common_name: str) -> Tuple[bytes, bytes]:
    """Generates a deterministic PKCS#7 detached signature block for a given common name."""
    if common_name in _CERT_CACHE:
        return _CERT_CACHE[common_name]
        
    # Generate RSA private key
    # Use deterministic key exponent
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"Org {common_name}"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    
    # Use fixed timestamps for determinism
    valid_from = datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    valid_to = datetime.datetime(2036, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(abs(hash(common_name)) + 10000)
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .sign(key, hashes.SHA256())
    )
    
    sf_bytes = f"Signature-Version: 1.0\r\nCreated-By: 1.0 (CiphR Test Matrix)\r\nSHA-256-Digest: {common_name}\r\n\r\n".encode("utf-8")
    
    builder = pkcs7.PKCS7SignatureBuilder().set_data(sf_bytes).add_signer(cert, key, hashes.SHA256())
    pkcs7_der = builder.sign(Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])
    
    _CERT_CACHE[common_name] = (sf_bytes, pkcs7_der)
    return sf_bytes, pkcs7_der

DATASET_CONFIGS = [
    # --- GROUP 1: FinSteal Trojan Family (3 samples, Cert A, High/Critical Risk) ---
    {
        "filename": "finsteal_v1.apk",
        "cert_name": "FinSteal Authority",
        "package_name": "com.threat.finsteal.v1",
        "app_name": "FinSteal Bank Assistant",
        "replacements": {
            "io.appium.android.apis": "com.threat.finsteal.v1",
            "API Demos": "FinSteal Bank Assistant",
            "android.permission.RECEIVE_SMS": "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SEND_SMS": "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.READ_SMS": "android.permission.RECEIVE_BOOT_COMPLETED",
        },
        "extra_content": b"FinSteal Payload Variant 1.0 binary payload bytes"
    },
    {
        "filename": "finsteal_v2.apk",
        "cert_name": "FinSteal Authority",
        "package_name": "com.threat.finsteal.v2",
        "app_name": "FinSteal Secure Token",
        "replacements": {
            "io.appium.android.apis": "com.threat.finsteal.v2",
            "API Demos": "FinSteal Secure Token",
            "android.permission.RECEIVE_SMS": "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SEND_SMS": "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.READ_SMS": "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.ACCESS_COARSE_LOCATION": "android.permission.ACCESS_FINE_LOCATION",
        },
        "extra_content": b"FinSteal Payload Variant 2.0 binary payload bytes"
    },
    {
        "filename": "finsteal_v3.apk",
        "cert_name": "FinSteal Authority",
        "package_name": "com.threat.finsteal.v3",
        "app_name": "FinSteal Authenticator",
        "replacements": {
            "io.appium.android.apis": "com.threat.finsteal.v3",
            "API Demos": "FinSteal Authenticator",
            "android.permission.RECEIVE_SMS": "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SEND_SMS": "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.READ_SMS": "android.permission.RECEIVE_BOOT_COMPLETED",
        },
        "extra_content": b"FinSteal Payload Variant 3.0 binary payload bytes"
    },

    # --- GROUP 2: AgentSMS Harvester Family (3 samples, Cert B, Medium Risk) ---
    {
        "filename": "agentsms_v1.apk",
        "cert_name": "AgentSMS Gateway",
        "package_name": "org.mobile.agentsms.v1",
        "app_name": "AgentSMS Fast Relay",
        "replacements": {
            "io.appium.android.apis": "org.mobile.agentsms.v1",
            "API Demos": "AgentSMS Fast Relay",
            "android.permission.WRITE_CONTACTS": "android.permission.QUERY_ALL_PACKAGES",
            "android.permission.ACCESS_COARSE_LOCATION": "android.permission.RECEIVE_BOOT_COMPLETED",
        },
        "extra_content": b"AgentSMS Delivery Agent v1"
    },
    {
        "filename": "agentsms_v2.apk",
        "cert_name": "AgentSMS Gateway",
        "package_name": "org.mobile.agentsms.v2",
        "app_name": "AgentSMS Pro Forwarder",
        "replacements": {
            "io.appium.android.apis": "org.mobile.agentsms.v2",
            "API Demos": "AgentSMS Pro Forwarder",
            "android.permission.WRITE_CONTACTS": "android.permission.QUERY_ALL_PACKAGES",
            "android.permission.ACCESS_COARSE_LOCATION": "android.permission.RECEIVE_BOOT_COMPLETED",
        },
        "extra_content": b"AgentSMS Delivery Agent v2"
    },
    {
        "filename": "agentsms_v3.apk",
        "cert_name": "AgentSMS Gateway",
        "package_name": "org.mobile.agentsms.v3",
        "app_name": "AgentSMS Sync Service",
        "replacements": {
            "io.appium.android.apis": "org.mobile.agentsms.v3",
            "API Demos": "AgentSMS Sync Service",
            "android.permission.WRITE_CONTACTS": "android.permission.QUERY_ALL_PACKAGES",
            "android.permission.ACCESS_COARSE_LOCATION": "android.permission.RECEIVE_BOOT_COMPLETED",
        },
        "extra_content": b"AgentSMS Delivery Agent v3"
    },

    # --- INDEPENDENT SAMPLES (4 samples, Certs C-F, Mixed Risk Spectrum) ---
    {
        "filename": "benign_calculator.apk",
        "cert_name": "Benign Tools LLC",
        "package_name": "com.utilities.calculator",
        "app_name": "Simple Calculator",
        "replacements": {
            "io.appium.android.apis": "com.utilities.calculator",
            "API Demos": "Simple Calculator",
            # Replace high-risk and dangerous perms with harmless permissions
            "android.permission.RECEIVE_SMS": "android.permission.VIBRATE",
            "android.permission.SEND_SMS": "android.permission.INTERNET",
            "android.permission.READ_CONTACTS": "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.WRITE_CONTACTS": "android.permission.WAKE_LOCK",
            "android.permission.CAMERA": "android.permission.SET_WALLPAPER",
            "android.permission.RECORD_AUDIO": "android.permission.VIBRATE",
            "android.permission.WRITE_EXTERNAL_STORAGE": "android.permission.ACCESS_WIFI_STATE",
            "android.permission.ACCESS_COARSE_LOCATION": "android.permission.FLASHLIGHT",
        },
        "extra_content": b"Benign Calculator Codebase"
    },
    {
        "filename": "photo_viewer_pro.apk",
        "cert_name": "Photo Studio Software",
        "package_name": "com.studio.photoviewer",
        "app_name": "Photo Viewer Pro",
        "replacements": {
            "io.appium.android.apis": "com.studio.photoviewer",
            "API Demos": "Photo Viewer Pro",
            "android.permission.RECEIVE_SMS": "android.permission.VIBRATE",
            "android.permission.SEND_SMS": "android.permission.INTERNET",
            "android.permission.READ_CONTACTS": "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.WRITE_CONTACTS": "android.permission.WAKE_LOCK",
            "android.permission.RECORD_AUDIO": "android.permission.VIBRATE",
            "android.permission.ACCESS_COARSE_LOCATION": "android.permission.FLASHLIGHT",
        },
        "extra_content": b"Photo Viewer Pro Codebase"
    },
    {
        "filename": "system_monitor_test.apk",
        "cert_name": "System Utilities AOSP",
        "package_name": "com.android.sysmon",
        "app_name": "System Monitor Test",
        "replacements": {
            "io.appium.android.apis": "com.android.sysmon",
            "API Demos": "System Monitor Test",
        },
        "extra_content": b"System Monitor Test Codebase"
    },
    {
        "filename": "stealth_dropper_lone.apk",
        "cert_name": "Solo Threat Actor",
        "package_name": "com.lone.dropper",
        "app_name": "Software Update Assistant",
        "replacements": {
            "io.appium.android.apis": "com.lone.dropper",
            "API Demos": "Software Update Assistant",
            "android.permission.RECEIVE_SMS": "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.SEND_SMS": "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.READ_CONTACTS": "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.WRITE_CONTACTS": "android.permission.WAKE_LOCK",
            "android.permission.CAMERA": "android.permission.SET_WALLPAPER",
            "android.permission.RECORD_AUDIO": "android.permission.VIBRATE",
            "android.permission.WRITE_EXTERNAL_STORAGE": "android.permission.ACCESS_WIFI_STATE",
            "android.permission.ACCESS_COARSE_LOCATION": "android.permission.FLASHLIGHT",
        },
        "extra_content": b"Stealth Dropper Payload"
    },
]

def build_demo_dataset(force: bool = False) -> List[Path]:
    """Generates all 10 APK fixtures in tests/fixtures/demo_dataset/."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    with zipfile.ZipFile(BASE_APK_PATH) as base_zip:
        manifest_bytes = base_zip.read("AndroidManifest.xml")
        classes_dex = base_zip.read("classes.dex")
        
        generated_paths = []
        for cfg in DATASET_CONFIGS:
            out_file = OUTPUT_DIR / cfg["filename"]
            if out_file.exists() and not force:
                generated_paths.append(out_file)
                continue
                
            modified_manifest = _modify_axml_strings(manifest_bytes, cfg["replacements"])
            sf_bytes, rsa_bytes = _get_cert_signature(cfg["cert_name"])
            
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr("AndroidManifest.xml", modified_manifest)
                z.writestr("classes.dex", classes_dex)
                z.writestr("assets/payload_info.dat", cfg["extra_content"])
                z.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\nCreated-By: CiphR\r\n\r\n")
                z.writestr("META-INF/CERT.SF", sf_bytes)
                z.writestr("META-INF/CERT.RSA", rsa_bytes)
                
            out_file.write_bytes(buf.getvalue())
            generated_paths.append(out_file)
            
        return generated_paths

if __name__ == "__main__":
    paths = build_demo_dataset(force=True)
    print(f"Successfully generated {len(paths)} APK fixtures in {OUTPUT_DIR}:")
    for p in paths:
        print(f"  - {p.name} ({p.stat().st_size} bytes)")
