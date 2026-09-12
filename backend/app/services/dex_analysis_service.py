import re
import base64
from typing import Dict, Any, List
from androguard.core.dex import DEX
from app.core.logging import logger

# Strict IPv4 regex to reject things like 256.x.x.x or arbitrary version strings
IPV4_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# URL regex
URL_REGEX = re.compile(r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?')

# Domain regex (heuristic, requiring at least one dot and valid characters)
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

# Suspicious APIs mapping (Class/Method substrings to detect)
SUSPICIOUS_APIS = {
    'java.lang.Runtime': {
        'methods': ['exec'],
        'reason': 'Application contains process execution capability',
        'mitre': 'T1059',
        'weight': 30
    },
    'dalvik.system.DexClassLoader': {
        'methods': ['<init>'],
        'reason': 'Application contains dynamic code loading capability',
        'mitre': 'T1628', # T1628 / T1129 dynamic payload
        'weight': 25
    },
    'dalvik.system.PathClassLoader': {
        'methods': ['<init>'],
        'reason': 'Application contains dynamic code loading capability',
        'mitre': 'T1628',
        'weight': 20
    },
    'java.lang.reflect.Method': {
        'methods': ['invoke'],
        'reason': 'Application uses reflection to invoke methods, often used for obfuscation',
        'mitre': 'T1027.002',
        'weight': 10
    }
}

def is_valid_base64(s: str) -> bool:
    """Check if a string looks like Base64 (heuristic)."""
    if len(s) < 16 or len(s) % 4 != 0:
        return False
    if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', s):
        return False
    return True

def analyze_dex(dex_bytes_generator) -> Dict[str, Any]:
    """
    Performs static-only analysis of DEX bytes.
    Extracts URLs, IPs, Domains, Suspicious APIs, and Base64 strings.
    """
    result: Dict[str, Any] = {
        "dex_files_analyzed": 0,
        "suspicious_apis": [],
        "hardcoded_ips": [],
        "urls": [],
        "domains": [],
        "encoded_strings": [],
        "risk_factors": [],
        "findings_data": []
    }
    
    unique_ips = set()
    unique_urls = set()
    unique_domains = set()
    unique_encoded = set()
    detected_apis = set()
    
    try:
        for dex_bytes in dex_bytes_generator:
            result["dex_files_analyzed"] += 1
            try:
                dex = DEX(dex_bytes)
                
                # 1. Analyze Strings
                for string_item in dex.get_strings():
                    # androguard get_strings returns bytes in 4.x or str in 3.x, let's coerce to string safely
                    try:
                        if isinstance(string_item, bytes):
                            s = string_item.decode('utf-8', errors='ignore')
                        else:
                            s = str(string_item)
                    except Exception:
                        continue
                        
                    # Ignore tiny strings and excessively large strings (prevent ReDoS/OOM)
                    if len(s) < 5 or len(s) > 10000:
                        continue
                        
                    # IPv4
                    if len(unique_ips) < 200:
                        for ip in IPV4_REGEX.findall(s):
                            if len(unique_ips) >= 200:
                                break
                            if ip not in unique_ips:
                                unique_ips.add(ip)
                                result["hardcoded_ips"].append({
                                    "indicator": ip,
                                    "type": "hardcoded_ip",
                                    "source": "dex_string",
                                    "reason": "Hardcoded IPv4 address observed in application code"
                                })
                            
                    # URLs
                    if len(unique_urls) < 200:
                        for url in URL_REGEX.findall(s):
                            if len(unique_urls) >= 200:
                                break
                            if url not in unique_urls:
                                unique_urls.add(url)
                                result["urls"].append({
                                    "indicator": url,
                                    "type": "url",
                                    "source": "dex_string",
                                    "reason": "Hardcoded URL observed in application code"
                                })
                            
                    # Base64
                    if len(unique_encoded) < 200 and is_valid_base64(s):
                        if s not in unique_encoded:
                            unique_encoded.add(s)
                            
                            decoded_str = ""
                            decoded_indicators = []
                            try:
                                decoded_bytes = base64.b64decode(s)
                                decoded_str = decoded_bytes.decode('utf-8')
                                
                                # Check decoded string for URLs or IPs
                                for dec_ip in IPV4_REGEX.findall(decoded_str):
                                    decoded_indicators.append(f"IP: {dec_ip}")
                                    
                                for dec_url in URL_REGEX.findall(decoded_str):
                                    decoded_indicators.append(f"URL: {dec_url}")
                                    
                            except Exception:
                                pass # Not real utf-8 base64
                                
                            result["encoded_strings"].append({
                                "encoding": "base64",
                                "original": s,
                                "decoded": decoded_str,
                                "detected_indicators": decoded_indicators,
                                "source": "dex_string"
                            })

                # 2. Analyze Methods for Suspicious APIs
                for method in dex.get_methods():
                    class_name = method.get_class_name()
                    method_name = method.get_name()
                    
                    # Convert Ljava/lang/Runtime; to java.lang.Runtime
                    clean_class_name = class_name.lstrip('L').rstrip(';').replace('/', '.')
                    
                    if clean_class_name in SUSPICIOUS_APIS:
                        rule = SUSPICIOUS_APIS[clean_class_name]
                        methods = rule.get('methods', [])
                        if isinstance(methods, list) and method_name in methods:
                            if len(result["suspicious_apis"]) < 200:
                                api_sig = f"{clean_class_name}.{method_name}"
                                if api_sig not in detected_apis:
                                    detected_apis.add(api_sig)
                                    
                                    result["suspicious_apis"].append({
                                        "api": api_sig,
                                        "class": clean_class_name,
                                        "method": method_name,
                                        "source": "dex_method",
                                        "reason": str(rule.get("reason", ""))
                                    })
                                    
                                    weight_val = rule.get("weight", 0)
                                    weight = int(weight_val) if isinstance(weight_val, (int, str)) else 0
                                    
                                    result["risk_factors"].append({
                                        "indicator": api_sig,
                                        "weight": weight,
                                        "evidence": f"Suspicious API usage detected in DEX: {api_sig}"
                                    })
                                    
                                    result["findings_data"].append({
                                        "title": f"Suspicious API: {api_sig}",
                                        "description": str(rule.get("reason", "")),
                                        "severity": "HIGH",
                                        "category": "Code",
                                        "evidence": api_sig,
                                        "mitre_technique_id": str(rule.get("mitre", "")),
                                        "confidence": 1.0
                                    })

            except Exception as e:
                logger.error(f"Failed to parse individual DEX file: {e}")
                
    except Exception as e:
        logger.error(f"DEX analysis failed: {e}")
        
    return result
