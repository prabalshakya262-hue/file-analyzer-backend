from androguard.core.apk import APK
import hashlib
import re

def analyze_apk(file_path):
    results = {
        "file_type": "APK",
        "hashes": {},
        "permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "exported_components": [],
        "network_security": {},
        "hardcoded_secrets": [],
        "libraries": [],
        "certificate": {},
        "manifest_analysis": {},
        "signature": {},
        "dex_analysis": {},
    }
    with open(file_path, "rb") as f:
        data = f.read()
        results["hashes"]["sha256"] = hashlib.sha256(data).hexdigest()
        results["hashes"]["md5"] = hashlib.md5(data).hexdigest()
        results["hashes"]["sha1"] = hashlib.sha1(data).hexdigest()

    try:
        a = APK(file_path)
        results["package_name"] = a.get_package()
        results["min_sdk"] = a.get_min_sdk_version()
        results["target_sdk"] = a.get_target_sdk_version()
        results["permissions"] = a.get_permissions()
        results["activities"] = a.get_activities()
        results["services"] = a.get_services()
        results["receivers"] = a.get_receivers()
        results["providers"] = a.get_providers()
        results["libraries"] = a.get_libraries()

        manifest = a.get_android_manifest_xml()
        manifest_str = manifest.toxml()
        results["manifest_analysis"]["xml"] = manifest_str
        results["manifest_analysis"]["debuggable"] = a.get_attribute_value('application', 'debuggable')
        results["manifest_analysis"]["allow_backup"] = a.get_attribute_value('application', 'allowBackup')
        results["manifest_analysis"]["uses_cleartext_traffic"] = a.get_attribute_value('application', 'usesCleartextTraffic')

        exported_activities = re.findall(r'<activity[^>]*android:exported="true"[^>]*>', manifest_str, re.IGNORECASE)
        exported_services = re.findall(r'<service[^>]*android:exported="true"[^>]*>', manifest_str, re.IGNORECASE)
        exported_receivers = re.findall(r'<receiver[^>]*android:exported="true"[^>]*>', manifest_str, re.IGNORECASE)
        results["exported_components"] = exported_activities + exported_services + exported_receivers
        components_with_intent = re.findall(r'<(activity|service|receiver)[^>]*>.*?<intent-filter>', manifest_str, re.DOTALL)
        results["components_with_intent_filter"] = components_with_intent

        results["network_security"]["has_network_security_config"] = a.get_file("res/xml/network_security_config.xml") is not None

        try:
            dex_files = a.get_all_dex()
            secrets = []
            for dex in dex_files:
                for string in dex.get_strings():
                    if re.search(r'(api[_-]?key|secret|token|password|passwd|auth)', string, re.IGNORECASE):
                        secrets.append(string)
            results["hardcoded_secrets"] = secrets[:50]
        except:
            results["hardcoded_secrets"] = ["Could not extract DEX strings"]

        cert = a.get_certificate()
        if cert:
            results["certificate"]["subject"] = str(cert.subject)
            results["certificate"]["issuer"] = str(cert.issuer)
            results["certificate"]["serial_number"] = str(cert.serial_number)
            results["certificate"]["not_before"] = str(cert.not_valid_before)
            results["certificate"]["not_after"] = str(cert.not_valid_after)

        results["signature"]["v1"] = a.is_signed_v1()
        results["signature"]["v2"] = a.is_signed_v2()
        results["signature"]["v3"] = a.is_signed_v3()
    except Exception as e:
        results["error"] = f"Failed to parse APK: {str(e)}"
    return results