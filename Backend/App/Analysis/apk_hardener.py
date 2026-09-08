import subprocess
import os
import shutil
import re
from ..config import settings
from ..utils.signing import sign_apk

class APKHardener:
    def __init__(self):
        self.apktool_path = settings.APKTOOL_PATH or "apktool"
        self.output_dir = "/tmp/hardened_apks"

    def harden(self, apk_path):
        if not shutil.which(self.apktool_path):
            return None
        apk_name = os.path.basename(apk_path).replace('.apk', '')
        work_dir = os.path.join(self.output_dir, apk_name)
        os.makedirs(work_dir, exist_ok=True)
        try:
            subprocess.run([self.apktool_path, "d", apk_path, "-o", work_dir, "-f"], check=True)
            manifest_path = os.path.join(work_dir, "AndroidManifest.xml")
            self._patch_manifest(manifest_path)
            self._add_network_security_config(work_dir)
            rebuilt_path = os.path.join(work_dir, "dist", f"{apk_name}.apk")
            subprocess.run([self.apktool_path, "b", work_dir, "-o", rebuilt_path], check=True)
            signed_path = self._sign_apk(rebuilt_path)
            return signed_path
        except Exception as e:
            print(f"Hardening failed: {e}")
            return None

    def _patch_manifest(self, manifest_path):
        with open(manifest_path, 'r', encoding='utf-8') as f:
            content = f.read()
        if 'android:usesCleartextTraffic' not in content:
            content = re.sub(r'(<application[^>]*?)>', r'\1 android:usesCleartextTraffic="false">', content, count=1)
        else:
            content = re.sub(r'android:usesCleartextTraffic="true"', 'android:usesCleartextTraffic="false"', content)
        dangerous_perms = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.RECORD_AUDIO',
            'android.permission.CAMERA',
            'android.permission.READ_PHONE_STATE',
        ]
        for perm in dangerous_perms:
            content = re.sub(rf'<uses-permission\s+android:name="{re.escape(perm)}"\s*/>', '', content)
        content = re.sub(r'android:debuggable="true"', 'android:debuggable="false"', content)
        with open(manifest_path, 'w', encoding='utf-8') as f:
            f.write(content)

    def _add_network_security_config(self, work_dir):
        res_dir = os.path.join(work_dir, "res", "xml")
        os.makedirs(res_dir, exist_ok=True)
        config_path = os.path.join(res_dir, "network_security_config.xml")
        with open(config_path, 'w') as f:
            f.write('''<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>''')
        manifest_path = os.path.join(work_dir, "AndroidManifest.xml")
        with open(manifest_path, 'r') as f:
            content = f.read()
        if 'android:networkSecurityConfig' not in content:
            content = re.sub(r'(<application[^>]*?)>', r'\1 android:networkSecurityConfig="@xml/network_security_config">', content, count=1)
        with open(manifest_path, 'w') as f:
            f.write(content)

    def _sign_apk(self, apk_path):
        return sign_apk(apk_path)