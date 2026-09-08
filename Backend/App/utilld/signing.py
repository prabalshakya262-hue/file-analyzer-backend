import subprocess
import shutil
import os
from ..config import settings

def sign_apk(apk_path):
    if not settings.CODE_SIGN_CERT_PATH or not settings.CODE_SIGN_CERT_PASSWORD:
        return apk_path
    signed_path = apk_path.replace('.apk', '_signed.apk')
    if shutil.which("apksigner"):
        cmd = [
            "apksigner", "sign",
            "--ks", settings.CODE_SIGN_CERT_PATH,
            "--ks-pass", f"pass:{settings.CODE_SIGN_CERT_PASSWORD}",
            "--ks-key-alias", settings.CODE_SIGN_KEY_ALIAS,
            "--out", signed_path,
            apk_path
        ]
        subprocess.run(cmd, check=True)
        return signed_path
    elif shutil.which("jarsigner"):
        shutil.copy(apk_path, signed_path)
        cmd = [
            "jarsigner", "-sigalg", "SHA256withRSA",
            "-digestalg", "SHA-256",
            "-keystore", settings.CODE_SIGN_CERT_PATH,
            "-storepass", settings.CODE_SIGN_CERT_PASSWORD,
            signed_path, settings.CODE_SIGN_KEY_ALIAS
        ]
        subprocess.run(cmd, check=True)
        return signed_path
    else:
        return apk_path

def sign_pe(pe_path):
    if not settings.CODE_SIGN_CERT_PATH or not settings.CODE_SIGN_CERT_PASSWORD:
        return pe_path
    signed_path = pe_path.replace('.exe', '_signed.exe')
    if shutil.which("osslsigncode"):
        cmd = [
            "osslsigncode", "sign",
            "-pkcs12", settings.CODE_SIGN_CERT_PATH,
            "-pass", settings.CODE_SIGN_CERT_PASSWORD,
            "-in", pe_path,
            "-out", signed_path
        ]
        subprocess.run(cmd, check=True)
        return signed_path
    elif shutil.which("signtool"):
        cmd = [
            "signtool", "sign",
            "/f", settings.CODE_SIGN_CERT_PATH,
            "/p", settings.CODE_SIGN_CERT_PASSWORD,
            "/fd", "SHA256",
            "/out", signed_path,
            pe_path
        ]
        subprocess.run(cmd, check=True)
        return signed_path
    else:
        return pe_path