import pefile
import hashlib
import math
import re
import os

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def analyze_pe(file_path):
    results = {
        "file_type": "PE32",
        "hashes": {},
        "sections": [],
        "imports": [],
        "suspicious_imports": [],
        "entropy": {},
        "strings_suspicious": [],
        "yara_matches": [],
        "packer_indicators": [],
        "security_features": {},
        "version_info": {},
    }
    with open(file_path, "rb") as f:
        data = f.read()
        results["hashes"]["sha256"] = hashlib.sha256(data).hexdigest()
        results["hashes"]["md5"] = hashlib.md5(data).hexdigest()
        results["hashes"]["sha1"] = hashlib.sha1(data).hexdigest()
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        results["error"] = f"Failed to parse PE: {str(e)}"
        return results

    results["machine"] = hex(pe.FILE_HEADER.Machine)
    results["timestamp"] = pe.FILE_HEADER.TimeDateStamp
    results["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)

    for section in pe.sections:
        name = section.Name.decode().rstrip('\x00')
        entropy = section.get_entropy()
        results["sections"].append({
            "name": name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": entropy,
        })
        if entropy > 7.0:
            results["packer_indicators"].append(f"High entropy in section {name} ({entropy:.2f})")
        if name not in ['.text', '.data', '.rdata', '.bss', '.idata', '.edata', '.rsrc', '.reloc']:
            results["packer_indicators"].append(f"Unusual section name: {name}")

    suspicious_apis = [
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
        "LoadLibrary", "GetProcAddress", "WinExec", "ShellExecute", "OpenProcess",
        "AdjustTokenPrivileges", "RegSetValue", "CryptEncrypt", "socket", "bind",
        "listen", "connect", "recv", "send", "CreateFile", "ReadFile", "WriteFile",
        "DeleteFile", "MoveFile", "CopyFile", "SetWindowsHookEx", "GetAsyncKeyState",
        "GetForegroundWindow", "GetWindowText", "CreateToolhelp32Snapshot", "Process32First",
        "Process32Next", "TerminateProcess", "OpenProcessToken", "LookupPrivilegeValue",
        "AdjustTokenPrivileges"
    ]
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode()
            for imp in entry.imports:
                if imp.name:
                    api_name = imp.name.decode()
                    results["imports"].append(f"{dll_name}!{api_name}")
                    if api_name in suspicious_apis:
                        results["suspicious_imports"].append(f"{dll_name}!{api_name}")

    dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    results["security_features"]["ASLR"] = bool(dll_characteristics & 0x0040)
    results["security_features"]["DEP"] = bool(dll_characteristics & 0x0100)
    results["security_features"]["SafeSEH"] = False
    if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
        results["security_features"]["SafeSEH"] = True
    results["security_features"]["HighEntropyVA"] = bool(dll_characteristics & 0x0020)
    results["security_features"]["ForceIntegrity"] = bool(dll_characteristics & 0x0080)
    results["security_features"]["GuardCF"] = bool(dll_characteristics & 0x4000)

    strings = re.findall(rb'[ -~]{5,}', data)
    suspicious_patterns = [
        b"http://", b"https://", b"cmd.exe", b"powershell", b"eval", b"base64",
        b"password", b"api_key", b"secret", b"token", b"SELECT * FROM", b"DROP TABLE"
    ]
    for s in strings:
        for pat in suspicious_patterns:
            if pat.lower() in s.lower():
                results["strings_suspicious"].append(s.decode(errors='ignore'))
                break
    results["strings_suspicious"] = results["strings_suspicious"][:30]

    if hasattr(pe, 'FileInfo'):
        for fileinfo in pe.FileInfo:
            for entry in fileinfo:
                if hasattr(entry, 'StringTable'):
                    for st in entry.StringTable:
                        for k, v in st.entries.items():
                            results["version_info"][k.decode()] = v.decode()
    return results