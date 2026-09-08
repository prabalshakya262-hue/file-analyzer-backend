import requests
import time
import json
import os
from ..config import settings

class DynamicAnalyzer:
    def __init__(self):
        self.cuckoo_url = settings.CUCKOO_API_URL.rstrip('/')
        self.cuckoo_token = settings.CUCKOO_API_TOKEN
        self.mobsf_url = settings.MOBSF_API_URL.rstrip('/')
        self.mobsf_key = settings.MOBSF_API_KEY
        self.timeout = settings.DYNAMIC_TIMEOUT

    def analyze(self, file_path, file_type):
        if file_type == ".exe":
            return self._analyze_pe(file_path)
        elif file_type == ".apk":
            return self._analyze_apk(file_path)
        else:
            return {"error": "Unsupported file type for dynamic analysis"}

    def _analyze_pe(self, file_path):
        if not self.cuckoo_url:
            return {"status": "skipped", "reason": "Cuckoo sandbox not configured"}
        try:
            files = {"file": open(file_path, "rb")}
            headers = {"Authorization": f"Bearer {self.cuckoo_token}"} if self.cuckoo_token else {}
            res = requests.post(f"{self.cuckoo_url}/tasks/create/file", files=files, headers=headers)
            if res.status_code != 200:
                return {"status": "error", "error": f"Cuckoo submission failed: {res.text}"}
            task_id = res.json().get("task_id")
            if not task_id:
                return {"status": "error", "error": "No task ID returned"}
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                report_res = requests.get(f"{self.cuckoo_url}/tasks/report/{task_id}", headers=headers)
                if report_res.status_code == 200:
                    return {"status": "completed", "task_id": task_id, "report": report_res.json()}
                elif report_res.status_code == 404:
                    time.sleep(10)
                else:
                    return {"status": "error", "error": f"Error fetching report: {report_res.text}"}
            return {"status": "timeout", "error": "Dynamic analysis timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _analyze_apk(self, file_path):
        if not self.mobsf_url:
            return {"status": "skipped", "reason": "MobSF not configured"}
        try:
            files = {"file": open(file_path, "rb")}
            headers = {"Authorization": self.mobsf_key} if self.mobsf_key else {}
            upload_res = requests.post(f"{self.mobsf_url}/api/v1/upload", files=files, headers=headers)
            if upload_res.status_code != 200:
                return {"status": "error", "error": f"MobSF upload failed: {upload_res.text}"}
            upload_data = upload_res.json()
            scan_hash = upload_data.get("hash")
            if not scan_hash:
                return {"status": "error", "error": "No hash returned from MobSF"}
            start_res = requests.post(f"{self.mobsf_url}/api/v1/dynamic/start_analysis", data={"hash": scan_hash}, headers=headers)
            if start_res.status_code != 200:
                return {"status": "error", "error": f"Failed to start dynamic analysis: {start_res.text}"}
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                dyn_res = requests.get(f"{self.mobsf_url}/api/v1/dynamic/report_json", params={"hash": scan_hash}, headers=headers)
                if dyn_res.status_code == 200 and dyn_res.json():
                    return {"status": "completed", "hash": scan_hash, "report": dyn_res.json()}
                time.sleep(10)
            return {"status": "timeout", "error": "Dynamic analysis timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}