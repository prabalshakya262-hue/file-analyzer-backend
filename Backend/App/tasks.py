from .celery_app import celery_app
from .config import settings
from .database import SessionLocal
from . import models
from .analysis.pe_analyzer import analyze_pe
from .analysis.apk_analyzer import analyze_apk
from .analysis.yara_scanner import scan_with_yara
from .analysis.dynamic_analyzer import DynamicAnalyzer
from .analysis.apk_hardener import APKHardener
from .analysis.pe_hardener import PEHardener
from .analysis.original_signer import sign_original
from .analysis.report_generator import generate_report
import os
import json
import time

@celery_app.task(bind=True)
def analyze_file(self, file_id: str, file_path: str, ext: str):
    db = SessionLocal()
    try:
        report = db.query(models.AnalysisReport).filter(models.AnalysisReport.file_id == file_id).first()
        if not report:
            raise Exception("Report not found in DB")
        report.status = "processing"
        db.commit()

        self.update_state(state="PROGRESS", meta={"progress": 10, "status": "Static analysis"})

        raw_results = {}
        if ext == ".exe":
            raw_results = analyze_pe(file_path)
            raw_results["yara_matches"] = scan_with_yara(file_path)
        elif ext == ".apk":
            raw_results = analyze_apk(file_path)

        self.update_state(state="PROGRESS", meta={"progress": 30, "status": "Dynamic analysis"})

        if settings.ENABLE_DYNAMIC_ANALYSIS:
            analyzer = DynamicAnalyzer()
            dynamic_results = analyzer.analyze(file_path, ext)
            raw_results["dynamic_analysis"] = dynamic_results
        else:
            raw_results["dynamic_analysis"] = {"status": "disabled", "reason": "Dynamic analysis not enabled"}

        self.update_state(state="PROGRESS", meta={"progress": 50, "status": "Hardening"})

        if ext == ".apk" and settings.ENABLE_APK_HARDENING:
            hardener = APKHardener()
            hardened_path = hardener.harden(file_path)
            if hardened_path:
                raw_results["hardened_apk_path"] = hardened_path
                report.hardened_apk_path = hardened_path
        elif ext == ".exe" and settings.ENABLE_PE_HARDENING:
            hardener = PEHardener()
            hardened_path = hardener.harden(file_path)
            if hardened_path:
                raw_results["hardened_exe_path"] = hardened_path
                report.hardened_exe_path = hardened_path

        if settings.ENABLE_ORIGINAL_SIGNING:
            signed_original = sign_original(file_path, ext)
            if signed_original:
                raw_results["signed_original_path"] = signed_original
                report.signed_original_path = signed_original

        self.update_state(state="PROGRESS", meta={"progress": 70, "status": "Generating report"})

        report_markdown, report_json = generate_report(file_id, file_path, raw_results)
        report.report_markdown = report_markdown
        report.report_json = report_json
        report.raw_json = raw_results
        report.status = "completed"
        db.commit()

        if settings.EMAIL_ENABLED:
            send_email_notification(report)

        return {"file_id": file_id, "status": "completed", "report": report_markdown}
    except Exception as e:
        report.status = "failed"
        db.commit()
        raise
    finally:
        db.close()

def send_email_notification(report):
    import smtplib
    from email.mime.text import MIMEText
    try:
        msg = MIMEText(f"Your analysis for {report.file_name} is complete. View report at http://frontend/report/{report.file_id}")
        msg["Subject"] = "Analysis Completed"
        msg["From"] = settings.EMAIL_FROM
        msg["To"] = report.owner.email
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"Email failed: {e}")