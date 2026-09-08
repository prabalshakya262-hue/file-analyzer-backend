from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
import uuid, os, json
import asyncio
from .config import settings
from .database import get_db, engine
from . import models, auth
from .tasks import analyze_file
from .celery_app import celery_app
from .rate_limit import RateLimiter

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="File Security Analyzer", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
rate_limiter = RateLimiter()

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db)
):
    if not rate_limiter.check(current_user.id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Only .exe and .apk files are allowed")

    content = await file.read()
    if len(content) > settings.MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large")

    if ext == ".exe" and not content.startswith(b'MZ'):
        raise HTTPException(status_code=400, detail="Invalid PE file")
    if ext == ".apk" and not content.startswith(b'PK'):
        raise HTTPException(status_code=400, detail="Invalid APK file")

    file_id = str(uuid.uuid4())
    file_path = os.path.join(settings.UPLOAD_DIR, f"{file_id}{ext}")
    with open(file_path, "wb") as f:
        f.write(content)

    report = models.AnalysisReport(
        file_id=file_id,
        owner_id=current_user.id,
        file_name=file.filename,
        file_type=ext[1:],
        status="queued"
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    task = analyze_file.delay(file_id, file_path, ext)
    return JSONResponse({"file_id": file_id, "task_id": task.id, "status": "queued"})

@app.get("/reports")
def list_reports(current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    reports = db.query(models.AnalysisReport).filter(models.AnalysisReport.owner_id == current_user.id).order_by(models.AnalysisReport.created_at.desc()).all()
    return reports

@app.get("/report/{file_id}")
def get_report(file_id: str, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    report = db.query(models.AnalysisReport).filter(
        models.AnalysisReport.file_id == file_id,
        models.AnalysisReport.owner_id == current_user.id
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report

@app.get("/status/{task_id}")
async def get_status(task_id: str):
    from celery.result import AsyncResult
    task = AsyncResult(task_id, app=celery_app)
    if task.state == "PENDING":
        return {"status": "pending"}
    elif task.state == "PROGRESS":
        return {"status": "progress", "meta": task.info}
    elif task.state == "SUCCESS":
        return {"status": "completed", "result": task.result}
    elif task.state == "FAILURE":
        return {"status": "failed", "error": str(task.result)}
    else:
        return {"status": task.state}

@app.websocket("/ws/{task_id}")
async def websocket_endpoint(websocket: WebSocket, task_id: str):
    await websocket.accept()
    from celery.result import AsyncResult
    task = AsyncResult(task_id, app=celery_app)
    while True:
        if task.state == "SUCCESS":
            await websocket.send_json({"status": "completed", "result": task.result})
            break
        elif task.state == "FAILURE":
            await websocket.send_json({"status": "failed", "error": str(task.result)})
            break
        elif task.state == "PROGRESS":
            await websocket.send_json({"status": "progress", "meta": task.info})
        else:
            await websocket.send_json({"status": "pending"})
        await asyncio.sleep(2)
    await websocket.close()

@app.get("/download/hardened/{file_id}")
async def download_hardened(file_id: str, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    report = db.query(models.AnalysisReport).filter(
        models.AnalysisReport.file_id == file_id,
        models.AnalysisReport.owner_id == current_user.id
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.hardened_apk_path and os.path.exists(report.hardened_apk_path):
        return FileResponse(report.hardened_apk_path, media_type="application/vnd.android.package-archive", filename="hardened.apk")
    if report.hardened_exe_path and os.path.exists(report.hardened_exe_path):
        return FileResponse(report.hardened_exe_path, media_type="application/octet-stream", filename="hardened.exe")
    raise HTTPException(status_code=404, detail="No hardened file available")

@app.get("/download/original/{file_id}")
async def download_original(file_id: str, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    report = db.query(models.AnalysisReport).filter(
        models.AnalysisReport.file_id == file_id,
        models.AnalysisReport.owner_id == current_user.id
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.signed_original_path and os.path.exists(report.signed_original_path):
        ext = os.path.splitext(report.signed_original_path)[1].lower()
        if ext == ".apk":
            return FileResponse(report.signed_original_path, media_type="application/vnd.android.package-archive", filename="signed_original.apk")
        else:
            return FileResponse(report.signed_original_path, media_type="application/octet-stream", filename="signed_original.exe")
    raise HTTPException(status_code=404, detail="No signed original available")