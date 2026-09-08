from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    reports = relationship("AnalysisReport", back_populates="owner")

class AnalysisReport(Base):
    __tablename__ = "analysis_reports"
    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(String, unique=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    file_name = Column(String)
    file_type = Column(String)
    sha256 = Column(String)
    status = Column(String)
    report_markdown = Column(Text, nullable=True)
    report_json = Column(JSON, nullable=True)
    raw_json = Column(JSON, nullable=True)
    hardened_apk_path = Column(String, nullable=True)
    hardened_exe_path = Column(String, nullable=True)
    signed_original_path = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", back_populates="reports")