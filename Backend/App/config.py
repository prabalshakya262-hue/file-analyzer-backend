import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    # Core
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./file_analyzer.db")
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
    REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

    # File upload
    MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", 50 * 1024 * 1024))
    ALLOWED_EXTENSIONS = {".exe", ".apk"}
    UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/uploads")
    REPORT_DIR = os.getenv("REPORT_DIR", "/tmp/reports")
    STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "local")

    # Analysis
    YARA_RULES_DIR = "app/analysis/yara_rules"
    ENABLE_DYNAMIC_ANALYSIS = os.getenv("ENABLE_DYNAMIC_ANALYSIS", "false").lower() == "true"
    CUCKOO_API_URL = os.getenv("CUCKOO_API_URL", "")
    CUCKOO_API_TOKEN = os.getenv("CUCKOO_API_TOKEN", "")
    MOBSF_API_URL = os.getenv("MOBSF_API_URL", "")
    MOBSF_API_KEY = os.getenv("MOBSF_API_KEY", "")
    DYNAMIC_TIMEOUT = int(os.getenv("DYNAMIC_TIMEOUT", 600))

    # Hardening
    ENABLE_APK_HARDENING = os.getenv("ENABLE_APK_HARDENING", "true").lower() == "true"
    ENABLE_PE_HARDENING = os.getenv("ENABLE_PE_HARDENING", "true").lower() == "true"
    ENABLE_ORIGINAL_SIGNING = os.getenv("ENABLE_ORIGINAL_SIGNING", "true").lower() == "true"
    APKTOOL_PATH = os.getenv("APKTOOL_PATH", "apktool")

    # Code Signing
    CODE_SIGN_CERT_PATH = os.getenv("CODE_SIGN_CERT_PATH", "")
    CODE_SIGN_CERT_PASSWORD = os.getenv("CODE_SIGN_CERT_PASSWORD", "")
    CODE_SIGN_KEY_ALIAS = os.getenv("CODE_SIGN_KEY_ALIAS", "")

    # LLM
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4-turbo-preview")
    OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")

    # Email
    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    EMAIL_FROM = os.getenv("EMAIL_FROM", "")
    EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"

    # Rate limiting
    RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", 10))

settings = Settings()
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.REPORT_DIR, exist_ok=True)
os.makedirs(settings.YARA_RULES_DIR, exist_ok=True)