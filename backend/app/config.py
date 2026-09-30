import os
import warnings
from dotenv import load_dotenv

load_dotenv()

class Config:
    DATABASE_URL = os.environ.get("DATABASE_URL")
    SUPABASE_URL = os.environ.get("SUPABASE_URL")
    SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

    LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "groq").lower()
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
    GROQ_CLASSIFY_MODEL = os.environ.get("GROQ_CLASSIFY_MODEL") or "openai/gpt-oss-20b"
    GROQ_EXPLAIN_MODEL = os.environ.get("GROQ_EXPLAIN_MODEL") or "openai/gpt-oss-120b"
    GEMINI_MODEL = os.environ.get("GEMINI_MODEL") or "gemini-flash-latest"
    # Retry budget for LLM 429/5xx (Groq free tier is ~8k tokens/min).
    LLM_MAX_RETRIES = int(os.environ.get("LLM_MAX_RETRIES", 6))
    LLM_RETRY_MAX_WAIT = float(os.environ.get("LLM_RETRY_MAX_WAIT", 30))
    GROQ_REASONING_EFFORT = os.environ.get("GROQ_REASONING_EFFORT", "low")
    LLM_CONCURRENCY = max(1, int(os.environ.get("LLM_CONCURRENCY", 5)))

    PORT = int(os.environ.get("PORT", 8000))
    FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:3000")
    LLM_PROMPT_VERSION = os.environ.get("LLM_PROMPT_VERSION", "v1.0")
    ALLOWED_LOG_SOURCES = ["nginx", "auth", "syslog", "custom"]
    DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
    ALLOW_MOCK_DB = os.environ.get("ALLOW_MOCK_DB", "false").lower() == "true"

    @property
    def is_db_configured(self) -> bool:
        return bool(self.DATABASE_URL or (self.SUPABASE_URL and self.SUPABASE_SERVICE_ROLE_KEY))

    @property
    def is_llm_configured(self) -> bool:
        if self.LLM_PROVIDER == "groq" and self.GROQ_API_KEY:
            return True
        if self.LLM_PROVIDER == "gemini" and self.GEMINI_API_KEY:
            return True
        return False

settings = Config()

if (not settings.FRONTEND_ORIGIN.startswith("https://") and
        "localhost" not in settings.FRONTEND_ORIGIN and
        "127.0.0.1" not in settings.FRONTEND_ORIGIN):
    warnings.warn(
        f"FRONTEND_ORIGIN '{settings.FRONTEND_ORIGIN}' is not HTTPS — possible misconfiguration in production",
        stacklevel=1
    )
