import os

# Force MockDatabase + MockLLMClient during tests.
# app.config calls load_dotenv(), which only fills vars that are *absent* from
# os.environ — so popping them let backend/.env re-inject the real Supabase and
# Groq credentials (tests then hit production). Setting them to empty strings
# stops load_dotenv from overriding while still reading as "not configured".
for _var in ("DATABASE_URL", "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY",
             "GROQ_API_KEY", "GEMINI_API_KEY"):
    os.environ[_var] = ""
# get_db() raises unless mock fallback is explicitly allowed.
os.environ["ALLOW_MOCK_DB"] = "true"
