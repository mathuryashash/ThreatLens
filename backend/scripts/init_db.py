import os
import sys
import psycopg2
from dotenv import load_dotenv

# Add parent directory to path to allow running directly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def init_db():
    load_dotenv()
    
    # Try getting DATABASE_URL first
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("Error: DATABASE_URL environment variable is not set.")
        print("Please set it in your environment or in backend/.env")
        print("Format: postgresql://postgres:password@db.xxxxxx.supabase.co:5432/postgres")
        sys.exit(1)
        
    print(f"Connecting to database...")
    try:
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        cursor = conn.cursor()
        
        print("Reading database schema...")
        # Path to schema file
        schema_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "docs", "optional", "DATABASE_SCHEMA.md"
        )
        
        if not os.path.exists(schema_path):
            # Try absolute path or fallback
            schema_path = "docs/optional/DATABASE_SCHEMA.md"
            
        with open(schema_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Extract SQL block from markdown
        import re
        sql_blocks = re.findall(r"```sql\n(.*?)\n```", content, re.DOTALL)
        if not sql_blocks:
            print("Error: Could not find SQL block in DATABASE_SCHEMA.md")
            sys.exit(1)
            
        sql_script = sql_blocks[0]
        
        print("Executing SQL schema...")
        cursor.execute(sql_script)
        print("Database schema successfully applied!")
        
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Database initialization failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    init_db()
