"""
Database initialization script
Creates all tables in the database from SQLAlchemy models
"""
from database import Base, engine
from models import User, Password, MFATOTP
import sys

def init_database():
    """Initialize database by creating all tables"""
    try:
        print("🔄 Initializing database...")
        print(f"📊 Database URL: {engine.url}")
        
        # Create all tables
        Base.metadata.create_all(bind=engine)
        
        print("✅ Database tables created successfully!")
        print("\n📋 Tables created:")
        print("  - users (email, password_hash, verification, etc.)")
        print("  - passwords (encrypted password storage)")
        print("  - mfa_totp (2FA authentication)")
        
        return True
        
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        print(f"Error type: {type(e).__name__}")
        sys.exit(1)

def drop_all_tables():
    """Drop all tables (use with caution!)"""
    try:
        print("⚠️  WARNING: Dropping all tables...")
        Base.metadata.drop_all(bind=engine)
        print("✅ All tables dropped successfully!")
        return True
    except Exception as e:
        print(f"❌ Error dropping tables: {e}")
        return False

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--drop":
        confirm = input("⚠️  Are you sure you want to drop all tables? (yes/no): ")
        if confirm.lower() == "yes":
            drop_all_tables()
            print("\n🔄 Now creating tables...")
            init_database()
        else:
            print("❌ Operation cancelled.")
    else:
        init_database()
