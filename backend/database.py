import os
import sqlite3
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime
import bcrypt

# Current database schema version
CURRENT_DB_VERSION = 3

# Database setup
DATABASE_URL = "sqlite:///./data/nuki_users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    smartlock_permissions = relationship("UserSmartlockPermission", back_populates="user", cascade="all, delete-orphan")
    auth_permissions = relationship("UserAuthPermission", back_populates="user", cascade="all, delete-orphan", uselist=False)
    specific_auth_access = relationship("UserSpecificAuthAccess", back_populates="user", cascade="all, delete-orphan")

class UserSmartlockPermission(Base):
    __tablename__ = "user_smartlock_permissions"
    
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    smartlock_id = Column(Integer, primary_key=True)
    can_view = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="smartlock_permissions")

class UserAuthPermission(Base):
    __tablename__ = "user_auth_permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    can_create_auth = Column(Boolean, default=False)
    can_edit_auth = Column(Boolean, default=False)
    can_delete_auth = Column(Boolean, default=False)
    
    # Relationships
    user = relationship("User", back_populates="auth_permissions")

class UserSpecificAuthAccess(Base):
    __tablename__ = "user_specific_auth_access"
    
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    auth_id = Column(String, primary_key=True)
    can_edit = Column(Boolean, default=False)
    can_delete = Column(Boolean, default=False)
    can_not_edit = Column(Boolean, default=False)
    
    # Relationships
    user = relationship("User", back_populates="specific_auth_access")

class SmartlockGroup(Base):
    __tablename__ = "smartlock_groups"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    creator = relationship("User")
    members = relationship("SmartlockGroupMember", back_populates="group", cascade="all, delete-orphan")

class SmartlockGroupMember(Base):
    __tablename__ = "smartlock_group_members"
    
    group_id = Column(Integer, ForeignKey("smartlock_groups.id"), primary_key=True)
    smartlock_id = Column(Integer, primary_key=True)
    
    # Relationships
    group = relationship("SmartlockGroup", back_populates="members")

class DatabaseVersion(Base):
    __tablename__ = "database_version"
    
    id = Column(Integer, primary_key=True, index=True)
    version = Column(Integer, nullable=False)
    applied_at = Column(DateTime, default=datetime.utcnow)
    description = Column(String, nullable=True)

# Database functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_database():
    """Initialize database and create tables"""
    Base.metadata.create_all(bind=engine)
    
def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_initial_admin(db: Session):
    """Create initial admin user from environment variable"""
    initial_admin = os.getenv("INITIAL_ADMIN_USER", "")
    if not initial_admin:
        return
    
    if ':' not in initial_admin:
        return
    
    username, password = initial_admin.split(':', 1)
    
    # Check if admin already exists
    existing_admin = db.query(User).filter(User.username == username).first()
    if existing_admin:
        return
    
    # Create admin user
    admin_user = User(
        username=username,
        password_hash=hash_password(password),
        is_admin=True,
        created_at=datetime.utcnow()
    )
    
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)
    
    # Create default auth permissions for admin
    auth_permissions = UserAuthPermission(
        user_id=admin_user.id,
        can_create_auth=True,
        can_edit_auth=True,
        can_delete_auth=True
    )
    
    db.add(auth_permissions)
    db.commit()
    
    print(f"Created initial admin user: {username}")

def migrate_legacy_users(db: Session):
    """Migrate users from LOGIN_USERS environment variable"""
    login_users = os.getenv("LOGIN_USERS", "")
    if not login_users:
        return
    
    initial_admin = os.getenv("INITIAL_ADMIN_USER", "")
    admin_username = initial_admin.split(':', 1)[0] if ':' in initial_admin else ""
    
    for user_pair in login_users.split(','):
        if ':' not in user_pair:
            continue
            
        username, password = user_pair.strip().split(':', 1)
        
        # Skip if user already exists
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            continue
        
        # Skip if this is the admin user (already created)
        if username == admin_username:
            continue
        
        # Create regular user
        user = User(
            username=username,
            password_hash=hash_password(password),
            is_admin=False,
            created_at=datetime.utcnow()
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Create default auth permissions for regular user
        auth_permissions = UserAuthPermission(
            user_id=user.id,
            can_create_auth=False,
            can_edit_auth=False,
            can_delete_auth=False
        )
        
        db.add(auth_permissions)
        db.commit()
        
        print(f"Migrated user: {username}")

def get_db_version(db: Session) -> int:
    """Get current database version"""
    try:
        version_record = db.query(DatabaseVersion).order_by(DatabaseVersion.version.desc()).first()
        return version_record.version if version_record else 0
    except Exception:
        # Table doesn't exist yet, this is a new database
        return 0

def apply_migrations(db: Session, current_version: int):
    """Apply database migrations"""
    if current_version < 1:
        print("Applying migration to version 1: Initial database setup")
        
        # Create initial admin and migrate legacy users
        create_initial_admin(db)
        migrate_legacy_users(db)
        
        # Record this migration
        version_record = DatabaseVersion(
            version=1,
            description="Initial database setup with user management"
        )
        db.add(version_record)
        db.commit()
        
        print("✅ Migration to version 1 completed")
    
    if current_version < 2:
        print("Applying migration to version 2: Add can_not_edit column to specific auth access")
        
        # Add can_not_edit column to user_specific_auth_access table
        try:
            db.execute("ALTER TABLE user_specific_auth_access ADD COLUMN can_not_edit BOOLEAN DEFAULT FALSE")
            db.commit()
            print("✅ Added can_not_edit column to user_specific_auth_access table")
        except Exception as e:
            # Column might already exist, check if it's a duplicate column error
            if "duplicate column name" in str(e).lower():
                print("✅ can_not_edit column already exists in user_specific_auth_access table")
            else:
                print(f"⚠️ Error adding can_not_edit column: {e}")
                # Continue anyway, the column might exist
        
        # Record this migration
        version_record = DatabaseVersion(
            version=2,
            description="Add can_not_edit column to specific auth access"
        )
        db.add(version_record)
        db.commit()
        
        print("✅ Migration to version 2 completed")
    
    if current_version < 3:
        print("Applying migration to version 3: Add smartlock groups tables")
        
        # The new tables will be automatically created by init_database()
        # since we call Base.metadata.create_all(bind=engine) which creates all tables
        
        # Record this migration
        version_record = DatabaseVersion(
            version=3,
            description="Add smartlock groups and group members tables"
        )
        db.add(version_record)
        db.commit()
        
        print("✅ Migration to version 3 completed")

def get_auth_permissions(db: Session, auth_id: str):
    """Get all user permissions for a specific authorization"""
    return db.query(UserSpecificAuthAccess).filter(
        UserSpecificAuthAccess.auth_id == auth_id
    ).all()

def copy_auth_permissions(db: Session, old_auth_id: str, new_auth_id: str):
    """Copy all permissions from old auth to new auth"""
    old_permissions = get_auth_permissions(db, old_auth_id)
    
    for old_perm in old_permissions:
        # Check if permission already exists for this user and new auth
        existing_perm = db.query(UserSpecificAuthAccess).filter(
            UserSpecificAuthAccess.user_id == old_perm.user_id,
            UserSpecificAuthAccess.auth_id == new_auth_id
        ).first()
        
        if not existing_perm:
            new_perm = UserSpecificAuthAccess(
                user_id=old_perm.user_id,
                auth_id=new_auth_id,
                can_edit=old_perm.can_edit,
                can_delete=old_perm.can_delete,
                can_not_edit=old_perm.can_not_edit
            )
            db.add(new_perm)
    
    db.commit()
    return len(old_permissions)

def setup_database():
    """Setup database with automatic migrations"""
    # Ensure data directory exists
    os.makedirs("./data", exist_ok=True)
    
    # Check if database file exists
    db_file_exists = os.path.exists("./data/nuki_users.db")
    
    # Always create tables (safe operation, won't overwrite existing data)
    init_database()
    
    db = SessionLocal()
    try:
        current_version = get_db_version(db)
        
        if current_version < CURRENT_DB_VERSION:
            if not db_file_exists:
                print(f"🆕 Creating new database (version {CURRENT_DB_VERSION})")
            else:
                print(f"🔄 Migrating database from version {current_version} to {CURRENT_DB_VERSION}")
            
            apply_migrations(db, current_version)
        else:
            print(f"✅ Database is up to date (version {current_version})")
            if db_file_exists:
                print("📁 Using existing database, ignoring .env user settings")
    finally:
        db.close()
