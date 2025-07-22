import os
import logging
import re
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import requests
import jwt
from datetime import datetime, timedelta
import hashlib
from sqlalchemy.orm import Session

# Import our new modules
from database import get_db, setup_database, User, UserSmartlockPermission, UserAuthPermission, UserSpecificAuthAccess, hash_password, verify_password, get_auth_permissions, copy_auth_permissions
from models import (
    UserCreate, UserUpdate, UserResponse, UserWithPermissions, UserPermissions, 
    UserPermissionsUpdate, AdminStatusUpdate, CurrentUserInfo, SmartlockPermission,
    AuthPermissions, SpecificAuthAccess
)

logging.basicConfig(level=logging.INFO)

def clean_user_name(name):
    """Clean user names from encoding artifacts and garbage characters"""
    if not name:
        return name
    
    # Convert to string if not already
    original_name = str(name)
    cleaned = original_name
    
    # Remove Unicode replacement characters and diamond characters first
    cleaned = re.sub(r'[\uFFFD\u25C6\u2666\u2665\u2663\u2660]', '', cleaned)
    
    # Remove null bytes and control characters
    cleaned = re.sub(r'[\x00-\x1F\x7F]', '', cleaned)
    
    # Remove specific problematic byte sequences
    cleaned = cleaned.replace('\xEF\xBF\xBD', '')  # UTF-8 replacement character
    cleaned = cleaned.replace('\xFF\xFE', '')  # BOM markers
    cleaned = cleaned.replace('\xFE\xFF', '')  # BOM markers
    
    # Remove other encoding artifacts and unknown characters (but preserve common European characters)
    cleaned = re.sub(r'[^\x20-\x7E\u00A0-\u017F\u0100-\u024F\u1E00-\u1EFF\u0370-\u03FF]', '', cleaned)
    
    # Remove trailing whitespace and invisible characters
    cleaned = re.sub(r'[\u00A0\u00AD\u200B-\u200D\uFEFF]+\s*$', '', cleaned)
    
    # Normalize whitespace
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    
    # Check if anything was actually cleaned/replaced
    was_cleaned = cleaned != original_name
    
    # If something was cleaned AND there's a trailing 'x', remove it
    if was_cleaned and cleaned.endswith('x'):
        # Only remove the 'x' if it's likely a garbage character
        # (i.e., if the name doesn't naturally end with 'x')
        potential_clean = cleaned[:-1].strip()
        if potential_clean and not potential_clean.lower().endswith(('max', 'alex', 'felix', 'marx', 'cox', 'fox', 'lux')):
            cleaned = potential_clean
    
    # Additional check: if name still ends with 'x' and we detected cleaning, be more aggressive
    if was_cleaned and cleaned.endswith('x'):
        # Check if removing the 'x' leaves a reasonable name
        without_x = cleaned[:-1].strip()
        if len(without_x) >= 2 and re.match(r'^[a-zA-ZäöüÄÖÜß\s]+$', without_x):
            cleaned = without_x
    
    return cleaned

def clean_log_data(logs):
    """Clean log data to remove encoding artifacts from user names"""
    if not isinstance(logs, list):
        return logs
    
    cleaned_logs = []
    for log in logs:
        if isinstance(log, dict):
            # Create a copy of the log entry
            cleaned_log = log.copy()
            
            # Clean the 'name' field if it exists
            if 'name' in cleaned_log and cleaned_log['name']:
                cleaned_log['name'] = clean_user_name(cleaned_log['name'])
            
            cleaned_logs.append(cleaned_log)
        else:
            cleaned_logs.append(log)
    
    return cleaned_logs

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    setup_database()
    yield
    # Shutdown (if needed in the future)

app = FastAPI(lifespan=lifespan)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

NUKI_API_URL = os.getenv("NUKI_API_URL", "https://api.nuki.io")
API_TOKEN = os.getenv("NUKI_API_TOKEN")
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-this")

if not API_TOKEN:
    raise RuntimeError("NUKI_API_TOKEN environment variable not set")

# Log which API we're using
logging.info(f"Using Nuki API at: {NUKI_API_URL}")

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# Security
security = HTTPBearer()

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    username: str

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm="HS256")
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_user(username: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Get current user from database (database authentication only)"""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found in database",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    return user

def get_current_db_user(username: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Get current user from database (required for new features)"""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found in database",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    return user

def require_admin(current_user: User = Depends(get_current_db_user)):
    """Require admin privileges"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

def check_smartlock_permission(smartlock_id: int, current_user: User, db: Session):
    """Check if user has permission to access a specific smartlock"""
    if current_user.is_admin:
        return True
    
    # Check if user has specific permission for this smartlock
    permission = db.query(UserSmartlockPermission).filter(
        UserSmartlockPermission.user_id == current_user.id,
        UserSmartlockPermission.smartlock_id == smartlock_id,
        UserSmartlockPermission.can_view == True
    ).first()
    
    return permission is not None

def check_auth_create_permission(current_user: User, smartlock_ids: list = None):
    """Check if user can create authorizations"""
    if current_user.is_admin:
        return True
    
    # Check general create permission
    if current_user.auth_permissions and current_user.auth_permissions.can_create_auth:
        return True
    
    # For authorization editing (moving between smartlocks), allow if user has edit permission
    if current_user.auth_permissions and current_user.auth_permissions.can_edit_auth:
        # If smartlock_ids provided, check if user has access to those smartlocks
        if smartlock_ids:
            user_smartlock_ids = {perm.smartlock_id for perm in current_user.smartlock_permissions if perm.can_view}
            # Allow if user has access to at least one of the target smartlocks
            if any(sl_id in user_smartlock_ids for sl_id in smartlock_ids):
                return True
        else:
            return True
    
    return False

def check_auth_edit_permission(auth_id: str, current_user: User, smartlock_id: int = None, db: Session = None):
    """Check if user can edit a specific authorization"""
    if current_user.is_admin:
        return True
    
    # First check if there's a specific permission for this auth
    specific_access = next((access for access in current_user.specific_auth_access 
                          if access.auth_id == auth_id), None)
    
    if specific_access:
        # If specific permission exists, use only that (overrides general permissions)
        return specific_access.can_edit
    
    # If no specific permission, check general edit permission (no smartlock check needed!)
    if current_user.auth_permissions and current_user.auth_permissions.can_edit_auth:
        return True
    
    return False

def check_auth_delete_permission(auth_id: str, current_user: User, smartlock_id: int = None, db: Session = None, allow_edit_as_delete: bool = False):
    """Check if user can delete a specific authorization"""
    if current_user.is_admin:
        return True
    
    # First check if there's a specific permission for this auth
    specific_access = next((access for access in current_user.specific_auth_access 
                          if access.auth_id == auth_id), None)
    
    if specific_access:
        # If specific permission exists, use only that (overrides general permissions)
        if specific_access.can_delete:
            return True
        # For editing operations, allow delete if user can edit (moving between smartlocks)
        if allow_edit_as_delete and specific_access.can_edit:
            return True
        return False
    
    # If no specific permission, check general permissions
    if current_user.auth_permissions:
        if current_user.auth_permissions.can_delete_auth:
            return True
        # For editing operations, allow delete if user can edit (moving between smartlocks)
        if allow_edit_as_delete and current_user.auth_permissions.can_edit_auth:
            return True
    
    return False

def filter_smartlocks_by_permission(smartlocks: list, current_user: User, db: Session):
    """Filter smartlocks based on user permissions"""
    if current_user.is_admin:
        return smartlocks
    
    # Get user's allowed smartlock IDs
    allowed_smartlock_ids = set()
    for perm in current_user.smartlock_permissions:
        if perm.can_view:
            allowed_smartlock_ids.add(perm.smartlock_id)
    
    # Filter smartlocks
    return [sl for sl in smartlocks if sl.get('smartlockId') in allowed_smartlock_ids]

def filter_auths_by_permission(auths: list, current_user: User):
    """Filter authorizations based on user permissions"""
    if current_user.is_admin:
        return auths
    
    # Get user's allowed smartlock IDs
    allowed_smartlock_ids = set()
    for perm in current_user.smartlock_permissions:
        if perm.can_view:
            allowed_smartlock_ids.add(perm.smartlock_id)
    
    # Get user's specific auth access and blocked auths
    specific_auth_ids = set()
    blocked_auth_ids = set()
    for access in current_user.specific_auth_access:
        if access.can_not_edit:
            # If can_not_edit is True, this auth should be completely hidden
            blocked_auth_ids.add(access.auth_id)
        else:
            # Only add to specific access if not blocked
            specific_auth_ids.add(access.auth_id)
    
    # Filter auths: only show auths for allowed smartlocks OR specific auth access, but NEVER show blocked auths
    filtered_auths = []
    for auth in auths:
        auth_id = auth.get('id')
        smartlock_id = auth.get('smartlockId')
        
        # First check if this auth is explicitly blocked
        if auth_id in blocked_auth_ids:
            continue  # Skip this auth completely
        
        # Include if user has specific access to this auth OR access to the smartlock
        if auth_id in specific_auth_ids or smartlock_id in allowed_smartlock_ids:
            filtered_auths.append(auth)
    
    return filtered_auths

@app.post("/login")
def login(login_request: LoginRequest, db: Session = Depends(get_db)):
    username = login_request.username
    password = login_request.password
    
    # Database authentication only
    user = db.query(User).filter(User.username == username).first()
    if user and verify_password(password, user.password_hash):
        # Update last login
        user.last_login = datetime.utcnow()
        db.commit()
        
        access_token_expires = timedelta(hours=24)
        access_token = create_access_token(
            data={"sub": username}, expires_delta=access_token_expires
        )
        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
            username=username
        )
    
    # User not found or password incorrect
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

@app.get("/verify-token")
def verify_user_token(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return {
        "username": current_user.username, 
        "valid": True, 
        "is_admin": current_user.is_admin,
        "user_id": current_user.id
    }

@app.get("/user/info")
def get_user_info(current_user: User = Depends(get_current_db_user), db: Session = Depends(get_db)):
    """Get current user information with permissions"""
    
    # Get user permissions
    smartlock_permissions = []
    for perm in current_user.smartlock_permissions:
        smartlock_permissions.append(SmartlockPermission(
            smartlock_id=perm.smartlock_id,
            can_view=perm.can_view
        ))
    
    auth_permissions = AuthPermissions()
    if current_user.auth_permissions:
        auth_permissions = AuthPermissions(
            can_create_auth=current_user.auth_permissions.can_create_auth,
            can_edit_auth=current_user.auth_permissions.can_edit_auth,
            can_delete_auth=current_user.auth_permissions.can_delete_auth
        )
    
    specific_auth_access = []
    for access in current_user.specific_auth_access:
        specific_auth_access.append(SpecificAuthAccess(
            auth_id=access.auth_id,
            can_edit=access.can_edit,
            can_delete=access.can_delete,
            can_not_edit=access.can_not_edit
        ))
    
    permissions = UserPermissions(
        smartlock_permissions=smartlock_permissions,
        auth_permissions=auth_permissions,
        specific_auth_access=specific_auth_access
    )
    
    return CurrentUserInfo(
        username=current_user.username,
        is_admin=current_user.is_admin,
        permissions=permissions
    )

@app.get("/user/permissions/refresh")
def refresh_user_permissions(current_user: User = Depends(get_current_db_user), db: Session = Depends(get_db)):
    """Refresh current user permissions for real-time updates"""
    
    # Refresh user from database to get latest permissions
    db.refresh(current_user)
    
    # Get user permissions
    smartlock_permissions = []
    for perm in current_user.smartlock_permissions:
        smartlock_permissions.append(SmartlockPermission(
            smartlock_id=perm.smartlock_id,
            can_view=perm.can_view
        ))
    
    auth_permissions = AuthPermissions()
    if current_user.auth_permissions:
        auth_permissions = AuthPermissions(
            can_create_auth=current_user.auth_permissions.can_create_auth,
            can_edit_auth=current_user.auth_permissions.can_edit_auth,
            can_delete_auth=current_user.auth_permissions.can_delete_auth
        )
    
    specific_auth_access = []
    for access in current_user.specific_auth_access:
        specific_auth_access.append(SpecificAuthAccess(
            auth_id=access.auth_id,
            can_edit=access.can_edit,
            can_delete=access.can_delete,
            can_not_edit=access.can_not_edit
        ))
    
    return UserPermissions(
        smartlock_permissions=smartlock_permissions,
        auth_permissions=auth_permissions,
        specific_auth_access=specific_auth_access
    )

@app.get("/")
def read_root():
    return {"message": "Nuki Web API integration"}

@app.get("/smartlocks")
def get_smartlocks(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    response = requests.get(f"{NUKI_API_URL}/smartlock", headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    
    smartlocks = response.json()
    
    # Filter smartlocks based on user permissions
    smartlocks = filter_smartlocks_by_permission(smartlocks, current_user, db)
    
    return smartlocks

@app.get("/smartlocks/all")
def get_all_smartlocks_for_auth_editing(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get all smartlocks for authorization editing - includes read-only smartlocks from specific auth access"""
    response = requests.get(f"{NUKI_API_URL}/smartlock", headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    
    all_smartlocks = response.json()
    
    if current_user.is_admin:
        return all_smartlocks
    
    # For non-admin users, get smartlocks they can view + smartlocks from their specific auth access
    allowed_smartlock_ids = set()
    
    # Add smartlocks user has direct permission to view
    for perm in current_user.smartlock_permissions:
        if perm.can_view:
            allowed_smartlock_ids.add(perm.smartlock_id)
    
    # Add smartlocks from specific auth access (these will be read-only)
    if current_user.specific_auth_access:
        # Get all auths to find smartlock IDs
        auths_response = requests.get(f"{NUKI_API_URL}/smartlock/auth", headers=headers)
        if auths_response.status_code == 200:
            all_auths = auths_response.json()
            for access in current_user.specific_auth_access:
                # Find auths with this auth_id and add their smartlock IDs
                for auth in all_auths:
                    if auth.get('id') == access.auth_id:
                        allowed_smartlock_ids.add(auth.get('smartlockId'))
    
    # Filter smartlocks to only include those the user should see
    filtered_smartlocks = []
    for smartlock in all_smartlocks:
        smartlock_id = smartlock.get('smartlockId')
        if smartlock_id in allowed_smartlock_ids:
            # Add permission info to smartlock
            has_direct_permission = any(
                perm.smartlock_id == smartlock_id and perm.can_view 
                for perm in current_user.smartlock_permissions
            )
            smartlock['user_can_modify'] = has_direct_permission
            filtered_smartlocks.append(smartlock)
    
    return filtered_smartlocks

@app.post("/smartlocks/{smartlock_id}/action/lock")
def lock_smartlock(smartlock_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Check permissions
    if not check_smartlock_permission(smartlock_id, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to control this smartlock"
        )
    
    logging.info(f"Locking smartlock {smartlock_id}")
    url = f"{NUKI_API_URL}/smartlock/{smartlock_id}/action/lock"
    logging.info(f"Calling Nuki API URL: {url}")
    response = requests.post(url, headers=headers)
    logging.info(f"Nuki API response status code: {response.status_code}")
    logging.info(f"Nuki API response text: {response.text}")
    if response.status_code != 204:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return {"message": "Lock command sent"}

@app.post("/smartlocks/{smartlock_id}/action/unlatch")
def unlatch_smartlock(smartlock_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Check permissions
    if not check_smartlock_permission(smartlock_id, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to control this smartlock"
        )
    
    logging.info(f"Unlatching smartlock {smartlock_id}")
    url = f"{NUKI_API_URL}/smartlock/{smartlock_id}/action"
    logging.info(f"Calling Nuki API URL: {url}")
    data = {"action": 3}
    response = requests.post(url, headers=headers, json=data)
    logging.info(f"Nuki API response status code: {response.status_code}")
    logging.info(f"Nuki API response text: {response.text}")
    if response.status_code != 204:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return {"message": "Unlatch command sent"}

class AccountUser(BaseModel):
    email: str
    name: str
    language: str = "en"

class AccountUserUpdate(BaseModel):
    name: str
    language: str = "en"

@app.get("/account/users")
def get_account_users(current_user: str = Depends(get_current_user)):
    response = requests.get(f"{NUKI_API_URL}/account/user", headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return response.json()

@app.put("/account/user")
def create_account_user(user: AccountUser, current_user: str = Depends(get_current_user)):
    response = requests.put(f"{NUKI_API_URL}/account/user", headers=headers, json=user.dict())
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return response.json()

@app.post("/account/user/{account_user_id}")
def update_account_user(account_user_id: int, user: AccountUserUpdate, current_user: str = Depends(get_current_user)):
    """
    Update an account user. The Nuki API only supports updating name and language
    for account users. Fingerprints are managed through smartlock authorizations,
    not user accounts, so they are automatically preserved.
    """
    try:
        # Prepare the update payload with only the fields supported by the Nuki API
        update_payload = {
            "name": user.name,
            "language": user.language
        }
        
        logging.info(f"Updating user {account_user_id} with payload: {update_payload}")
        
        response = requests.post(f"{NUKI_API_URL}/account/user/{account_user_id}", headers=headers, json=update_payload)
        
        if response.status_code not in [200, 204]:
            logging.error(f"Nuki API error: {response.status_code} - {response.text}")
            raise HTTPException(status_code=response.status_code, detail=response.text)
        
        logging.info(f"User {account_user_id} updated successfully")
        return {"message": "User updated successfully. Fingerprints are preserved in smartlock authorizations."}
        
    except requests.RequestException as e:
        logging.error(f"Error updating user {account_user_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update user: {str(e)}")

@app.delete("/account/user/{account_user_id}")
def delete_account_user(account_user_id: int, current_user: str = Depends(get_current_user)):
    response = requests.delete(f"{NUKI_API_URL}/account/user/{account_user_id}", headers=headers)
    if response.status_code != 204:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return {"message": "User deleted"}

class SmartlockAuth(BaseModel):
    name: str
    accountUserId: Optional[int] = None
    type: int = 0
    smartlockIds: list[int]
    code: Optional[int] = None
    enabled: bool = True
    remoteAllowed: Optional[bool] = True
    allowedFromDate: Optional[str] = None
    allowedUntilDate: Optional[str] = None
    allowedWeekDays: Optional[int] = None
    allowedFromTime: Optional[int] = None
    allowedUntilTime: Optional[int] = None

class SmartlockAuthUpdate(BaseModel):
    name: str
    code: Optional[int] = None
    allowedFromDate: Optional[str] = None
    allowedUntilDate: Optional[str] = None
    allowedWeekDays: Optional[int] = None
    allowedFromTime: Optional[int] = None
    allowedUntilTime: Optional[int] = None
    accountUserId: Optional[int] = None
    enabled: Optional[bool] = None
    remoteAllowed: Optional[bool] = None
    # Note: fingerprints are NOT supported in updates according to Nuki API documentation
    # They are read-only and automatically preserved by the Nuki API

@app.get("/smartlock/auths")
def get_smartlock_auths(current_user: User = Depends(get_current_user)):
    response = requests.get(f"{NUKI_API_URL}/smartlock/auth", headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    
    auths = response.json()
    
    # Filter auths based on user permissions
    auths = filter_auths_by_permission(auths, current_user)
    
    return auths

@app.put("/smartlock/auth")
def create_smartlock_auth(auth: SmartlockAuth, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Check permissions - pass smartlock_ids for proper permission checking
    if not check_auth_create_permission(current_user, auth.smartlockIds):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to create authorizations"
        )
    
    response = requests.put(f"{NUKI_API_URL}/smartlock/auth", headers=headers, json=auth.dict(exclude_none=True))
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return response.json()

@app.post("/smartlock/{smartlock_id}/auth/{auth_id}")
def update_smartlock_auth(smartlock_id: int, auth_id: str, auth: SmartlockAuthUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Check permissions
    if not check_auth_edit_permission(auth_id, current_user, smartlock_id, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to edit this authorization"
        )
    
    # Only check smartlock permission if user doesn't have specific authorization access
    specific_access = next((access for access in current_user.specific_auth_access 
                          if access.auth_id == auth_id), None)
    
    if not specific_access and not check_smartlock_permission(smartlock_id, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to access this smartlock"
        )
    """
    Update a smartlock authorization. To preserve fingerprints, we need to fetch
    the current authorization data and include the fingerprints in the update request.
    """
    try:
        # First, get the current authorization data to preserve fingerprints
        logging.info(f"Fetching current authorization data for auth {auth_id} on smartlock {smartlock_id}")
        current_auths_response = requests.get(f"{NUKI_API_URL}/smartlock/auth", headers=headers)
        if current_auths_response.status_code != 200:
            logging.error(f"Failed to fetch current auths: {current_auths_response.status_code} - {current_auths_response.text}")
            raise HTTPException(status_code=current_auths_response.status_code, detail="Failed to fetch current authorization data")
        
        current_auths = current_auths_response.json()
        current_auth = None
        
        # Find the authorization to update
        if isinstance(current_auths, list):
            current_auth = next((a for a in current_auths if a.get("id") == auth_id and a.get("smartlockId") == smartlock_id), None)
        
        if not current_auth:
            logging.warning(f"Could not find current auth {auth_id} for smartlock {smartlock_id}")
            raise HTTPException(status_code=404, detail="Authorization not found")
        
        # Prepare the update payload, preserving existing fingerprints
        payload = auth.dict(exclude_unset=True)
        
        # Always preserve existing fingerprints
        if "fingerprints" in current_auth:
            payload["fingerprints"] = current_auth["fingerprints"]
            logging.info(f"Preserving {len(current_auth['fingerprints'])} fingerprints for auth {auth_id}")
        
        # Include other required fields from current auth to ensure complete payload
        required_fields = ["enabled", "remoteAllowed", "lockCount"]
        for field in required_fields:
            if field in current_auth and field not in payload:
                payload[field] = current_auth[field]
        
        logging.info(f"Updating authorization {auth_id} for smartlock {smartlock_id} with payload: {payload}")
        
        response = requests.post(f"{NUKI_API_URL}/smartlock/{smartlock_id}/auth/{auth_id}", headers=headers, json=payload)
        
        if response.status_code != 204:
            logging.error(f"Nuki API error: {response.status_code} - {response.text}")
            raise HTTPException(status_code=response.status_code, detail=response.text)
        
        fingerprint_count = len(current_auth.get("fingerprints", {}))
        logging.info(f"Authorization {auth_id} updated successfully with {fingerprint_count} fingerprints preserved")
        return {"message": f"Authorization updated successfully with {fingerprint_count} fingerprints preserved"}
        
    except requests.RequestException as e:
        logging.error(f"Error updating authorization {auth_id} for smartlock {smartlock_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update authorization: {str(e)}")

@app.delete("/smartlock/auth")
def delete_smartlock_auth(auth_ids: list[str], current_user: User = Depends(get_current_user), db: Session = Depends(get_db), allow_edit_as_delete: bool = False):
    # First get all current auths to find smartlock IDs
    current_auths_response = requests.get(f"{NUKI_API_URL}/smartlock/auth", headers=headers)
    if current_auths_response.status_code != 200:
        raise HTTPException(status_code=current_auths_response.status_code, detail="Failed to fetch current authorization data")
    
    current_auths = current_auths_response.json()
    auth_smartlock_map = {}
    
    # Create mapping of auth_id to smartlock_id
    if isinstance(current_auths, list):
        for auth in current_auths:
            auth_smartlock_map[auth.get('id')] = auth.get('smartlockId')
    
    # Check permissions for each auth
    for auth_id in auth_ids:
        smartlock_id = auth_smartlock_map.get(auth_id)
        if not check_auth_delete_permission(auth_id, current_user, smartlock_id, db, allow_edit_as_delete):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"You don't have permission to delete authorization {auth_id}"
            )
    
    response = requests.delete(f"{NUKI_API_URL}/smartlock/auth", headers=headers, json=auth_ids)
    if response.status_code != 204:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return {"message": "Authorization(s) deleted"}


def get_all_smartlock_ids():
    response = requests.get(f"{NUKI_API_URL}/smartlock", headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return [sl["smartlockId"] for sl in response.json()]


@app.post("/smartlocks/sync")
def sync_all_smartlocks(current_user: str = Depends(get_current_user)):
    smartlock_ids = get_all_smartlock_ids()
    for smartlock_id in smartlock_ids:
        sync_smartlock(smartlock_id)
    return {"message": "All smartlocks synced"}


@app.post("/smartlocks/{smartlock_id}/sync")
def sync_smartlock_endpoint(smartlock_id: int, current_user: str = Depends(get_current_user)):
    sync_smartlock(smartlock_id)
    return {"message": "Sync successful"}


def sync_smartlock(smartlock_id: int):
    url = f"{NUKI_API_URL}/smartlock/{smartlock_id}/sync"
    response = requests.post(url, headers=headers)
    if response.status_code != 204:
        raise HTTPException(status_code=response.status_code, detail=response.text)


@app.get("/smartlocks/battery")
def get_smartlocks_battery_status():
    """Get battery status for all smartlocks"""
    response = requests.get(f"{NUKI_API_URL}/smartlock", headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    
    smartlocks = response.json()
    battery_info = []
    
    for smartlock in smartlocks:
        state = smartlock.get('state', {})
        battery_data = {
            'smartlockId': smartlock.get('smartlockId'),
            'name': smartlock.get('name'),
            'batteryCritical': state.get('batteryCritical', False),
            'batteryCharging': state.get('batteryCharging', False),
            'batteryCharge': state.get('batteryCharge'),  # Percentage 0-100
            'keypadBatteryCritical': state.get('keypadBatteryCritical', False),
            'doorsensorBatteryCritical': state.get('doorsensorBatteryCritical', False)
        }
        battery_info.append(battery_data)
    
    return battery_info

@app.get("/smartlock/log")
def get_all_smartlock_logs(limit: int = 50, fromDate: str = None, toDate: str = None, id: str = None, current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get logs from all smartlocks"""
    params = {"limit": min(limit, 50)}  # Ensure we don't exceed API limit
    if fromDate:
        params["fromDate"] = fromDate
    if toDate:
        params["toDate"] = toDate
    if id:
        params["id"] = id
    
    response = requests.get(f"{NUKI_API_URL}/smartlock/log", headers=headers, params=params)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    
    logs = response.json()
    
    # Clean log data to remove encoding artifacts
    logs = clean_log_data(logs)
    
    # Filter logs based on user permissions (only for database users)
    if isinstance(current_user, User):
        # Get user's allowed smartlock IDs
        allowed_smartlock_ids = set()
        for perm in current_user.smartlock_permissions:
            if perm.can_view:
                allowed_smartlock_ids.add(perm.smartlock_id)
        
        # Filter logs to only show logs from allowed smartlocks
        if not current_user.is_admin:
            logs = [log for log in logs if log.get('smartlockId') in allowed_smartlock_ids]
    
    return logs


@app.get("/smartlock/{smartlock_id}/log")
def get_smartlock_logs(smartlock_id: int, limit: int = 50, fromDate: str = None, toDate: str = None, id: str = None, current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get logs for a specific smartlock"""
    # Check permissions for database users
    if isinstance(current_user, User):
        if not check_smartlock_permission(smartlock_id, current_user, db):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to view logs for this smartlock"
            )
    
    params = {"limit": min(limit, 50)}  # Ensure we don't exceed API limit
    if fromDate:
        params["fromDate"] = fromDate
    if toDate:
        params["toDate"] = toDate
    if id:
        params["id"] = id
    
    response = requests.get(f"{NUKI_API_URL}/smartlock/{smartlock_id}/log", headers=headers, params=params)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    
    logs = response.json()
    
    # Clean log data to remove encoding artifacts
    logs = clean_log_data(logs)
    
    return logs


# Admin User Management Endpoints

@app.get("/admin/users", response_model=List[UserResponse])
def get_all_users(admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Get all users (admin only)"""
    users = db.query(User).all()
    return users

@app.post("/admin/users", response_model=UserResponse)
def create_user(user_data: UserCreate, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Create a new user (admin only)"""
    
    # Check if username already exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    # Create new user
    new_user = User(
        username=user_data.username,
        password_hash=hash_password(user_data.password),
        is_admin=user_data.is_admin,
        created_at=datetime.utcnow()
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Create default auth permissions
    auth_permissions = UserAuthPermission(
        user_id=new_user.id,
        can_create_auth=user_data.is_admin,  # Admins get all permissions by default
        can_edit_auth=user_data.is_admin,
        can_delete_auth=user_data.is_admin
    )
    
    db.add(auth_permissions)
    db.commit()
    
    return new_user

@app.put("/admin/users/{user_id}", response_model=UserResponse)
def update_user(user_id: int, user_data: UserUpdate, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Update a user (admin only)"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Update user fields
    if user_data.username is not None:
        # Check if new username already exists
        existing_user = db.query(User).filter(User.username == user_data.username, User.id != user_id).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
        user.username = user_data.username
    
    if user_data.password is not None:
        user.password_hash = hash_password(user_data.password)
    
    if user_data.is_admin is not None:
        user.is_admin = user_data.is_admin
        
        # Update auth permissions based on admin status
        if user.auth_permissions:
            if user_data.is_admin:
                user.auth_permissions.can_create_auth = True
                user.auth_permissions.can_edit_auth = True
                user.auth_permissions.can_delete_auth = True
    
    db.commit()
    db.refresh(user)
    
    return user

@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Delete a user (admin only)"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent deleting yourself
    if user.id == admin_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    db.delete(user)
    db.commit()
    
    return {"message": "User deleted successfully"}

@app.put("/admin/users/{user_id}/admin")
def update_admin_status(user_id: int, admin_status: AdminStatusUpdate, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Update user admin status (admin only)"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent removing admin from yourself if you're the only admin
    if user.id == admin_user.id and not admin_status.is_admin:
        admin_count = db.query(User).filter(User.is_admin == True).count()
        if admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove admin privileges from the last admin user"
            )
    
    user.is_admin = admin_status.is_admin
    
    # Update auth permissions based on admin status
    if user.auth_permissions:
        if admin_status.is_admin:
            user.auth_permissions.can_create_auth = True
            user.auth_permissions.can_edit_auth = True
            user.auth_permissions.can_delete_auth = True
    
    db.commit()
    
    return {"message": "Admin status updated successfully"}

@app.get("/admin/users/{user_id}/permissions", response_model=UserPermissions)
def get_user_permissions(user_id: int, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Get user permissions (admin only)"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Get user permissions
    smartlock_permissions = []
    for perm in user.smartlock_permissions:
        smartlock_permissions.append(SmartlockPermission(
            smartlock_id=perm.smartlock_id,
            can_view=perm.can_view
        ))
    
    auth_permissions = AuthPermissions()
    if user.auth_permissions:
        auth_permissions = AuthPermissions(
            can_create_auth=user.auth_permissions.can_create_auth,
            can_edit_auth=user.auth_permissions.can_edit_auth,
            can_delete_auth=user.auth_permissions.can_delete_auth
        )
    
    specific_auth_access = []
    for access in user.specific_auth_access:
        specific_auth_access.append(SpecificAuthAccess(
            auth_id=access.auth_id,
            can_edit=access.can_edit,
            can_delete=access.can_delete,
            can_not_edit=access.can_not_edit
        ))
    
    return UserPermissions(
        smartlock_permissions=smartlock_permissions,
        auth_permissions=auth_permissions,
        specific_auth_access=specific_auth_access
    )

@app.put("/admin/users/{user_id}/permissions")
def update_user_permissions(user_id: int, permissions: UserPermissionsUpdate, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Update user permissions (admin only)"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Update smartlock permissions
    if permissions.smartlock_permissions is not None:
        # Remove existing smartlock permissions
        db.query(UserSmartlockPermission).filter(UserSmartlockPermission.user_id == user_id).delete()
        
        # Add new smartlock permissions
        for perm in permissions.smartlock_permissions:
            new_perm = UserSmartlockPermission(
                user_id=user_id,
                smartlock_id=perm.smartlock_id,
                can_view=perm.can_view
            )
            db.add(new_perm)
    
    # Update auth permissions
    if permissions.auth_permissions is not None:
        if not user.auth_permissions:
            # Create new auth permissions
            auth_perms = UserAuthPermission(
                user_id=user_id,
                can_create_auth=permissions.auth_permissions.can_create_auth,
                can_edit_auth=permissions.auth_permissions.can_edit_auth,
                can_delete_auth=permissions.auth_permissions.can_delete_auth
            )
            db.add(auth_perms)
        else:
            # Update existing auth permissions
            user.auth_permissions.can_create_auth = permissions.auth_permissions.can_create_auth
            user.auth_permissions.can_edit_auth = permissions.auth_permissions.can_edit_auth
            user.auth_permissions.can_delete_auth = permissions.auth_permissions.can_delete_auth
    
    # Update specific auth access
    if permissions.specific_auth_access is not None:
        # Remove existing specific auth access
        db.query(UserSpecificAuthAccess).filter(UserSpecificAuthAccess.user_id == user_id).delete()
        
        # Add new specific auth access
        for access in permissions.specific_auth_access:
            new_access = UserSpecificAuthAccess(
                user_id=user_id,
                auth_id=access.auth_id,
                can_edit=access.can_edit,
                can_delete=access.can_delete,
                can_not_edit=access.can_not_edit
            )
            db.add(new_access)
    
    db.commit()
    
    return {"message": "User permissions updated successfully"}

# Permission Management Endpoints for Authorization Updates

@app.get("/admin/auth/{auth_id}/permissions")
def get_auth_permissions_endpoint(auth_id: str, current_user: User = Depends(get_current_db_user), db: Session = Depends(get_db)):
    """Get all permissions for an authorization (for copying)"""
    permissions = get_auth_permissions(db, auth_id)
    return [
        {
            "user_id": perm.user_id,
            "can_edit": perm.can_edit,
            "can_delete": perm.can_delete,
            "can_not_edit": perm.can_not_edit
        }
        for perm in permissions
    ]

@app.post("/admin/auth/{new_auth_id}/permissions/copy")
def copy_auth_permissions_endpoint(
    new_auth_id: str, 
    copy_request: dict,  # {"old_auth_id": "..."}
    current_user: User = Depends(get_current_db_user), 
    db: Session = Depends(get_db)
):
    """Copy permissions from old auth to new auth"""
    old_auth_id = copy_request.get("old_auth_id")
    if not old_auth_id:
        raise HTTPException(status_code=400, detail="old_auth_id required")
    
    copied_count = copy_auth_permissions(db, old_auth_id, new_auth_id)
    return {"message": f"Permissions copied successfully ({copied_count} permissions copied)"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
