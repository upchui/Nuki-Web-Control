import os
import logging
import re
import asyncio
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
from database import get_db, setup_database, User, UserSmartlockPermission, UserAuthPermission, UserSpecificAuthAccess, SmartlockGroup, SmartlockGroupMember, hash_password, verify_password, get_auth_permissions, copy_auth_permissions
from models import (
    UserCreate, UserUpdate, UserResponse, UserWithPermissions, UserPermissions, 
    UserPermissionsUpdate, AdminStatusUpdate, CurrentUserInfo, SmartlockPermission,
    AuthPermissions, SpecificAuthAccess, SmartlockGroupCreate, SmartlockGroupUpdate, 
    SmartlockGroupResponse, SmartlockGroupActionResponse
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

# Global variables for auto-sync
last_known_states = {}
auto_sync_task = None
groups_initialized = False

# Global variable for group action prevention (prevents duplicate consecutive actions)
group_last_action = {}
# Format: {group_id: "lock"/"unlock"}

def should_skip_group_action(group_id: int, action: str) -> bool:
    """Check if group action should be skipped due to being the same as last action"""
    global group_last_action
    
    last_action = group_last_action.get(group_id)
    
    if last_action == action:
        logging.info(f"🚫 Skipping duplicate group action '{action}' for group {group_id} (last action was also '{last_action}')")
        return True
    
    return False

def record_group_action(group_id: int, action: str):
    """Record the current group action to prevent immediate duplicates"""
    global group_last_action
    
    group_last_action[group_id] = action
    logging.debug(f"📝 Recorded group action '{action}' for group {group_id}")

async def initialize_group_states():
    """Initialize all groups by locking all open smartlocks before starting monitoring"""
    global groups_initialized
    
    logging.info("🔒 Starting group initialization - locking all open smartlocks in groups...")
    
    try:
        # Get all smartlocks
        response = requests.get(f"{NUKI_API_URL}/smartlock", headers=headers)
        if response.status_code != 200:
            logging.error(f"Failed to fetch smartlocks for initialization: {response.status_code}")
            return False
        
        current_smartlocks = response.json()
        smartlock_states = {sl.get('smartlockId'): sl.get('state', {}).get('state') for sl in current_smartlocks}
        
        db = next(get_db())
        
        try:
            # Get all groups
            groups = db.query(SmartlockGroup).all()
            
            if not groups:
                logging.info("No groups found - skipping group initialization")
                groups_initialized = True
                return True
            
            logging.info(f"Found {len(groups)} groups to initialize")
            
            for group in groups:
                group_smartlock_ids = [member.smartlock_id for member in group.members]
                logging.info(f"Initializing group '{group.name}' with {len(group_smartlock_ids)} smartlocks")
                
                # Check states of all smartlocks in this group
                open_smartlocks = []
                locked_smartlocks = []
                unknown_smartlocks = []
                
                for smartlock_id in group_smartlock_ids:
                    state = smartlock_states.get(smartlock_id)
                    if state == 1:  # locked
                        locked_smartlocks.append(smartlock_id)
                    elif state in [3, 5, 6]:  # unlocked, unlatched, unlocked (lock'n'go)
                        open_smartlocks.append(smartlock_id)
                    else:
                        unknown_smartlocks.append(smartlock_id)
                        logging.warning(f"Smartlock {smartlock_id} in group '{group.name}' has unknown state: {state}")
                
                logging.info(f"Group '{group.name}' status: {len(locked_smartlocks)} locked, {len(open_smartlocks)} open, {len(unknown_smartlocks)} unknown")
                
                # If there are open smartlocks, lock them all
                if open_smartlocks:
                    logging.info(f"🔒 Locking {len(open_smartlocks)} open smartlocks in group '{group.name}': {open_smartlocks}")
                    await sync_group_smartlocks(open_smartlocks, "lock")
                    
                    # Wait for locks to be applied and verify
                    logging.info(f"⏳ Waiting for locks to be applied in group '{group.name}'...")
                    max_retries = 30  # 30 seconds
                    retry_count = 0
                    
                    while retry_count < max_retries:
                        await asyncio.sleep(1)
                        retry_count += 1
                        
                        # Check if all smartlocks are now locked
                        response = requests.get(f"{NUKI_API_URL}/smartlock", headers=headers)
                        if response.status_code != 200:
                            continue
                        
                        updated_smartlocks = response.json()
                        updated_states = {sl.get('smartlockId'): sl.get('state', {}).get('state') for sl in updated_smartlocks}
                        
                        still_open = []
                        for smartlock_id in open_smartlocks:
                            if updated_states.get(smartlock_id) != 1:  # not locked
                                still_open.append(smartlock_id)
                        
                        if not still_open:
                            logging.info(f"✅ All smartlocks in group '{group.name}' are now locked")
                            break
                        else:
                            logging.info(f"⏳ Still waiting for {len(still_open)} smartlocks to lock in group '{group.name}': {still_open}")
                    
                    if still_open:
                        logging.warning(f"⚠️ Timeout waiting for some smartlocks to lock in group '{group.name}': {still_open}")
                else:
                    logging.info(f"✅ All smartlocks in group '{group.name}' are already locked")
            
            logging.info("🎉 Group initialization completed - all groups are synchronized")
            groups_initialized = True
            return True
            
        finally:
            db.close()
            
    except Exception as e:
        logging.error(f"❌ Error during group initialization: {e}")
        groups_initialized = True  # Set to true to prevent blocking the app
        return False

async def auto_sync_groups():
    """Background task to monitor smartlock status changes and auto-sync groups"""
    global last_known_states, groups_initialized
    
    # First, initialize all groups by locking open smartlocks
    if not groups_initialized:
        await initialize_group_states()
    
    logging.info("🔄 Starting continuous group synchronization monitoring...")
    
    while True:
        try:
            # Get all smartlocks
            response = requests.get(f"{NUKI_API_URL}/smartlock", headers=headers)
            if response.status_code != 200:
                logging.warning(f"Failed to fetch smartlocks for auto-sync: {response.status_code}")
                await asyncio.sleep(5)
                continue
            
            current_smartlocks = response.json()
            db = next(get_db())
            
            try:
                # Get all groups
                groups = db.query(SmartlockGroup).all()
                
                for smartlock in current_smartlocks:
                    smartlock_id = smartlock.get('smartlockId')
                    current_state = smartlock.get('state', {}).get('state')
                    
                    # Skip if no state info
                    if current_state is None:
                        continue
                    
                    # Check if state changed
                    last_state = last_known_states.get(smartlock_id)
                    if last_state is not None and last_state != current_state:
                        logging.info(f"Smartlock {smartlock_id} state changed from {last_state} to {current_state}")
                        
                        # Find groups containing this smartlock
                        for group in groups:
                            group_smartlock_ids = [member.smartlock_id for member in group.members]
                            
                            if smartlock_id in group_smartlock_ids:
                                logging.info(f"Auto-syncing group '{group.name}' (ID: {group.id}) due to smartlock {smartlock_id} state change")
                                
                                # Determine target action based on new state
                                target_action = None
                                if current_state == 1:  # locked
                                    target_action = "lock"
                                elif current_state in [3, 5, 6]:  # unlocked, unlatched, unlocked (lock'n'go)
                                    target_action = "unlock"
                                
                                if target_action:
                                    # Sync other smartlocks in the group to the same state
                                    other_smartlock_ids = [sid for sid in group_smartlock_ids if sid != smartlock_id]
                                    
                                    if other_smartlock_ids:
                                        logging.info(f"Syncing {len(other_smartlock_ids)} other smartlocks in group to {target_action}")
                                        
                                        # Execute action on other smartlocks
                                        await sync_group_smartlocks(other_smartlock_ids, target_action, group.id)
                    
                    # Update last known state
                    last_known_states[smartlock_id] = current_state
                
            finally:
                db.close()
                
        except Exception as e:
            logging.error(f"Error in auto-sync groups: {e}")
        
        # Wait 2 seconds before next check
        await asyncio.sleep(2)

async def sync_group_smartlocks(smartlock_ids: list, action: str, group_id: int = None):
    """Sync specific smartlocks to a target action and wait for completion"""
    
    # Check if this group action should be skipped due to being the same as last action
    if group_id and should_skip_group_action(group_id, action):
        return  # Skip this action silently
    
    # Record this group action immediately to prevent duplicates
    if group_id:
        record_group_action(group_id, action)
    
    # Define action endpoints and target states
    action_map = {
        "lock": "lock",
        "unlock": "unlatch"
    }
    
    # Define target states for verification
    target_states = {
        "lock": [1],  # locked
        "unlock": [3, 5, 6]  # unlocked, unlatched, unlocked (lock'n'go)
    }
    
    if action not in action_map:
        logging.warning(f"Unknown action for group sync: {action}")
        return
    
    endpoint_action = action_map[action]
    target_state_list = target_states[action]
    
    def execute_single_sync_action(smartlock_id):
        try:
            if endpoint_action == "unlatch":
                # Use the general action endpoint with action=1 for unlatch
                url = f"{NUKI_API_URL}/smartlock/{smartlock_id}/action"
                payload = {"action": 1}
                response = requests.post(url, headers=headers, json=payload)
                if response.status_code in [200, 204]:
                    logging.info(f"Successfully sent {action} command to smartlock {smartlock_id}")
                    return True
                else:
                    logging.warning(f"Failed to send {action} command to smartlock {smartlock_id}: HTTP {response.status_code}: {response.text}")
                    return False
            else:
                # Use specific endpoint for lock
                url = f"{NUKI_API_URL}/smartlock/{smartlock_id}/action/{endpoint_action}"
                response = requests.post(url, headers=headers)
                if response.status_code in [200, 204]:
                    logging.info(f"Successfully sent {action} command to smartlock {smartlock_id}")
                    return True
                else:
                    logging.warning(f"Failed to send {action} command to smartlock {smartlock_id}: HTTP {response.status_code}: {response.text}")
                    return False
        except Exception as e:
            logging.error(f"Exception sending {action} command to smartlock {smartlock_id}: {e}")
            return False
    
    # Step 1: Execute actions sequentially
    successful_commands = []
    failed_commands = []
    
    for smartlock_id in smartlock_ids:
        if execute_single_sync_action(smartlock_id):
            successful_commands.append(smartlock_id)
        else:
            failed_commands.append(smartlock_id)
    
    logging.info(f"Commands sent: {len(successful_commands)}/{len(smartlock_ids)} successful, {len(failed_commands)} failed")
    
    # Step 2: Wait for all smartlocks to reach target state
    if successful_commands:
        logging.info(f"⏳ Waiting for {len(successful_commands)} smartlocks to reach target state for action '{action}'...")
        max_retries = 30  # 30 seconds
        retry_count = 0
        
        while retry_count < max_retries:
            await asyncio.sleep(1)
            retry_count += 1
            
            try:
                # Check current states of all smartlocks
                response = requests.get(f"{NUKI_API_URL}/smartlock", headers=headers)
                if response.status_code != 200:
                    logging.warning(f"Failed to fetch smartlock states for verification: {response.status_code}")
                    continue
                
                current_smartlocks = response.json()
                current_states = {sl.get('smartlockId'): sl.get('state', {}).get('state') for sl in current_smartlocks}
                
                # Check which smartlocks still need to reach target state
                pending_smartlocks = []
                completed_smartlocks = []
                
                for smartlock_id in successful_commands:
                    current_state = current_states.get(smartlock_id)
                    if current_state in target_state_list:
                        completed_smartlocks.append(smartlock_id)
                    else:
                        pending_smartlocks.append(smartlock_id)
                        logging.debug(f"Smartlock {smartlock_id} still has state {current_state}, waiting for {target_state_list}")
                
                if not pending_smartlocks:
                    logging.info(f"✅ All {len(successful_commands)} smartlocks have reached target state for action '{action}'")
                    break
                else:
                    logging.info(f"⏳ Still waiting for {len(pending_smartlocks)} smartlocks to reach target state: {pending_smartlocks}")
                    
            except Exception as e:
                logging.warning(f"Error during state verification: {e}")
                continue
        
        # Check if timeout occurred
        if pending_smartlocks:
            logging.warning(f"⚠️ Timeout waiting for {len(pending_smartlocks)} smartlocks to reach target state: {pending_smartlocks}")
        
        # Final status report
        final_successful = len(successful_commands) - len(pending_smartlocks) if 'pending_smartlocks' in locals() else len(successful_commands)
        logging.info(f"🎯 Group sync '{action}' completed: {final_successful}/{len(smartlock_ids)} smartlocks successfully synchronized")
    else:
        logging.warning(f"❌ No commands were sent successfully - group sync '{action}' failed")

@asynccontextmanager
async def lifespan(app: FastAPI):
    global auto_sync_task
    
    # Startup
    setup_database()
    
    # Start auto-sync background task
    auto_sync_task = asyncio.create_task(auto_sync_groups())
    logging.info("Started automatic group synchronization")
    
    yield
    
    # Shutdown
    if auto_sync_task:
        auto_sync_task.cancel()
        try:
            await auto_sync_task
        except asyncio.CancelledError:
            pass
        logging.info("Stopped automatic group synchronization")

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
    data = {"action": 1}
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
def get_all_smartlock_logs(limit: int = 10000, fromDate: str = None, toDate: str = None, id: str = None, current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get logs from all smartlocks"""
    params = {"limit": min(limit, 10000)}  # Allow much higher limits for comprehensive log retrieval
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
def get_smartlock_logs(smartlock_id: int, limit: int = 10000, fromDate: str = None, toDate: str = None, id: str = None, current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get logs for a specific smartlock"""
    # Check permissions for database users
    if isinstance(current_user, User):
        if not check_smartlock_permission(smartlock_id, current_user, db):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to view logs for this smartlock"
            )
    
    params = {"limit": min(limit, 10000)}  # Allow much higher limits for comprehensive log retrieval
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

# Smart Lock Groups Endpoints

def check_group_permission(group: SmartlockGroup, current_user: User, db: Session):
    """Check if user has permission to use a group (must have access to at least one smartlock in group)"""
    if current_user.is_admin:
        return True
    
    # User must have permission to at least one smartlock in the group
    for member in group.members:
        if check_smartlock_permission(member.smartlock_id, current_user, db):
            return True
    
    return False

@app.get("/admin/smartlock-groups", response_model=List[SmartlockGroupResponse])
def get_all_groups(admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Get all smartlock groups (admin only)"""
    groups = db.query(SmartlockGroup).all()
    
    # Get smartlock names for each group
    smartlocks_response = requests.get(f"{NUKI_API_URL}/smartlock", headers=headers)
    if smartlocks_response.status_code != 200:
        raise HTTPException(status_code=smartlocks_response.status_code, detail="Failed to fetch smartlocks")
    
    all_smartlocks = smartlocks_response.json()
    smartlock_map = {sl['smartlockId']: sl['name'] for sl in all_smartlocks}
    
    result = []
    for group in groups:
        smartlock_ids = [member.smartlock_id for member in group.members]
        smartlock_names = [smartlock_map.get(sl_id, f"Unknown ({sl_id})") for sl_id in smartlock_ids]
        
        result.append(SmartlockGroupResponse(
            id=group.id,
            name=group.name,
            description=group.description,
            created_by=group.created_by,
            created_at=group.created_at,
            smartlock_ids=smartlock_ids,
            smartlock_names=smartlock_names
        ))
    
    return result

@app.post("/admin/smartlock-groups", response_model=SmartlockGroupResponse)
def create_group(group_data: SmartlockGroupCreate, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Create a new smartlock group (admin only)"""
    
    # Validate smartlock IDs exist
    smartlocks_response = requests.get(f"{NUKI_API_URL}/smartlock", headers=headers)
    if smartlocks_response.status_code != 200:
        raise HTTPException(status_code=smartlocks_response.status_code, detail="Failed to validate smartlocks")
    
    all_smartlocks = smartlocks_response.json()
    valid_smartlock_ids = {sl['smartlockId'] for sl in all_smartlocks}
    smartlock_map = {sl['smartlockId']: sl['name'] for sl in all_smartlocks}
    
    for smartlock_id in group_data.smartlock_ids:
        if smartlock_id not in valid_smartlock_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid smartlock ID: {smartlock_id}"
            )
    
    # Create new group
    new_group = SmartlockGroup(
        name=group_data.name,
        description=group_data.description,
        created_by=admin_user.id,
        created_at=datetime.utcnow()
    )
    
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    
    # Add group members
    for smartlock_id in group_data.smartlock_ids:
        member = SmartlockGroupMember(
            group_id=new_group.id,
            smartlock_id=smartlock_id
        )
        db.add(member)
    
    db.commit()
    db.refresh(new_group)
    
    # Prepare response
    smartlock_names = [smartlock_map.get(sl_id, f"Unknown ({sl_id})") for sl_id in group_data.smartlock_ids]
    
    return SmartlockGroupResponse(
        id=new_group.id,
        name=new_group.name,
        description=new_group.description,
        created_by=new_group.created_by,
        created_at=new_group.created_at,
        smartlock_ids=group_data.smartlock_ids,
        smartlock_names=smartlock_names
    )

@app.put("/admin/smartlock-groups/{group_id}", response_model=SmartlockGroupResponse)
def update_group(group_id: int, group_data: SmartlockGroupUpdate, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Update a smartlock group (admin only)"""
    
    group = db.query(SmartlockGroup).filter(SmartlockGroup.id == group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Group not found"
        )
    
    # Update group fields
    if group_data.name is not None:
        group.name = group_data.name
    if group_data.description is not None:
        group.description = group_data.description
    
    # Update smartlock members if provided
    if group_data.smartlock_ids is not None:
        # Validate smartlock IDs exist
        smartlocks_response = requests.get(f"{NUKI_API_URL}/smartlock", headers=headers)
        if smartlocks_response.status_code != 200:
            raise HTTPException(status_code=smartlocks_response.status_code, detail="Failed to validate smartlocks")
        
        all_smartlocks = smartlocks_response.json()
        valid_smartlock_ids = {sl['smartlockId'] for sl in all_smartlocks}
        smartlock_map = {sl['smartlockId']: sl['name'] for sl in all_smartlocks}
        
        for smartlock_id in group_data.smartlock_ids:
            if smartlock_id not in valid_smartlock_ids:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid smartlock ID: {smartlock_id}"
                )
        
        # Remove existing members
        db.query(SmartlockGroupMember).filter(SmartlockGroupMember.group_id == group_id).delete()
        
        # Add new members
        for smartlock_id in group_data.smartlock_ids:
            member = SmartlockGroupMember(
                group_id=group_id,
                smartlock_id=smartlock_id
            )
            db.add(member)
    
    db.commit()
    db.refresh(group)
    
    # Prepare response
    smartlocks_response = requests.get(f"{NUKI_API_URL}/smartlock", headers=headers)
    smartlock_map = {sl['smartlockId']: sl['name'] for sl in smartlocks_response.json()} if smartlocks_response.status_code == 200 else {}
    
    smartlock_ids = [member.smartlock_id for member in group.members]
    smartlock_names = [smartlock_map.get(sl_id, f"Unknown ({sl_id})") for sl_id in smartlock_ids]
    
    return SmartlockGroupResponse(
        id=group.id,
        name=group.name,
        description=group.description,
        created_by=group.created_by,
        created_at=group.created_at,
        smartlock_ids=smartlock_ids,
        smartlock_names=smartlock_names
    )

@app.delete("/admin/smartlock-groups/{group_id}")
def delete_group(group_id: int, admin_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Delete a smartlock group (admin only)"""
    
    group = db.query(SmartlockGroup).filter(SmartlockGroup.id == group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Group not found"
        )
    
    db.delete(group)
    db.commit()
    
    return {"message": "Group deleted successfully"}

@app.get("/smartlock-groups", response_model=List[SmartlockGroupResponse])
def get_groups_for_user(current_user: User = Depends(get_current_db_user), db: Session = Depends(get_db)):
    """Get smartlock groups that user has access to"""
    groups = db.query(SmartlockGroup).all()
    
    # Get smartlock names
    smartlocks_response = requests.get(f"{NUKI_API_URL}/smartlock", headers=headers)
    if smartlocks_response.status_code != 200:
        # Return empty list if can't fetch smartlocks
        return []
    
    all_smartlocks = smartlocks_response.json()
    smartlock_map = {sl['smartlockId']: sl['name'] for sl in all_smartlocks}
    
    # Filter groups based on permissions
    accessible_groups = []
    for group in groups:
        if check_group_permission(group, current_user, db):
            smartlock_ids = [member.smartlock_id for member in group.members]
            smartlock_names = [smartlock_map.get(sl_id, f"Unknown ({sl_id})") for sl_id in smartlock_ids]
            
            accessible_groups.append(SmartlockGroupResponse(
                id=group.id,
                name=group.name,
                description=group.description,
                created_by=group.created_by,
                created_at=group.created_at,
                smartlock_ids=smartlock_ids,
                smartlock_names=smartlock_names
            ))
    
    return accessible_groups



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
