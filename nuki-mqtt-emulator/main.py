import os
import logging
import uuid
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

# Import our modules
from mqtt_client import mqtt_client
from log_manager import LogCollector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global log collector instance
log_collector = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global log_collector
    
    # Startup
    logger.info("Starting Nuki MQTT API Emulator...")
    
    # Connect to MQTT broker
    mqtt_client.connect()
    
    # Initialize and start log collector
    collection_enabled = os.getenv("LOG_COLLECTION_ENABLED", "true").lower() == "true"
    collection_interval = int(os.getenv("LOG_COLLECTION_INTERVAL", "60"))
    
    if collection_enabled:
        log_collector = LogCollector(mqtt_client, mqtt_client.log_manager, collection_interval)
        await log_collector.start()
        logger.info(f"Log collector started with {collection_interval}s interval")
    else:
        logger.info("Log collection disabled")
    
    # Cleanup existing duplicates on startup
    cleanup_enabled = os.getenv("CLEANUP_DUPLICATES_ON_STARTUP", "true").lower() == "true"
    if cleanup_enabled:
        logger.info("Starting duplicate cleanup on startup...")
        removed_count = mqtt_client.log_manager.remove_duplicate_logs()
        logger.info(f"Startup duplicate cleanup completed: {removed_count} duplicates removed")
    else:
        logger.info("Startup duplicate cleanup disabled")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Nuki MQTT API Emulator...")
    
    # Stop log collector
    if log_collector:
        await log_collector.stop()
        logger.info("Log collector stopped")
    
    mqtt_client.disconnect()

app = FastAPI(
    title="Nuki MQTT API Emulator",
    description="MQTT-based emulator for the Nuki Web API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for API requests
class SmartlockAuthCreate(BaseModel):
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
    fingerprints: Optional[dict] = None

class AccountUser(BaseModel):
    email: str
    name: str
    language: str = "en"

class AccountUserUpdate(BaseModel):
    name: str
    language: str = "en"

# API Endpoints

@app.get("/")
def read_root():
    return {"message": "Nuki MQTT API Emulator", "version": "1.0.0", "mqtt_connected": mqtt_client.connected}

@app.get("/smartlock")
def get_smartlocks():
    """Get all smartlocks"""
    smartlocks = mqtt_client.data_store.get_smartlocks()
    return smartlocks

@app.post("/smartlock/{smartlock_id}/action/lock")
def lock_smartlock(smartlock_id: int):
    """Lock a smartlock"""
    logger.info(f"Locking smartlock {smartlock_id}")
    
    # Check if smartlock exists
    smartlock = mqtt_client.data_store.get_smartlock(smartlock_id)
    if not smartlock:
        raise HTTPException(status_code=404, detail="Smartlock not found")
    
    # Publish lock action to MQTT
    mqtt_client.publish_action(smartlock_id, "lock")
    
    return {"message": "Lock command sent"}

@app.post("/smartlock/{smartlock_id}/action/unlatch")
def unlatch_smartlock(smartlock_id: int):
    """Unlatch a smartlock"""
    logger.info(f"Unlatching smartlock {smartlock_id}")
    
    # Check if smartlock exists
    smartlock = mqtt_client.data_store.get_smartlock(smartlock_id)
    if not smartlock:
        raise HTTPException(status_code=404, detail="Smartlock not found")
    
    # Publish unlatch action to MQTT
    mqtt_client.publish_action(smartlock_id, "unlatch")
    
    return {"message": "Unlatch command sent"}

@app.post("/smartlock/{smartlock_id}/action")
def smartlock_action(smartlock_id: int, action_data: dict):
    """Generic smartlock action endpoint"""
    action = action_data.get("action")
    
    # Check if smartlock exists
    smartlock = mqtt_client.data_store.get_smartlock(smartlock_id)
    if not smartlock:
        raise HTTPException(status_code=404, detail="Smartlock not found")
    
    # Map action numbers to names
    action_mapping = {
        1: "unlock",
        2: "lock", 
        3: "unlatch",
        4: "lockNgo",
        5: "lockNgoUnlatch",
        6: "fullLock"
    }
    
    action_name = action_mapping.get(action, str(action))
    logger.info(f"Executing action {action_name} on smartlock {smartlock_id}")
    
    # Publish action to MQTT
    mqtt_client.publish_action(smartlock_id, action_name)
    
    return {"message": f"Action {action_name} sent"}

@app.get("/smartlock/auth")
def get_smartlock_auths():
    """Get all smartlock authorizations"""
    auths = mqtt_client.data_store.get_authorizations()
    
    # Return the authorizations directly - they are already properly formatted by mqtt_client
    logger.info(f"Returning {len(auths)} authorizations")
    return auths

@app.put("/smartlock/auth")
def create_smartlock_auth(auth: SmartlockAuthCreate):
    """Create a new smartlock authorization via MQTT (to fix time-limited access)"""
    
    # Validate that smartlockIds is not empty
    if not auth.smartlockIds:
        raise HTTPException(status_code=400, detail="No smartlocks specified")
    
    # Create authorization for each smartlock via MQTT (like the old working version)
    created_auths = []
    for smartlock_id in auth.smartlockIds:
        # Check if smartlock exists
        smartlock = mqtt_client.data_store.get_smartlock(smartlock_id)
        if not smartlock:
            logger.warning(f"Smartlock {smartlock_id} not found, creating it")
            mqtt_client.data_store.create_smartlock(smartlock_id, mqtt_client)
        
        # For keypad codes (type 13), use MQTT keypad action (FIXED)
        if auth.type == 13:
            # Prepare MQTT keypad action data (like the old version)
            mqtt_action_data = {
                "action": "add",
                "name": auth.name,
                "code": auth.code,
                "enabled": 1 if auth.enabled else 0
            }
            
            # Add time restrictions if present (FIXED LOGIC)
            if any([auth.allowedFromDate, auth.allowedUntilDate, auth.allowedWeekDays, 
                   auth.allowedFromTime, auth.allowedUntilTime]):
                mqtt_action_data["timeLimited"] = 1
                
                if auth.allowedFromDate:
                    # Convert from ISO format to MQTT format
                    mqtt_action_data["allowedFrom"] = auth.allowedFromDate.replace("T", " ").replace(".000Z", "")
                if auth.allowedUntilDate:
                    mqtt_action_data["allowedUntil"] = auth.allowedUntilDate.replace("T", " ").replace(".000Z", "")
                if auth.allowedWeekDays:
                    # Convert bit representation to weekday names
                    weekday_map = {1: "mon", 4: "tue", 8: "wed", 32: "thu", 16: "fri", 64: "sat", 2: "sun"}
                    weekdays = []
                    for bit, day in weekday_map.items():
                        if auth.allowedWeekDays & bit:
                            weekdays.append(day)
                    mqtt_action_data["allowedWeekdays"] = weekdays
                if auth.allowedFromTime is not None:
                    # Convert minutes to HH:MM
                    hours = auth.allowedFromTime // 60
                    minutes = auth.allowedFromTime % 60
                    mqtt_action_data["allowedFromTime"] = f"{hours:02d}:{minutes:02d}"
                if auth.allowedUntilTime is not None:
                    hours = auth.allowedUntilTime // 60
                    minutes = auth.allowedUntilTime % 60
                    mqtt_action_data["allowedUntilTime"] = f"{hours:02d}:{minutes:02d}"
            else:
                mqtt_action_data["timeLimited"] = 0
            
            # Send MQTT action - this will create the keypad code via MQTT handler
            mqtt_client.publish_keypad_action(smartlock_id, mqtt_action_data)
            
            # Wait briefly for MQTT processing and then find the created auth
            import time
            time.sleep(0.1)  # 100ms wait for MQTT processing
            
            # Find the newly created authorization
            new_auths = [a for a in mqtt_client.data_store.get_authorizations() 
                        if a.get("smartlockId") == smartlock_id and 
                           a.get("name") == auth.name and 
                           a.get("code") == auth.code]
            if new_auths:
                created_auth = new_auths[-1]  # Take the most recent one
                created_auths.append(created_auth)
                logger.info(f"Created keypad code via MQTT for smartlock {smartlock_id}: {auth.name}")
            else:
                # Fallback: create a placeholder response
                created_auth = {
                    "id": "pending",
                    "smartlockId": smartlock_id,
                    "name": auth.name,
                    "code": auth.code,
                    "type": 13,
                    "enabled": auth.enabled,
                    "remoteAllowed": True,
                    "lockCount": 0,
                    "creationDate": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
                }
                created_auths.append(created_auth)
                logger.warning(f"MQTT keypad creation pending for smartlock {smartlock_id}: {auth.name}")
        
        else:
            # Create regular authorization via MQTT (like the old version)
            mqtt_action_data = {
                "action": "add",
                "name": auth.name,
                "type": auth.type,
                "enabled": 1 if auth.enabled else 0,
                "remoteAllowed": 1 if auth.remoteAllowed else 0
            }
            
            if auth.code:
                mqtt_action_data["code"] = auth.code
            if auth.accountUserId:
                mqtt_action_data["accountUserId"] = auth.accountUserId
            if auth.allowedFromDate:
                mqtt_action_data["allowedFrom"] = auth.allowedFromDate
            if auth.allowedUntilDate:
                mqtt_action_data["allowedUntil"] = auth.allowedUntilDate
            if auth.allowedWeekDays:
                mqtt_action_data["allowedWeekdays"] = auth.allowedWeekDays
            if auth.allowedFromTime:
                mqtt_action_data["allowedFromTime"] = auth.allowedFromTime
            if auth.allowedUntilTime:
                mqtt_action_data["allowedUntilTime"] = auth.allowedUntilTime
            
            # Send MQTT action - this will create the authorization via MQTT handler
            mqtt_client.publish_authorization_action(smartlock_id, mqtt_action_data)
            
            # Wait briefly for MQTT processing and then find the created auth
            import time
            time.sleep(0.1)  # 100ms wait for MQTT processing
            
            # Find the newly created authorization
            new_auths = [a for a in mqtt_client.data_store.get_authorizations() 
                        if a.get("smartlockId") == smartlock_id and 
                           a.get("name") == auth.name and 
                           a.get("type") == auth.type]
            if new_auths:
                created_auth = new_auths[-1]  # Take the most recent one
                created_auths.append(created_auth)
                logger.info(f"Created authorization via MQTT for smartlock {smartlock_id}: {auth.name}")
            else:
                # Fallback: create a placeholder response
                created_auth = {
                    "id": "pending",
                    "smartlockId": smartlock_id,
                    "name": auth.name,
                    "type": auth.type,
                    "enabled": auth.enabled,
                    "remoteAllowed": auth.remoteAllowed if auth.remoteAllowed is not None else True,
                    "lockCount": 0,
                    "creationDate": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
                }
                if auth.code:
                    created_auth["code"] = auth.code
                created_auths.append(created_auth)
                logger.warning(f"MQTT authorization creation pending for smartlock {smartlock_id}: {auth.name}")
    
    # Return the first created auth (Nuki API behavior)
    if created_auths:
        logger.info(f"Successfully created {len(created_auths)} authorization(s)")
        return created_auths[0]
    else:
        raise HTTPException(status_code=500, detail="Failed to create authorization")

@app.post("/smartlock/{smartlock_id}/auth/{auth_id}")
def update_smartlock_auth(smartlock_id: int, auth_id: str, auth: SmartlockAuthUpdate):
    """Update a smartlock authorization via MQTT"""
    
    # Find the authorization (check both regular auths and keypad codes)
    existing_auth = mqtt_client.data_store.get_authorization(auth_id)
    if not existing_auth or existing_auth.get("smartlockId") != smartlock_id:
        raise HTTPException(status_code=404, detail="Authorization not found")
    
    # Check if this is a keypad code (type 13)
    if existing_auth.get("type") == 13:
        # This is a keypad code - use keypad action
        action_data = _convert_api_to_mqtt_keypad(auth, auth_id)
        mqtt_client.publish_keypad_action(smartlock_id, action_data)
    else:
        # Regular authorization - use authorization action
        action_data = {
            "action": "update",
            "authId": existing_auth.get("authId", hash(auth_id) % 1000000),  # Use numeric authId for MQTT
            "name": auth.name
        }
        
        if auth.code is not None:
            action_data["code"] = auth.code
        if auth.allowedFromDate is not None:
            action_data["allowedFrom"] = auth.allowedFromDate
        if auth.allowedUntilDate is not None:
            action_data["allowedUntil"] = auth.allowedUntilDate
        if auth.allowedWeekDays is not None:
            action_data["allowedWeekdays"] = auth.allowedWeekDays
        if auth.allowedFromTime is not None:
            action_data["allowedFromTime"] = auth.allowedFromTime
        if auth.allowedUntilTime is not None:
            action_data["allowedUntilTime"] = auth.allowedUntilTime
        if auth.enabled is not None:
            action_data["enabled"] = 1 if auth.enabled else 0
        if auth.remoteAllowed is not None:
            action_data["remoteAllowed"] = 1 if auth.remoteAllowed else 0
        
        mqtt_client.publish_authorization_action(smartlock_id, action_data)
    
    return {"message": "Authorization updated successfully"}

def _convert_api_to_mqtt_keypad(auth: SmartlockAuthUpdate, auth_id: str) -> dict:
    """Convert API format to MQTT keypad action format"""
    action_data = {
        "action": "update",
        "codeId": int(auth_id),  # MQTT expects numeric codeId
        "name": auth.name
    }
    
    # Code conversion
    if auth.code is not None:
        action_data["code"] = auth.code
    
    if auth.enabled is not None:
        action_data["enabled"] = 1 if auth.enabled else 0
    
    # Date conversions: "2025-07-21T21:22:00.000Z" -> "2025-07-21 21:22:00"
    if auth.allowedFromDate:
        action_data["allowedFrom"] = auth.allowedFromDate.replace("T", " ").replace(".000Z", "")
    
    if auth.allowedUntilDate:
        action_data["allowedUntil"] = auth.allowedUntilDate.replace("T", " ").replace(".000Z", "")
    
    # Weekdays conversion: 36 -> ["tue", "thu"]
    if auth.allowedWeekDays is not None:
        weekday_map = {1: "mon", 4: "tue", 8: "wed", 32: "thu", 16: "fri", 64: "sat", 2: "sun"}
        weekdays = []
        for bit, day in weekday_map.items():
            if auth.allowedWeekDays & bit:
                weekdays.append(day)
        action_data["allowedWeekdays"] = weekdays
    
    # Time conversion: minutes to HH:MM
    if auth.allowedFromTime is not None:
        hours = auth.allowedFromTime // 60
        minutes = auth.allowedFromTime % 60
        action_data["allowedFromTime"] = f"{hours:02d}:{minutes:02d}"
    
    if auth.allowedUntilTime is not None:
        hours = auth.allowedUntilTime // 60
        minutes = auth.allowedUntilTime % 60
        action_data["allowedUntilTime"] = f"{hours:02d}:{minutes:02d}"
    
    # Set timeLimited automatically based on presence of time restrictions
    has_time_restrictions = any([
        auth.allowedFromDate, auth.allowedUntilDate, 
        auth.allowedWeekDays, auth.allowedFromTime, auth.allowedUntilTime
    ])
    action_data["timeLimited"] = 1 if has_time_restrictions else 0
    
    return action_data

@app.delete("/smartlock/auth")
def delete_smartlock_auth(auth_ids: list[str]):
    """Delete smartlock authorizations via MQTT with improved ID safety"""
    
    deleted_auths = []
    failed_deletions = []
    
    for auth_id in auth_ids:
        try:
            # Use safe authorization retrieval with validation
            auth = mqtt_client.data_store.get_authorization_safe(auth_id)
            if not auth:
                failed_deletions.append({"id": auth_id, "reason": "Authorization not found"})
                continue
            
            # Validate that this authorization is safe to delete
            if not mqtt_client.data_store.validate_auth_for_deletion(auth, auth_id):
                failed_deletions.append({"id": auth_id, "reason": "ID validation failed"})
                continue
            
            smartlock_id = auth["smartlockId"]
            auth_name = auth.get("name", "Unknown")
            
            # Check if this is a keypad code (type 13) or regular authorization
            if auth.get("type") == 13:
                # This is a keypad code - delete via keypad action
                try:
                    # Use the ID mapper to get the correct numeric ID
                    numeric_id = mqtt_client.data_store.id_mapper.get_numeric_id(auth_id)
                    if numeric_id is None:
                        # Fallback: use authId from the authorization object
                        numeric_id = auth.get("authId")
                    
                    if numeric_id is None:
                        # Last resort: try to parse the string ID
                        if auth_id.isdigit():
                            numeric_id = int(auth_id)
                        else:
                            raise ValueError(f"Cannot determine numeric ID for keypad code {auth_id}")
                    
                    action_data = {
                        "action": "delete",
                        "codeId": numeric_id
                    }
                    
                    logger.info(f"Safely deleting keypad code: ID={auth_id} (numeric={numeric_id}), Name='{auth_name}', Smartlock={smartlock_id}")
                    mqtt_client.publish_keypad_action(smartlock_id, action_data)
                    
                    deleted_auths.append({
                        "id": auth_id,
                        "name": auth_name,
                        "smartlockId": smartlock_id,
                        "type": "keypad"
                    })
                    
                except (ValueError, TypeError) as e:
                    logger.error(f"Failed to delete keypad code {auth_id}: {e}")
                    failed_deletions.append({"id": auth_id, "reason": f"ID conversion error: {e}"})
                    
            else:
                # This is a regular authorization - delete via authorization action
                try:
                    # Use the ID mapper to get the correct numeric ID
                    numeric_id = mqtt_client.data_store.id_mapper.get_numeric_id(auth_id)
                    if numeric_id is None:
                        # Fallback: use authId from the authorization object
                        numeric_id = auth.get("authId")
                    
                    if numeric_id is None:
                        # Generate a safe numeric ID (but log this as suspicious)
                        logger.warning(f"No numeric ID mapping found for authorization {auth_id}, generating fallback")
                        numeric_id = abs(hash(auth_id)) % 1000000
                    
                    action_data = {
                        "action": "delete",
                        "authId": numeric_id
                    }
                    
                    logger.info(f"Safely deleting authorization: ID={auth_id} (numeric={numeric_id}), Name='{auth_name}', Smartlock={smartlock_id}")
                    mqtt_client.publish_authorization_action(smartlock_id, action_data)
                    
                    deleted_auths.append({
                        "id": auth_id,
                        "name": auth_name,
                        "smartlockId": smartlock_id,
                        "type": "regular"
                    })
                    
                except Exception as e:
                    logger.error(f"Failed to delete authorization {auth_id}: {e}")
                    failed_deletions.append({"id": auth_id, "reason": f"Deletion error: {e}"})
                    
        except Exception as e:
            logger.error(f"Unexpected error processing authorization {auth_id}: {e}")
            failed_deletions.append({"id": auth_id, "reason": f"Unexpected error: {e}"})
    
    # Prepare response with detailed information
    response = {
        "message": f"Successfully deleted {len(deleted_auths)} authorization(s)",
        "deleted": deleted_auths,
        "deleted_count": len(deleted_auths)
    }
    
    if failed_deletions:
        response["failed"] = failed_deletions
        response["failed_count"] = len(failed_deletions)
        response["message"] += f", {len(failed_deletions)} failed"
    
    return response

@app.get("/smartlock/log")
def get_all_smartlock_logs(limit: int = 50, fromDate: str = None, toDate: str = None, id: str = None):
    """Get logs from all smartlocks - reads from persistent storage"""
    # Use LogManager to get logs from disk instead of memory
    logs = mqtt_client.log_manager.get_logs(smartlock_id=None, limit=min(limit, 50))
    
    # Apply filters if provided
    if fromDate:
        try:
            from_dt = datetime.fromisoformat(fromDate.replace('Z', '+00:00'))
            logs = [log for log in logs if datetime.fromisoformat(log.get("date", "").replace('Z', '+00:00') if 'Z' in log.get("date", "") else log.get("date", "") + '+00:00') >= from_dt]
        except (ValueError, TypeError):
            pass
    
    if toDate:
        try:
            to_dt = datetime.fromisoformat(toDate.replace('Z', '+00:00'))
            logs = [log for log in logs if datetime.fromisoformat(log.get("date", "").replace('Z', '+00:00') if 'Z' in log.get("date", "") else log.get("date", "") + '+00:00') <= to_dt]
        except (ValueError, TypeError):
            pass
    
    if id:
        logs = [log for log in logs if log.get("id") == id]
    
    logger.info(f"Returning {len(logs)} logs from persistent storage")
    return logs

@app.get("/smartlock/{smartlock_id}/log")
def get_smartlock_logs(smartlock_id: int, limit: int = 50, fromDate: str = None, toDate: str = None, id: str = None):
    """Get logs for a specific smartlock - reads from persistent storage"""
    # Use LogManager to get logs from disk instead of memory
    logs = mqtt_client.log_manager.get_logs(smartlock_id=smartlock_id, limit=min(limit, 50))
    
    # Apply filters if provided
    if fromDate:
        try:
            from_dt = datetime.fromisoformat(fromDate.replace('Z', '+00:00'))
            logs = [log for log in logs if datetime.fromisoformat(log.get("date", "").replace('Z', '+00:00') if 'Z' in log.get("date", "") else log.get("date", "") + '+00:00') >= from_dt]
        except (ValueError, TypeError):
            pass
    
    if toDate:
        try:
            to_dt = datetime.fromisoformat(toDate.replace('Z', '+00:00'))
            logs = [log for log in logs if datetime.fromisoformat(log.get("date", "").replace('Z', '+00:00') if 'Z' in log.get("date", "") else log.get("date", "") + '+00:00') <= to_dt]
        except (ValueError, TypeError):
            pass
    
    if id:
        logs = [log for log in logs if log.get("id") == id]
    
    logger.info(f"Returning {len(logs)} logs for smartlock {smartlock_id} from persistent storage")
    return logs

@app.post("/smartlock/{smartlock_id}/sync")
def sync_smartlock(smartlock_id: int):
    """Sync smartlock (placeholder - just return success)"""
    smartlock = mqtt_client.data_store.get_smartlock(smartlock_id)
    if not smartlock:
        raise HTTPException(status_code=404, detail="Smartlock not found")
    
    logger.info(f"Sync requested for smartlock {smartlock_id}")
    return {"message": "Sync successful"}

@app.get("/account/user")
def get_account_users():
    """Get all account users"""
    users = mqtt_client.data_store.get_account_users()
    return users

@app.put("/account/user")
def create_account_user(user: AccountUser):
    """Create a new account user"""
    
    # Check if user already exists
    existing_users = mqtt_client.data_store.get_account_users()
    if any(u.get("email") == user.email for u in existing_users):
        raise HTTPException(status_code=400, detail="User with this email already exists")
    
    user_data = {
        "email": user.email,
        "name": user.name,
        "language": user.language
    }
    
    user_id = mqtt_client.data_store.add_account_user(user_data)
    return mqtt_client.data_store.get_account_user(user_id)

@app.post("/account/user/{account_user_id}")
def update_account_user(account_user_id: int, user: AccountUserUpdate):
    """Update an account user"""
    
    existing_user = mqtt_client.data_store.get_account_user(account_user_id)
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    update_data = {
        "name": user.name,
        "language": user.language
    }
    
    mqtt_client.data_store.update_account_user(account_user_id, update_data)
    
    return {"message": "User updated successfully"}

@app.delete("/account/user/{account_user_id}")
def delete_account_user(account_user_id: int):
    """Delete an account user"""
    
    user = mqtt_client.data_store.get_account_user(account_user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    mqtt_client.data_store.delete_account_user(account_user_id)
    
    return {"message": "User deleted"}

@app.get("/smartlocks/battery")
def get_smartlocks_battery_status():
    """Get battery status for all smartlocks"""
    smartlocks = mqtt_client.data_store.get_smartlocks()
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

@app.post("/smartlocks/sync")
def sync_all_smartlocks():
    """Sync all smartlocks"""
    smartlocks = mqtt_client.data_store.get_smartlocks()
    for smartlock in smartlocks:
        smartlock_id = smartlock.get("smartlockId")
        logger.info(f"Sync requested for smartlock {smartlock_id}")
    
    return {"message": "All smartlocks synced"}

# Health check endpoint
@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "mqtt_connected": mqtt_client.connected,
        "timestamp": datetime.utcnow().isoformat()
    }

# Debug endpoint
@app.get("/debug")
def debug_info():
    """Debug information endpoint"""
    auths = mqtt_client.data_store.get_authorizations()
    smartlocks = mqtt_client.data_store.get_smartlocks()
    
    return {
        "mqtt_connected": mqtt_client.connected,
        "mqtt_host": mqtt_client.mqtt_host,
        "mqtt_port": mqtt_client.mqtt_port,
        "smartlocks_count": len(smartlocks),
        "smartlocks": smartlocks,
        "authorizations_count": len(auths),
        "authorizations": auths,
        "topic_map": mqtt_client.smartlock_topic_map,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/admin/logs/cleanup-duplicates")
def cleanup_duplicate_logs(smartlock_id: Optional[int] = None):
    """Remove duplicate logs from storage (admin endpoint)"""
    removed_count = mqtt_client.log_manager.remove_duplicate_logs(smartlock_id)
    
    if smartlock_id:
        message = f"Removed {removed_count} duplicate logs for smartlock {smartlock_id}"
    else:
        message = f"Removed {removed_count} duplicate logs across all smartlocks"
    
    return {
        "message": message,
        "duplicates_removed": removed_count,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/admin/logs/statistics")
def get_log_statistics():
    """Get log statistics including duplicate information (admin endpoint)"""
    stats = mqtt_client.log_manager.get_log_statistics()
    
    # Add duplicate detection statistics
    total_duplicates = 0
    for smartlock_id in mqtt_client.log_manager.get_all_smartlock_ids():
        logs = mqtt_client.log_manager.load_logs_from_disk(smartlock_id)
        seen_hashes = set()
        duplicates_for_smartlock = 0
        
        for log in logs:
            content_hash = mqtt_client.log_manager._generate_content_hash(log)
            if content_hash in seen_hashes:
                duplicates_for_smartlock += 1
            else:
                seen_hashes.add(content_hash)
        
        total_duplicates += duplicates_for_smartlock
        if smartlock_id in stats['smartlock_stats']:
            stats['smartlock_stats'][smartlock_id]['duplicates'] = duplicates_for_smartlock
    
    stats['total_duplicates'] = total_duplicates
    stats['timestamp'] = datetime.utcnow().isoformat()
    
    return stats

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
