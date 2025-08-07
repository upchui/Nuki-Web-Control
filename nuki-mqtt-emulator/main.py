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
    
    # Enforce log limits on startup (NEW)
    enforce_limits_enabled = os.getenv("ENFORCE_LOG_LIMITS_ON_STARTUP", "true").lower() == "true"
    if enforce_limits_enabled:
        logger.info("Enforcing log limits on startup...")
        cleaned_count = mqtt_client.log_manager.enforce_log_limits_on_startup()
        logger.info(f"Startup log limit enforcement completed: {cleaned_count} old logs removed")
    else:
        logger.info("Startup log limit enforcement disabled")
    
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
    mqtt_client.publish_action(smartlock_id, "unlock")
    
    return {"message": "Unlock command sent"}

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
    """Create a new smartlock authorization via MQTT (FIXED: sequential processing for multiple smartlocks)"""
    
    # Validate that smartlockIds is not empty
    if not auth.smartlockIds:
        raise HTTPException(status_code=400, detail="No smartlocks specified")
    
    import time
    
    # Create authorization for each smartlock SEQUENTIALLY to avoid Race Conditions
    created_auths = []
    failed_creations = []
    
    logger.info(f"Creating authorization '{auth.name}' for {len(auth.smartlockIds)} smartlock(s): {auth.smartlockIds}")
    
    for i, smartlock_id in enumerate(auth.smartlockIds):
        try:
            logger.info(f"Processing smartlock {smartlock_id} ({i+1}/{len(auth.smartlockIds)})")
            
            # Check if smartlock exists
            smartlock = mqtt_client.data_store.get_smartlock(smartlock_id)
            if not smartlock:
                logger.warning(f"Smartlock {smartlock_id} not found, creating it")
                mqtt_client.data_store.create_smartlock(smartlock_id, mqtt_client)
                # Wait a bit for smartlock creation to settle
                time.sleep(0.2)
            
            # For keypad codes (type 13), use MQTT keypad action
            if auth.type == 13:
                # Prepare MQTT keypad action data
                mqtt_action_data = {
                    "action": "add",
                    "name": auth.name,
                    "code": auth.code,
                    "enabled": 1 if auth.enabled else 0
                }
                
                # DEBUG: Check what Time-Limited fields we received
                logger.info(f"DEBUG CREATE - Time-Limited fields received:")
                logger.info(f"  allowedFromDate: {auth.allowedFromDate}")
                logger.info(f"  allowedUntilDate: {auth.allowedUntilDate}")
                logger.info(f"  allowedWeekDays: {auth.allowedWeekDays}")
                logger.info(f"  allowedFromTime: {auth.allowedFromTime}")
                logger.info(f"  allowedUntilTime: {auth.allowedUntilTime}")
                
                # FIXED: Check for Time-Limited fields properly (including None and empty string)
                has_time_restrictions = any([
                    auth.allowedFromDate and auth.allowedFromDate.strip(),
                    auth.allowedUntilDate and auth.allowedUntilDate.strip(), 
                    auth.allowedWeekDays and auth.allowedWeekDays > 0,
                    auth.allowedFromTime is not None and auth.allowedFromTime >= 0,
                    auth.allowedUntilTime is not None and auth.allowedUntilTime >= 0
                ])
                
                logger.info(f"DEBUG CREATE - has_time_restrictions: {has_time_restrictions}")
                
                if has_time_restrictions:
                    mqtt_action_data["timeLimited"] = 1
                    logger.info(f"DEBUG CREATE - Setting timeLimited = 1")
                    
                    if auth.allowedFromDate and auth.allowedFromDate.strip():
                        # Convert from ISO format to MQTT format
                        mqtt_action_data["allowedFrom"] = auth.allowedFromDate.replace("T", " ").replace(".000Z", "")
                        logger.info(f"DEBUG CREATE - Added allowedFrom: {mqtt_action_data['allowedFrom']}")
                    
                    if auth.allowedUntilDate and auth.allowedUntilDate.strip():
                        mqtt_action_data["allowedUntil"] = auth.allowedUntilDate.replace("T", " ").replace(".000Z", "")
                        logger.info(f"DEBUG CREATE - Added allowedUntil: {mqtt_action_data['allowedUntil']}")
                    
                    if auth.allowedWeekDays and auth.allowedWeekDays > 0:
                        # Convert bit representation to weekday names
                        weekday_map = {64: "mon", 32: "tue", 16: "wed", 8: "thu", 4: "fri", 2: "sat", 1: "sun"}
                        weekdays = []
                        for bit, day in weekday_map.items():
                            if auth.allowedWeekDays & bit:
                                weekdays.append(day)
                        mqtt_action_data["allowedWeekdays"] = weekdays
                        logger.info(f"DEBUG CREATE - Added allowedWeekdays: {weekdays}")
                    
                    if auth.allowedFromTime is not None and auth.allowedFromTime >= 0:
                        # Convert minutes to HH:MM
                        hours = auth.allowedFromTime // 60
                        minutes = auth.allowedFromTime % 60
                        mqtt_action_data["allowedFromTime"] = f"{hours:02d}:{minutes:02d}"
                        logger.info(f"DEBUG CREATE - Added allowedFromTime: {mqtt_action_data['allowedFromTime']}")
                    
                    if auth.allowedUntilTime is not None and auth.allowedUntilTime >= 0:
                        hours = auth.allowedUntilTime // 60
                        minutes = auth.allowedUntilTime % 60
                        mqtt_action_data["allowedUntilTime"] = f"{hours:02d}:{minutes:02d}"
                        logger.info(f"DEBUG CREATE - Added allowedUntilTime: {mqtt_action_data['allowedUntilTime']}")
                else:
                    mqtt_action_data["timeLimited"] = 0
                    logger.info(f"DEBUG CREATE - Setting timeLimited = 0 (no time restrictions found)")
                
                logger.info(f"Sending MQTT keypad action for smartlock {smartlock_id}: {mqtt_action_data}")
                
                # Send MQTT action - this will create the keypad code via MQTT handler
                mqtt_client.publish_keypad_action(smartlock_id, mqtt_action_data)
                
                # ENHANCED: Longer initial wait for MQTT processing with adaptive timing
                initial_wait = 0.8 + (i * 0.2)  # Increase wait time for later smartlocks
                #time.sleep(initial_wait)
                logger.info(f"Waited {initial_wait}s for MQTT processing for smartlock {smartlock_id}")
                
                # ENHANCED: Improved retry logic with validation of Time-Limited fields
                created_auth = None
                max_attempts = 5  # Increased from 3 to 5 attempts
                for attempt in range(max_attempts):
                    new_auths = [a for a in mqtt_client.data_store.get_authorizations() 
                                if a.get("smartlockId") == smartlock_id and 
                                   a.get("name") == auth.name and 
                                   a.get("code") == auth.code]
                    
                    if new_auths:
                        candidate_auth = new_auths[-1]  # Take the most recent one
                        
                        # ENHANCED: Validate Time-Limited fields are correctly set
                        time_limited_validation_passed = True
                        
                        if has_time_restrictions:
                            # Check if timeLimited fields are present in the created auth
                            has_date_restrictions = candidate_auth.get("allowedFromDate") or candidate_auth.get("allowedUntilDate")
                            has_weekday_restrictions = candidate_auth.get("allowedWeekDays", 0) > 0
                            has_time_restrictions_in_auth = (candidate_auth.get("allowedFromTime") is not None or 
                                                           candidate_auth.get("allowedUntilTime") is not None)
                            
                            if not (has_date_restrictions or has_weekday_restrictions or has_time_restrictions_in_auth):
                                time_limited_validation_passed = False
                                logger.warning(f"Attempt {attempt+1}: Time-Limited fields missing in created auth for smartlock {smartlock_id}")
                            else:
                                logger.info(f"✅ Time-Limited validation passed for smartlock {smartlock_id}")
                        
                        if time_limited_validation_passed:
                            created_auth = candidate_auth
                            logger.info(f"✅ Successfully created and validated keypad code for smartlock {smartlock_id}: {auth.name}")
                            break
                        else:
                            logger.warning(f"Attempt {attempt+1}: Time-Limited validation failed for smartlock {smartlock_id}, retrying...")
                    else:
                        logger.warning(f"Attempt {attempt+1}: Auth not found yet for smartlock {smartlock_id}, waiting...")
                    
                    # ENHANCED: Adaptive retry timing - longer waits for later attempts
                    retry_wait = 0.4 + (attempt * 0.2)  # 0.4s, 0.6s, 0.8s, 1.0s, 1.2s
                    #time.sleep(retry_wait)
                
                # ENHANCED: If Time-Limited validation failed, try to fix it
                if created_auth and has_time_restrictions:
                    # Double-check that Time-Limited fields are present
                    needs_fix = False
                    if auth.allowedFromDate and not created_auth.get("allowedFromDate"):
                        needs_fix = True
                    if auth.allowedUntilDate and not created_auth.get("allowedUntilDate"):
                        needs_fix = True
                    if auth.allowedWeekDays and not created_auth.get("allowedWeekDays"):
                        needs_fix = True
                    if auth.allowedFromTime is not None and created_auth.get("allowedFromTime") is None:
                        needs_fix = True
                    if auth.allowedUntilTime is not None and created_auth.get("allowedUntilTime") is None:
                        needs_fix = True
                    
                    if needs_fix:
                        logger.warning(f"🔧 Time-Limited fields incomplete for smartlock {smartlock_id}, attempting to fix...")
                        # Try to update the code with missing Time-Limited fields
                        code_id = created_auth.get("authId") or created_auth.get("id").split("_")[-1]
                        if code_id and str(code_id).isdigit():
                            fix_action_data = mqtt_action_data.copy()
                            fix_action_data["action"] = "update"
                            fix_action_data["codeId"] = int(code_id)
                            
                            logger.info(f"🔧 Sending fix update for smartlock {smartlock_id}: {fix_action_data}")
                            mqtt_client.publish_keypad_action(smartlock_id, fix_action_data)
                            #time.sleep(0.8)  # Wait for update to process
                
                if created_auth:
                    created_auths.append(created_auth)
                    
                    # ENHANCED: Start verification thread to ensure enabled state is correct
                    mqtt_client.start_authorization_verification_thread(
                        smartlock_id=smartlock_id,
                        expected_name=auth.name,
                        expected_enabled=auth.enabled,
                        expected_code=auth.code,
                        max_attempts=5
                    )
                    logger.info(f"🔍 Started verification thread for '{auth.name}' on smartlock {smartlock_id}")
                else:
                    # Create a fallback response but mark as failed
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
                    failed_creations.append({
                        "smartlockId": smartlock_id,
                        "reason": "MQTT creation timeout - authorization may still be processing"
                    })
                    logger.error(f"❌ Failed to create keypad code for smartlock {smartlock_id}: timeout")
            
            else:
                # Create regular authorization via MQTT
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
                
                logger.info(f"Sending MQTT authorization action for smartlock {smartlock_id}: {mqtt_action_data}")
                
                # Send MQTT action - this will create the authorization via MQTT handler
                mqtt_client.publish_authorization_action(smartlock_id, mqtt_action_data)
                
                # Wait longer for MQTT processing
                time.sleep(0.5)
                
                # Retry logic for regular authorizations
                created_auth = None
                for attempt in range(3):
                    new_auths = [a for a in mqtt_client.data_store.get_authorizations() 
                                if a.get("smartlockId") == smartlock_id and 
                                   a.get("name") == auth.name and 
                                   a.get("type") == auth.type]
                    if new_auths:
                        created_auth = new_auths[-1]  # Take the most recent one
                        logger.info(f"✅ Successfully created authorization for smartlock {smartlock_id}: {auth.name}")
                        break
                    else:
                        logger.warning(f"Attempt {attempt+1}: Auth not found yet for smartlock {smartlock_id}, waiting...")
                        time.sleep(0.3)
                
                if created_auth:
                    created_auths.append(created_auth)
                else:
                    # Create a fallback response but mark as failed
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
                    failed_creations.append({
                        "smartlockId": smartlock_id,
                        "reason": "MQTT creation timeout - authorization may still be processing"
                    })
                    logger.error(f"❌ Failed to create authorization for smartlock {smartlock_id}: timeout")
            
            # ENHANCED: Adaptive delay between smartlocks to prevent race conditions
            if i < len(auth.smartlockIds) - 1:  # Don't wait after the last one
                inter_smartlock_delay = 0.7 + (i * 0.1)  # Increasing delay for later smartlocks
                logger.info(f"Waiting {inter_smartlock_delay}s before processing next smartlock...")
                time.sleep(inter_smartlock_delay)
                
        except Exception as e:
            logger.error(f"❌ Exception while creating authorization for smartlock {smartlock_id}: {e}")
            failed_creations.append({
                "smartlockId": smartlock_id,
                "reason": f"Exception: {str(e)}"
            })
    
    # Prepare response
    if created_auths:
        response_auth = created_auths[0]  # Return the first created auth (Nuki API behavior)
        logger.info(f"✅ Successfully created {len(created_auths)} authorization(s), {len(failed_creations)} failed")
        
        # Add information about failures to the response if any occurred
        if failed_creations:
            logger.warning(f"Some failures occurred: {failed_creations}")
            # Note: In a real scenario, you might want to return this information to the client
            # But for API compatibility, we just log it
        
        return response_auth
    else:
        logger.error(f"❌ Failed to create any authorizations. Failures: {failed_creations}")
        raise HTTPException(status_code=500, detail=f"Failed to create authorization for all smartlocks: {failed_creations}")

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
        
        # ENHANCED: Start verification thread for keypad code updates
        if auth.enabled is not None:
            mqtt_client.start_authorization_verification_thread(
                smartlock_id=smartlock_id,
                expected_name=auth.name,
                expected_enabled=auth.enabled,
                expected_code=auth.code,
                max_attempts=3
            )
            logger.info(f"🔍 Started verification thread for keypad update '{auth.name}' on smartlock {smartlock_id}")
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
        
        # ENHANCED: Start verification thread for regular authorization updates
        if auth.enabled is not None:
            mqtt_client.start_authorization_verification_thread(
                smartlock_id=smartlock_id,
                expected_name=auth.name,
                expected_enabled=auth.enabled,
                expected_code=auth.code,
                max_attempts=3
            )
            logger.info(f"🔍 Started verification thread for authorization update '{auth.name}' on smartlock {smartlock_id}")
    
    return {"message": "Authorization updated successfully"}

def _convert_api_to_mqtt_keypad(auth: SmartlockAuthUpdate, auth_id: str) -> dict:
    """Convert API format to MQTT keypad action format"""
    
    # Extract the original codeId from the unique ID format
    if "_" in auth_id:
        # New format: "smartlockId_codeId"
        parts = auth_id.split("_")
        if len(parts) == 2 and parts[1].isdigit():
            numeric_code_id = int(parts[1])
        else:
            raise ValueError(f"Invalid unique ID format: {auth_id}")
    else:
        # Old format: just the codeId
        if auth_id.isdigit():
            numeric_code_id = int(auth_id)
        else:
            raise ValueError(f"Cannot determine numeric codeId from auth_id: {auth_id}")
    
    action_data = {
        "action": "update",
        "codeId": numeric_code_id,  # MQTT expects numeric codeId
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
        weekday_map = {64: "mon", 32: "tue", 16: "wed", 8: "thu", 4: "fri", 2: "sat", 1: "sun"}
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
    """Delete smartlock authorizations - deletes only from specific smartlocks based on auth_id"""
    
    deleted_auths = []
    failed_deletions = []
    
    import time
    
    for auth_id in auth_ids:
        try:
            logger.info(f"🗑️ Processing deletion request for auth_id: {auth_id}")
            
            # Parse auth_id to extract smartlock_id and code_id
            if "_" in auth_id:
                # New format: "smartlock_id_code_id"
                parts = auth_id.split("_")
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    target_smartlock_id = int(parts[0])
                    target_code_id = int(parts[1])
                else:
                    failed_deletions.append({"id": auth_id, "reason": "Invalid auth_id format"})
                    continue
            else:
                # Old format or invalid - try to find the authorization first
                target_auth = mqtt_client.data_store.get_authorization_safe(auth_id)
                if not target_auth:
                    failed_deletions.append({"id": auth_id, "reason": "Authorization not found"})
                    continue
                
                target_smartlock_id = target_auth.get("smartlockId")
                # Extract code_id from the auth_id or authId
                if auth_id.isdigit():
                    target_code_id = int(auth_id)
                else:
                    failed_deletions.append({"id": auth_id, "reason": "Cannot determine code_id from auth_id"})
                    continue
            
            logger.info(f"🎯 Deleting from smartlock {target_smartlock_id}, code_id {target_code_id}")
            
            # Find the specific keypad code in the target smartlock
            target_code = None
            with mqtt_client.data_store.lock:
                codes = mqtt_client.data_store.keypad_codes.get(target_smartlock_id, [])
                for code in codes:
                    if code.get("codeId") == target_code_id:
                        target_code = code
                        break
            
            if not target_code:
                failed_deletions.append({
                    "id": auth_id,
                    "smartlockId": target_smartlock_id,
                    "reason": f"Keypad code {target_code_id} not found in smartlock {target_smartlock_id}"
                })
                continue
            
            # Delete the specific keypad code
            auth_name = target_code.get("name", "Unknown")
            code_value = target_code.get("code")
            
            action_data = {
                "action": "delete",
                "codeId": target_code_id
            }
            
            logger.info(f"🗑️ Deleting keypad code from smartlock {target_smartlock_id}: CodeId={target_code_id}, Name='{auth_name}', Code={code_value}")
            mqtt_client.publish_keypad_action(target_smartlock_id, action_data)
            
            # Clean up specific MQTT topics for this keypad code
            code_index = target_code.get("index")  # Get the index for targeted cleanup
            mqtt_client.cleanup_keypad_code_mqtt_topics(target_smartlock_id, target_code_id, code_index)
            logger.info(f"🧹 Cleaned up MQTT topics for deleted keypad code {target_code_id} (index: {code_index})")
            
            # Generate the unique ID for response (same format as API uses)
            unique_id = f"{target_smartlock_id}_{target_code_id}"
            
            deleted_auths.append({
                "id": unique_id,
                "name": auth_name,
                "smartlockId": target_smartlock_id,
                "type": "keypad",
                "code": code_value,
                "codeId": target_code_id
            })
            
            # Wait between deletions to avoid MQTT flooding
            time.sleep(0.2)
                    
        except Exception as e:
            logger.error(f"Unexpected error processing auth_id {auth_id}: {e}")
            failed_deletions.append({"id": auth_id, "reason": f"Unexpected error: {e}"})
    
    # Prepare response with detailed information
    response = {
        "message": f"Successfully deleted {len(deleted_auths)} keypad code(s) from specific smartlocks",
        "deleted": deleted_auths,
        "deleted_count": len(deleted_auths)
    }
    
    if failed_deletions:
        response["failed"] = failed_deletions
        response["failed_count"] = len(failed_deletions)
        response["message"] += f", {len(failed_deletions)} failed"
    
    # Log individual deletions for better visibility
    if deleted_auths:
        logger.info("✅ DELETION SUMMARY:")
        for auth in deleted_auths:
            logger.info(f"  - Deleted '{auth['name']}' (code: {auth['code']}) from smartlock {auth['smartlockId']}")
    
    return response

@app.get("/smartlock/log")
def get_all_smartlock_logs(limit: int = 10000, fromDate: str = None, toDate: str = None, id: str = None):
    """Get logs from all smartlocks - reads from persistent storage"""
    # Use LogManager to get logs from disk instead of memory
    logs = mqtt_client.log_manager.get_logs(smartlock_id=None, limit=limit)
    
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
def get_smartlock_logs(smartlock_id: int, limit: int = 10000, fromDate: str = None, toDate: str = None, id: str = None):
    """Get logs for a specific smartlock - reads from persistent storage"""
    # Use LogManager to get logs from disk instead of memory
    logs = mqtt_client.log_manager.get_logs(smartlock_id=smartlock_id, limit=limit)
    
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
