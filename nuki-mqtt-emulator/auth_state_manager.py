import hashlib
import threading
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, Set
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthorizationStateManager:
    """
    In-Memory Authorization State Manager for Nuki MQTT Emulator
    
    Manages and monitors authorization states to ensure they remain as intended.
    Automatically saves current states and restores them if unauthorized changes occur.
    All state management is done in RAM - no disk storage.
    """
    
    def __init__(self, auto_restore_enabled: bool = True):
        self.auto_restore_enabled = auto_restore_enabled
        self.lock = threading.RLock()
        
        # In-memory state tracking (no disk storage)
        self.expected_states: Dict[int, Dict[str, Any]] = {}  # smartlock_id -> {auth_id -> auth_data}
        self.monitoring_enabled: Dict[int, bool] = {}  # smartlock_id -> monitoring_enabled
        self.last_change_times: Dict[int, float] = {}  # smartlock_id -> last_change_timestamp
        
        # Change detection and restoration
        self.pending_restorations: Set[str] = set()  # Track pending restoration actions
        self.restoration_delays: Dict[str, float] = {}  # restoration_id -> delay_time
        
        # ENHANCED: Anti-loop protection
        self.restoration_cooldowns: Dict[int, float] = {}  # smartlock_id -> last_restoration_time
        self.cooldown_duration = 10.0  # 10 seconds cooldown after restoration
        self.our_restoration_actions: Set[str] = set()  # Track our own restoration action hashes
        self.last_restoration_count: Dict[int, int] = {}  # smartlock_id -> count of recent restorations
        self.max_restorations_per_minute = 5  # Max restorations per minute per smartlock
        
        # MQTT client reference (will be set later)
        self.mqtt_client = None
        
        logger.info(f"🔒 AuthorizationStateManager initialized (RAM-only, auto_restore: {auto_restore_enabled}, anti-loop protection enabled)")
    
    def set_mqtt_client(self, mqtt_client):
        """Set the MQTT client reference for restoration actions"""
        self.mqtt_client = mqtt_client
        logger.info("🔗 MQTT client reference set for AuthorizationStateManager")
    
    def _generate_content_hash(self, auth_data: Dict[str, Any]) -> str:
        """Generate content hash for change detection - includes all Time-Limited Access fields"""
        # Use key fields that matter for authorization state, especially Time-Limited Access
        relevant_fields = ['name', 'enabled', 'code', 'type', 'timeLimited', 
                          'allowedFromDate', 'allowedUntilDate', 'allowedWeekDays', 
                          'allowedFromTime', 'allowedUntilTime']
        
        content_parts = []
        for field in relevant_fields:
            if field in auth_data:
                value = auth_data[field]
                # Normalize Time-Limited values for consistent hashing
                if field == 'timeLimited':
                    value = 1 if value else 0
                elif field in ['allowedFromDate', 'allowedUntilDate'] and value:
                    # Normalize date format for consistent comparison
                    value = str(value).replace('T', ' ').replace('.000Z', '')
                elif field == 'allowedWeekDays' and isinstance(value, list):
                    # Sort weekdays for consistent hashing
                    value = sorted(value) if value else []
                content_parts.append(f"{field}:{value}")
        
        content_string = "|".join(content_parts)
        return hashlib.md5(content_string.encode('utf-8')).hexdigest()
    
    def save_current_state(self, smartlock_id: int, authorizations: List[Dict[str, Any]], 
                          source: str = "manual", reason: str = "state_save"):
        """
        Save the current authorization state as the expected/desired state (RAM-only)
        
        Args:
            smartlock_id: The smartlock ID
            authorizations: List of authorization data
            source: Source of the save action (e.g., "api_create", "manual", "mqtt_update")
            reason: Reason for saving (e.g., "initial_save", "after_create", "periodic_backup")
        """
        with self.lock:
            try:
                # Filter authorizations for this smartlock and type 13 (keypad codes)
                relevant_auths = [
                    auth for auth in authorizations 
                    if (auth.get("smartlockId") == smartlock_id and 
                        auth.get("type") == 13)
                ]
                
                # Create state data structure in memory
                auth_states = {}
                
                # Process each authorization
                for auth in relevant_auths:
                    auth_id = auth.get("id")
                    if auth_id:
                        # Create clean authorization data for storage
                        clean_auth = {
                            "id": auth_id,
                            "name": auth.get("name"),
                            "code": auth.get("code"),
                            "enabled": auth.get("enabled", True),
                            "type": auth.get("type", 13),
                            "timeLimited": auth.get("timeLimited", 0),
                            "content_hash": self._generate_content_hash(auth)
                        }
                        
                        # Add time-limited fields if present
                        time_limited_fields = ['allowedFromDate', 'allowedUntilDate', 'allowedWeekDays', 
                                             'allowedFromTime', 'allowedUntilTime']
                        for field in time_limited_fields:
                            if field in auth:
                                clean_auth[field] = auth[field]
                        
                        auth_states[auth_id] = clean_auth
                
                # Store in memory only
                self.expected_states[smartlock_id] = auth_states
                self.last_change_times[smartlock_id] = time.time()
                
                logger.info(f"💾 Saved authorization state in RAM for smartlock {smartlock_id}: "
                          f"{len(relevant_auths)} authorizations (source: {source}, reason: {reason})")
                
                # Enable monitoring for this smartlock
                self.enable_monitoring(smartlock_id)
                
            except Exception as e:
                logger.error(f"❌ Failed to save authorization state for smartlock {smartlock_id}: {e}")
    
    def enable_monitoring(self, smartlock_id: int):
        """Enable monitoring for a specific smartlock"""
        with self.lock:
            self.monitoring_enabled[smartlock_id] = True
            logger.info(f"👁️ Enabled authorization monitoring for smartlock {smartlock_id}")
    
    def disable_monitoring(self, smartlock_id: int):
        """Disable monitoring for a specific smartlock"""
        with self.lock:
            self.monitoring_enabled[smartlock_id] = False
            logger.info(f"🔒 Disabled authorization monitoring for smartlock {smartlock_id}")
    
    def is_monitoring_enabled(self, smartlock_id: int) -> bool:
        """Check if monitoring is enabled for a smartlock"""
        with self.lock:
            return self.monitoring_enabled.get(smartlock_id, False)
    
    def check_for_changes(self, smartlock_id: int, current_authorizations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Check current authorizations against expected state and detect changes
        
        Returns:
            Dict with change detection results
        """
        with self.lock:
            try:
                logger.debug(f"🔍 DEBUG: Starting change check for smartlock {smartlock_id}")
                
                if not self.is_monitoring_enabled(smartlock_id):
                    logger.debug(f"🔍 DEBUG: Monitoring disabled for smartlock {smartlock_id}")
                    return {"monitoring_enabled": False}
                
                expected_state = self.expected_states.get(smartlock_id, {})
                if not expected_state:
                    logger.debug(f"🔍 DEBUG: No expected state for smartlock {smartlock_id}")
                    return {"has_expected_state": False}
                
                logger.debug(f"🔍 DEBUG: Expected state has {len(expected_state)} authorizations for smartlock {smartlock_id}")
                for auth_id, auth_data in expected_state.items():
                    logger.debug(f"  - Expected: {auth_id} = '{auth_data.get('name')}' (enabled: {auth_data.get('enabled')}, hash: {auth_data.get('content_hash')})")
                
                # Filter current auths for this smartlock (type 13)
                current_auths = [
                    auth for auth in current_authorizations 
                    if (auth.get("smartlockId") == smartlock_id and 
                        auth.get("type") == 13)
                ]
                
                logger.debug(f"🔍 DEBUG: Found {len(current_auths)} current authorizations for smartlock {smartlock_id}")
                
                # Build current state map
                current_state = {}
                for auth in current_auths:
                    auth_id = auth.get("id")
                    if auth_id:
                        current_hash = self._generate_content_hash(auth)
                        logger.debug(f"  - Current: {auth_id} = '{auth.get('name')}' (enabled: {auth.get('enabled')}, hash: {current_hash})")
                        current_state[auth_id] = auth
                
                # Detect changes
                changes_detected = []
                missing_auths = []
                unexpected_auths = []
                
                logger.debug(f"🔍 DEBUG: Comparing expected vs current state...")
                
                # Check for changes in expected authorizations
                for auth_id, expected_auth in expected_state.items():
                    current_auth = current_state.get(auth_id)
                    
                    if not current_auth:
                        logger.warning(f"🔍 DEBUG: MISSING AUTH: {auth_id} = '{expected_auth.get('name')}' not found in current state")
                        missing_auths.append({
                            "auth_id": auth_id,
                            "expected_name": expected_auth.get("name"),
                            "action": "missing"
                        })
                        continue
                    
                    # Check for changes in enabled status
                    expected_enabled = expected_auth.get("enabled", True)
                    current_enabled = current_auth.get("enabled", True)
                    
                    logger.debug(f"🔍 DEBUG: Enabled check for {auth_id}: expected={expected_enabled}, current={current_enabled}")
                    
                    if bool(expected_enabled) != bool(current_enabled):
                        logger.warning(f"🔍 DEBUG: ENABLED CHANGE: {auth_id} = '{current_auth.get('name')}' enabled changed from {expected_enabled} to {current_enabled}")
                        changes_detected.append({
                            "auth_id": auth_id,
                            "name": current_auth.get("name"),
                            "field": "enabled",
                            "expected": expected_enabled,
                            "current": current_enabled,
                            "action": "restore_enabled"
                        })
                    
                    # 🆕 Check for changes in authorization name
                    expected_name = expected_auth.get("name", "")
                    current_name = current_auth.get("name", "")
                    
                    logger.debug(f"🔍 DEBUG: Name check for {auth_id}: expected='{expected_name}', current='{current_name}'")
                    
                    if str(expected_name) != str(current_name):
                        logger.warning(f"🔍 DEBUG: NAME CHANGE: {auth_id} name changed from '{expected_name}' to '{current_name}'")
                        changes_detected.append({
                            "auth_id": auth_id,
                            "name": current_auth.get("name"),  # Use current name for logging
                            "field": "name",
                            "expected": expected_name,
                            "current": current_name,
                            "action": "restore_name"
                        })
                    
                    # Check for content changes (name, code, time restrictions)
                    expected_hash = expected_auth.get("content_hash")
                    current_hash = self._generate_content_hash(current_auth)
                    
                    logger.debug(f"🔍 DEBUG: Hash check for {auth_id}: expected={expected_hash}, current={current_hash}")
                    
                    if expected_hash and expected_hash != current_hash:
                        logger.warning(f"🔍 DEBUG: CONTENT CHANGE: {auth_id} = '{current_auth.get('name')}' content hash mismatch")
                        logger.warning(f"  - Expected hash: {expected_hash}")
                        logger.warning(f"  - Current hash: {current_hash}")
                        
                        # DEBUG: Compare field by field
                        relevant_fields = ['name', 'enabled', 'code', 'type', 'timeLimited', 
                                          'allowedFromDate', 'allowedUntilDate', 'allowedWeekDays', 
                                          'allowedFromTime', 'allowedUntilTime']
                        
                        logger.warning(f"  - Field-by-field comparison:")
                        for field in relevant_fields:
                            expected_val = expected_auth.get(field)
                            current_val = current_auth.get(field)
                            if str(expected_val) != str(current_val):
                                logger.warning(f"    * {field}: expected='{expected_val}' vs current='{current_val}'")
                        
                        changes_detected.append({
                            "auth_id": auth_id,
                            "name": current_auth.get("name"),
                            "field": "content",
                            "expected_hash": expected_hash,
                            "current_hash": current_hash,
                            "action": "restore_content"
                        })
                
                # Check for unexpected new authorizations
                for auth_id in current_state:
                    if auth_id not in expected_state:
                        logger.warning(f"🔍 DEBUG: UNEXPECTED AUTH: {auth_id} = '{current_state[auth_id].get('name')}' not in expected state")
                        unexpected_auths.append({
                            "auth_id": auth_id,
                            "name": current_state[auth_id].get("name"),
                            "action": "unexpected"
                        })
                
                total_changes = len(changes_detected) + len(missing_auths) + len(unexpected_auths)
                logger.debug(f"🔍 DEBUG: Change detection completed: {total_changes} total changes")
                logger.debug(f"  - Changes detected: {len(changes_detected)}")
                logger.debug(f"  - Missing auths: {len(missing_auths)}")
                logger.debug(f"  - Unexpected auths: {len(unexpected_auths)}")
                
                result = {
                    "monitoring_enabled": True,
                    "has_expected_state": True,
                    "changes_detected": changes_detected,
                    "missing_auths": missing_auths,
                    "unexpected_auths": unexpected_auths,
                    "total_changes": total_changes,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                return result
                
            except Exception as e:
                logger.error(f"❌ Error checking for changes in smartlock {smartlock_id}: {e}")
                return {"error": str(e)}
    
    def auto_restore_if_needed(self, smartlock_id: int, current_authorizations: List[Dict[str, Any]]):
        """
        Automatically restore authorizations if unauthorized changes are detected (with anti-loop protection)
        """
        logger.debug(f"🔧 DEBUG AUTO_RESTORE: Called for smartlock {smartlock_id}")
        logger.debug(f"🔧 DEBUG AUTO_RESTORE: auto_restore_enabled = {self.auto_restore_enabled}")
        
        if not self.auto_restore_enabled:
            logger.debug(f"🔧 DEBUG AUTO_RESTORE: Auto-restore disabled, returning")
            return
        
        with self.lock:
            try:
                # ENHANCED: Check cooldown period to prevent loops
                current_time = time.time()
                last_restoration = self.restoration_cooldowns.get(smartlock_id, 0)
                
                logger.debug(f"🔧 DEBUG AUTO_RESTORE: Cooldown check - last_restoration: {last_restoration}, current_time: {current_time}")
                logger.debug(f"🔧 DEBUG AUTO_RESTORE: Time since last restoration: {current_time - last_restoration:.2f}s")
                logger.debug(f"🔧 DEBUG AUTO_RESTORE: Cooldown duration: {self.cooldown_duration}s")
                
                if current_time - last_restoration < self.cooldown_duration:
                    time_remaining = self.cooldown_duration - (current_time - last_restoration)
                    logger.debug(f"⏰ DEBUG AUTO_RESTORE: Cooldown active for smartlock {smartlock_id}: {time_remaining:.1f}s remaining")
                    return
                
                # ENHANCED: Check restoration rate limiting
                logger.debug(f"🔧 DEBUG AUTO_RESTORE: Checking rate limit...")
                if not self._check_restoration_rate_limit(smartlock_id):
                    logger.warning(f"🚫 DEBUG AUTO_RESTORE: Rate limit exceeded for smartlock {smartlock_id} - skipping auto-restore")
                    return
                
                logger.debug(f"🔧 DEBUG AUTO_RESTORE: Rate limit OK, checking for changes...")
                
                # Check for changes
                change_result = self.check_for_changes(smartlock_id, current_authorizations)
                
                logger.debug(f"🔧 DEBUG AUTO_RESTORE: Change result: {change_result}")
                
                if change_result.get("total_changes", 0) > 0:
                    logger.warning(f"🚨 DEBUG AUTO_RESTORE: Unauthorized changes detected for smartlock {smartlock_id}: "
                                 f"{change_result['total_changes']} changes")
                    logger.warning(f"🚨 DEBUG AUTO_RESTORE: Change details: {change_result}")
                    
                    # ENHANCED: Update cooldown timer BEFORE processing actions
                    logger.debug(f"🔧 DEBUG AUTO_RESTORE: Setting cooldown timer to {current_time}")
                    self.restoration_cooldowns[smartlock_id] = current_time
                    
                    # Process each type of change
                    logger.debug(f"🔧 DEBUG AUTO_RESTORE: Processing restoration actions...")
                    self._process_restoration_actions(smartlock_id, change_result)
                    
                    # ENHANCED: Track restoration count
                    logger.debug(f"🔧 DEBUG AUTO_RESTORE: Incrementing restoration count...")
                    self._increment_restoration_count(smartlock_id)
                    
                    logger.debug(f"🔧 DEBUG AUTO_RESTORE: Restoration processing completed")
                else:
                    logger.debug(f"✅ DEBUG AUTO_RESTORE: No unauthorized changes detected for smartlock {smartlock_id}")
                
            except Exception as e:
                logger.error(f"❌ Error in auto_restore for smartlock {smartlock_id}: {e}")
    
    def _process_restoration_actions(self, smartlock_id: int, change_result: Dict[str, Any]):
        """Process restoration actions for detected changes"""
        try:
            if not self.mqtt_client:
                logger.error("❌ Cannot restore: MQTT client not available")
                return
            
            # Process enabled/disabled changes
            for change in change_result.get("changes_detected", []):
                if change["action"] == "restore_enabled":
                    self._restore_enabled_status(smartlock_id, change)
                elif change["action"] == "restore_name":
                    self._restore_authorization_name(smartlock_id, change)
                elif change["action"] == "restore_content":
                    self._restore_authorization_content(smartlock_id, change)
            
            # Process missing authorizations
            for missing in change_result.get("missing_auths", []):
                self._restore_missing_authorization(smartlock_id, missing)
            
            # Log unexpected authorizations (but don't delete them automatically)
            for unexpected in change_result.get("unexpected_auths", []):
                logger.warning(f"⚠️ Unexpected authorization found: {unexpected['name']} (ID: {unexpected['auth_id']})")
                
        except Exception as e:
            logger.error(f"❌ Error processing restoration actions: {e}")
    
    def _restore_enabled_status(self, smartlock_id: int, change: Dict[str, Any]):
        """Restore the enabled status of an authorization"""
        try:
            auth_id = change["auth_id"]
            expected_enabled = change["expected"]
            name = change["name"]
            
            # Generate unique restoration ID to prevent duplicates
            restoration_id = f"restore_enabled_{smartlock_id}_{auth_id}_{int(time.time())}"
            
            if restoration_id in self.pending_restorations:
                return  # Already pending
            
            self.pending_restorations.add(restoration_id)
            
            logger.warning(f"🔧 Restoring enabled status for '{name}' (ID: {auth_id}) to {expected_enabled}")
            
            # Extract code ID for MQTT action
            code_id = None
            if "_" in auth_id:
                parts = auth_id.split("_")
                if len(parts) == 2 and parts[1].isdigit():
                    code_id = int(parts[1])
            
            if code_id is not None:
                # Send MQTT restoration action
                restoration_action = {
                    "action": "update",
                    "codeId": code_id,
                    "name": name,
                    "enabled": 1 if expected_enabled else 0
                }
                
                self.mqtt_client.publish_keypad_action(smartlock_id, restoration_action)
                logger.info(f"✅ Sent restoration MQTT action for '{name}': enabled={expected_enabled}")
                
                # Remove from pending after delay
                def cleanup_pending():
                    time.sleep(2.0)
                    self.pending_restorations.discard(restoration_id)
                
                threading.Thread(target=cleanup_pending, daemon=True).start()
            else:
                logger.error(f"❌ Cannot extract code ID from auth_id: {auth_id}")
                self.pending_restorations.discard(restoration_id)
                
        except Exception as e:
            logger.error(f"❌ Error restoring enabled status: {e}")
            self.pending_restorations.discard(restoration_id)
    
    def _restore_authorization_name(self, smartlock_id: int, change: Dict[str, Any]):
        """Restore the name of an authorization"""
        try:
            auth_id = change["auth_id"]
            expected_name = change["expected"]
            current_name = change["current"]
            
            # Generate unique restoration ID to prevent duplicates
            restoration_id = f"restore_name_{smartlock_id}_{auth_id}_{int(time.time())}"
            
            if restoration_id in self.pending_restorations:
                return  # Already pending
            
            self.pending_restorations.add(restoration_id)
            
            logger.warning(f"🔧 Restoring authorization name from '{current_name}' to '{expected_name}' (ID: {auth_id})")
            
            # Extract code ID for MQTT action
            code_id = None
            if "_" in auth_id:
                parts = auth_id.split("_")
                if len(parts) == 2 and parts[1].isdigit():
                    code_id = int(parts[1])
            
            if code_id is not None:
                # Get expected state for full context
                expected_state = self.expected_states.get(smartlock_id, {})
                expected_auth = expected_state.get(auth_id)
                
                if expected_auth:
                    # Send MQTT restoration action with name and enabled status
                    restoration_action = {
                        "action": "update",
                        "codeId": code_id,
                        "name": expected_name,
                        "enabled": 1 if expected_auth.get("enabled", True) else 0
                    }
                    
                    # Add code if present
                    if expected_auth.get("code"):
                        restoration_action["code"] = expected_auth["code"]
                    
                    self.mqtt_client.publish_keypad_action(smartlock_id, restoration_action)
                    logger.info(f"✅ Sent name restoration MQTT action: '{current_name}' -> '{expected_name}'")
                    
                    # Remove from pending after delay
                    def cleanup_pending():
                        time.sleep(2.0)
                        self.pending_restorations.discard(restoration_id)
                    
                    threading.Thread(target=cleanup_pending, daemon=True).start()
                else:
                    logger.error(f"❌ No expected state found for auth_id: {auth_id}")
                    self.pending_restorations.discard(restoration_id)
            else:
                logger.error(f"❌ Cannot extract code ID from auth_id: {auth_id}")
                self.pending_restorations.discard(restoration_id)
                
        except Exception as e:
            logger.error(f"❌ Error restoring authorization name: {e}")
            if 'restoration_id' in locals():
                self.pending_restorations.discard(restoration_id)
    
    def _restore_authorization_content(self, smartlock_id: int, change: Dict[str, Any]):
        """Restore the content of an authorization (name, code, time restrictions)"""
        try:
            auth_id = change["auth_id"]
            
            # Get expected content from stored state
            expected_state = self.expected_states.get(smartlock_id, {})
            expected_auth = expected_state.get(auth_id)
            
            if not expected_auth:
                logger.error(f"❌ No expected state found for auth_id: {auth_id}")
                return
            
            # Generate unique restoration ID
            restoration_id = f"restore_content_{smartlock_id}_{auth_id}_{int(time.time())}"
            
            if restoration_id in self.pending_restorations:
                logger.debug(f"🔧 DEBUG: Restoration already pending for {restoration_id}")
                return
            
            self.pending_restorations.add(restoration_id)
            
            logger.warning(f"🔧 DEBUG RESTORATION: Starting content restoration for '{expected_auth.get('name')}' (ID: {auth_id})")
            logger.warning(f"🔧 DEBUG RESTORATION: Expected auth data: {expected_auth}")
            
            # Extract code ID
            code_id = None
            if "_" in auth_id:
                parts = auth_id.split("_")
                if len(parts) == 2 and parts[1].isdigit():
                    code_id = int(parts[1])
            
            if code_id is not None:
                # Prepare full restoration action with CORRECT field conversion
                restoration_action = {
                    "action": "update",
                    "codeId": code_id,
                    "name": expected_auth.get("name"),
                    "enabled": 1 if expected_auth.get("enabled", True) else 0
                }
                
                # Add code if present
                if expected_auth.get("code"):
                    restoration_action["code"] = expected_auth["code"]
                
                # ENHANCED: Check if ANY Time-Limited fields exist in Expected State (auto-detect)
                allowed_from_date = expected_auth.get("allowedFromDate")
                allowed_until_date = expected_auth.get("allowedUntilDate")
                allowed_weekdays = expected_auth.get("allowedWeekDays")
                allowed_from_time = expected_auth.get("allowedFromTime")
                allowed_until_time = expected_auth.get("allowedUntilTime")
                
                # Auto-detect if Time-Limited fields are present
                has_time_restrictions = any([
                    allowed_from_date and allowed_from_date.strip(),
                    allowed_until_date and allowed_until_date.strip(),
                    allowed_weekdays is not None and allowed_weekdays > 0,
                    allowed_from_time is not None,
                    allowed_until_time is not None
                ])
                
                logger.warning(f"🔧 DEBUG RESTORATION: Time-Limited detection:")
                logger.warning(f"  - allowedFromDate: {allowed_from_date}")
                logger.warning(f"  - allowedUntilDate: {allowed_until_date}")
                logger.warning(f"  - allowedWeekDays: {allowed_weekdays}")
                logger.warning(f"  - allowedFromTime: {allowed_from_time}")
                logger.warning(f"  - allowedUntilTime: {allowed_until_time}")
                logger.warning(f"  - has_time_restrictions: {has_time_restrictions}")
                
                if has_time_restrictions:
                    restoration_action["timeLimited"] = 1
                    logger.warning(f"🔧 DEBUG RESTORATION: Setting timeLimited = 1 (time restrictions detected)")
                    
                    # Convert API date format to MQTT format
                    if allowed_from_date and allowed_from_date.strip():
                        # Convert "2025-08-07T15:36:00.000Z" to "2025-08-07 15:36:00"
                        mqtt_from_date = allowed_from_date.replace("T", " ").replace(".000Z", "")
                        restoration_action["allowedFrom"] = mqtt_from_date
                        logger.warning(f"🔧 DEBUG RESTORATION: Converting allowedFromDate: '{allowed_from_date}' -> '{mqtt_from_date}'")
                    
                    if allowed_until_date and allowed_until_date.strip():
                        # Convert "2025-08-07T15:36:00.000Z" to "2025-08-07 15:36:00"
                        mqtt_until_date = allowed_until_date.replace("T", " ").replace(".000Z", "")
                        restoration_action["allowedUntil"] = mqtt_until_date
                        logger.warning(f"🔧 DEBUG RESTORATION: Converting allowedUntilDate: '{allowed_until_date}' -> '{mqtt_until_date}'")
                    
                    # Convert weekday bit representation to weekday names
                    if allowed_weekdays is not None and allowed_weekdays > 0:
                        # Convert bit representation (40) to weekday names ["fri"]
                        weekday_map = {64: "mon", 32: "tue", 16: "wed", 8: "thu", 4: "fri", 2: "sat", 1: "sun"}
                        weekdays = []
                        for bit, day in weekday_map.items():
                            if allowed_weekdays & bit:
                                weekdays.append(day)
                        restoration_action["allowedWeekdays"] = weekdays
                        logger.warning(f"🔧 DEBUG RESTORATION: Converting allowedWeekDays: {allowed_weekdays} -> {weekdays}")
                    
                    # Convert time minutes to HH:MM format
                    if allowed_from_time is not None:
                        hours = allowed_from_time // 60
                        minutes = allowed_from_time % 60
                        time_str = f"{hours:02d}:{minutes:02d}"
                        restoration_action["allowedFromTime"] = time_str
                        logger.warning(f"🔧 DEBUG RESTORATION: Converting allowedFromTime: {allowed_from_time} -> '{time_str}'")
                    
                    if allowed_until_time is not None:
                        hours = allowed_until_time // 60
                        minutes = allowed_until_time % 60
                        time_str = f"{hours:02d}:{minutes:02d}"
                        restoration_action["allowedUntilTime"] = time_str
                        logger.warning(f"🔧 DEBUG RESTORATION: Converting allowedUntilTime: {allowed_until_time} -> '{time_str}'")
                else:
                    restoration_action["timeLimited"] = 0
                    logger.warning(f"🔧 DEBUG RESTORATION: No time-limited fields detected, setting timeLimited = 0")
                
                logger.warning(f"🔧 DEBUG RESTORATION: Final restoration action: {restoration_action}")
                
                # ENHANCED: Mark this as our own restoration to prevent loops
                if self.mqtt_client:
                    # Set cooldown BEFORE sending to prevent immediate re-detection
                    current_time = time.time()
                    self.restoration_cooldowns[smartlock_id] = current_time
                    logger.warning(f"🔧 DEBUG RESTORATION: Set cooldown timer before sending restoration")
                    
                    self.mqtt_client.publish_keypad_action(smartlock_id, restoration_action)
                    logger.info(f"✅ Sent content restoration MQTT action for '{expected_auth.get('name')}'")
                else:
                    logger.error(f"❌ No MQTT client available for restoration")
                
                # Cleanup after longer delay
                def cleanup_pending():
                    time.sleep(5.0)  # Longer delay for content restoration
                    self.pending_restorations.discard(restoration_id)
                    logger.debug(f"🔧 DEBUG RESTORATION: Cleaned up pending restoration {restoration_id}")
                
                threading.Thread(target=cleanup_pending, daemon=True).start()
            else:
                logger.error(f"❌ Cannot extract code ID from auth_id: {auth_id}")
                self.pending_restorations.discard(restoration_id)
                
        except Exception as e:
            logger.error(f"❌ Error restoring authorization content: {e}")
            if 'restoration_id' in locals():
                self.pending_restorations.discard(restoration_id)
    
    def _restore_missing_authorization(self, smartlock_id: int, missing: Dict[str, Any]):
        """Restore a missing authorization (recreate it)"""
        try:
            auth_id = missing["auth_id"]
            expected_name = missing.get("expected_name", "Unknown")
            
            # Get expected authorization data from stored state
            expected_state = self.expected_states.get(smartlock_id, {})
            expected_auth = expected_state.get(auth_id)
            
            if not expected_auth:
                logger.error(f"❌ No expected state found for missing auth_id: {auth_id}")
                return
            
            # Generate unique restoration ID
            restoration_id = f"restore_missing_{smartlock_id}_{auth_id}_{int(time.time())}"
            
            if restoration_id in self.pending_restorations:
                return  # Already pending
            
            self.pending_restorations.add(restoration_id)
            
            logger.warning(f"🔧 Recreating missing authorization '{expected_name}' (ID: {auth_id})")
            
            # Extract code ID for MQTT action
            code_id = None
            if "_" in auth_id:
                parts = auth_id.split("_")
                if len(parts) == 2 and parts[1].isdigit():
                    code_id = int(parts[1])
            
            if code_id is not None:
                # Prepare full recreation action
                recreation_action = {
                    "action": "add",
                    "codeId": code_id,
                    "name": expected_auth.get("name"),
                    "enabled": 1 if expected_auth.get("enabled", True) else 0
                }
                
                # Add code if present
                if expected_auth.get("code"):
                    recreation_action["code"] = expected_auth["code"]
                
                # Add time-limited fields if present
                if expected_auth.get("timeLimited"):
                    recreation_action["timeLimited"] = expected_auth["timeLimited"]
                    
                    # Add time-limited fields
                    time_fields = ['allowedFromDate', 'allowedUntilDate', 'allowedWeekDays', 
                                 'allowedFromTime', 'allowedUntilTime']
                    for field in time_fields:
                        if field in expected_auth:
                            recreation_action[field] = expected_auth[field]
                
                self.mqtt_client.publish_keypad_action(smartlock_id, recreation_action)
                logger.info(f"✅ Sent recreation MQTT action for missing '{expected_name}' (code_id: {code_id})")
                
                # Cleanup pending after delay
                def cleanup_pending():
                    time.sleep(3.0)  # Longer delay for recreation
                    self.pending_restorations.discard(restoration_id)
                
                threading.Thread(target=cleanup_pending, daemon=True).start()
                
            else:
                logger.error(f"❌ Cannot extract code ID from auth_id: {auth_id} - cannot recreate")
                self.pending_restorations.discard(restoration_id)
                
        except Exception as e:
            logger.error(f"❌ Error recreating missing authorization: {e}")
            if 'restoration_id' in locals():
                self.pending_restorations.discard(restoration_id)
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status for all smartlocks"""
        with self.lock:
            status = {
                "auto_restore_enabled": self.auto_restore_enabled,
                "total_monitored_smartlocks": len(self.expected_states),
                "storage_mode": "RAM-only",
                "smartlocks": {}
            }
            
            for smartlock_id in self.expected_states:
                status["smartlocks"][smartlock_id] = {
                    "monitoring_enabled": self.is_monitoring_enabled(smartlock_id),
                    "expected_auth_count": len(self.expected_states[smartlock_id]),
                    "last_change_time": self.last_change_times.get(smartlock_id)
                }
            
            return status
    
    def manual_restore(self, smartlock_id: int, current_authorizations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Manually trigger restoration for a specific smartlock"""
        logger.info(f"🔧 Manual restoration triggered for smartlock {smartlock_id}")
        
        change_result = self.check_for_changes(smartlock_id, current_authorizations)
        
        if change_result.get("total_changes", 0) > 0:
            self._process_restoration_actions(smartlock_id, change_result)
            return {
                "action": "restoration_triggered",
                "changes_found": change_result["total_changes"],
                "details": change_result
            }
        else:
            return {
                "action": "no_changes_found",
                "message": "No restoration needed - all authorizations match expected state"
            }
    
    def find_and_remove_by_pin_and_name(self, smartlock_id: int, pin: int = None, name: str = None, reason: str = "api_update_preparation") -> List[Dict[str, Any]]:
        """
        Suche nach PIN (code) + Name und entferne alle matching Authorizations aus RAM
        
        Args:
            smartlock_id: The smartlock ID
            pin: The PIN/code to search for (optional)
            name: The name to search for (optional)
            reason: Reason for removal
            
        Returns:
            List of removed authorization data
        """
        with self.lock:
            removed_auths = []
            try:
                expected_state = self.expected_states.get(smartlock_id, {})
                if not expected_state:
                    logger.debug(f"No expected state found for smartlock {smartlock_id}")
                    return removed_auths
                
                # Finde alle matching Authorizations
                auth_ids_to_remove = []
                
                for auth_id, auth_data in expected_state.items():
                    match_found = False
                    
                    # Match Kriterien prüfen
                    if pin is not None and name is not None:
                        # Beide müssen matchen
                        if (auth_data.get("code") == pin and 
                            auth_data.get("name") == name):
                            match_found = True
                            logger.info(f"🔍 Found match by PIN+Name: '{name}' (PIN: {pin}, ID: {auth_id})")
                    elif pin is not None:
                        # Nur PIN muss matchen
                        if auth_data.get("code") == pin:
                            match_found = True
                            logger.info(f"🔍 Found match by PIN: {pin} (Name: '{auth_data.get('name')}', ID: {auth_id})")
                    elif name is not None:
                        # Nur Name muss matchen
                        if auth_data.get("name") == name:
                            match_found = True
                            logger.info(f"🔍 Found match by Name: '{name}' (PIN: {auth_data.get('code')}, ID: {auth_id})")
                    
                    if match_found:
                        auth_ids_to_remove.append(auth_id)
                        removed_auths.append({
                            "auth_id": auth_id,
                            "name": auth_data.get("name"),
                            "code": auth_data.get("code"),
                            "enabled": auth_data.get("enabled"),
                            "complete_data": auth_data.copy()
                        })
                
                # Entferne die gefundenen Authorizations
                for auth_id in auth_ids_to_remove:
                    auth_name = expected_state[auth_id].get("name", "Unknown")
                    del expected_state[auth_id]
                    logger.info(f"🗑️ Removed authorization '{auth_name}' (ID: {auth_id}) from RAM for smartlock {smartlock_id} (reason: {reason})")
                
                if auth_ids_to_remove:
                    # Update the expected state
                    self.expected_states[smartlock_id] = expected_state
                    self.last_change_times[smartlock_id] = time.time()
                    
                    logger.info(f"📊 Removed {len(auth_ids_to_remove)} authorization(s) from RAM for smartlock {smartlock_id}")
                    
                    # If no more authorizations for this smartlock, disable monitoring
                    if not expected_state:
                        logger.info(f"🔒 No more expected authorizations for smartlock {smartlock_id}, disabling monitoring")
                        self.disable_monitoring(smartlock_id)
                else:
                    logger.debug(f"No matching authorizations found for smartlock {smartlock_id} (PIN: {pin}, Name: '{name}')")
                
                return removed_auths
                    
            except Exception as e:
                logger.error(f"❌ Error finding and removing authorizations by PIN+Name: {e}")
                return removed_auths
    
    def save_current_state_with_all_properties(self, smartlock_id: int, authorizations: List[Dict[str, Any]], 
                                             source: str = "api_update", reason: str = "post_update_save"):
        """
        Speichere den aktuellen Authorization State mit ALLEN Eigenschaften in RAM
        
        Args:
            smartlock_id: The smartlock ID
            authorizations: List of authorization data with ALL properties
            source: Source of the save action
            reason: Reason for saving
        """
        with self.lock:
            try:
                # Filter authorizations for this smartlock and type 13 (keypad codes)
                relevant_auths = [
                    auth for auth in authorizations 
                    if (auth.get("smartlockId") == smartlock_id and 
                        auth.get("type") == 13)
                ]
                
                # Create state data structure in memory
                auth_states = {}
                
                # Process each authorization with ALL properties
                for auth in relevant_auths:
                    auth_id = auth.get("id")
                    if auth_id:
                        # Speichere ALLE Eigenschaften der Authorization
                        complete_auth = {
                            "id": auth_id,
                            "smartlockId": auth.get("smartlockId"),
                            "authId": auth.get("authId"),
                            "name": auth.get("name"),
                            "code": auth.get("code"),
                            "enabled": auth.get("enabled", True),
                            "type": auth.get("type", 13),
                            "remoteAllowed": auth.get("remoteAllowed", True),
                            "lockCount": auth.get("lockCount", 0),
                            "creationDate": auth.get("creationDate"),
                            "content_hash": self._generate_content_hash(auth)
                        }
                        
                        # Time-Limited Access Eigenschaften
                        time_limited_fields = [
                            'timeLimited', 'allowedFromDate', 'allowedUntilDate', 
                            'allowedWeekDays', 'allowedFromTime', 'allowedUntilTime'
                        ]
                        for field in time_limited_fields:
                            if field in auth:
                                complete_auth[field] = auth[field]
                        
                        # Weitere Eigenschaften falls vorhanden
                        additional_fields = ['fingerprints', 'dateUpdated', 'accountUserId']
                        for field in additional_fields:
                            if field in auth:
                                complete_auth[field] = auth[field]
                        
                        auth_states[auth_id] = complete_auth
                        
                        logger.debug(f"💾 Stored complete authorization data: '{complete_auth.get('name')}' "
                                   f"(ID: {auth_id}, PIN: {complete_auth.get('code')}, "
                                   f"enabled: {complete_auth.get('enabled')}, "
                                   f"timeLimited: {complete_auth.get('timeLimited', 0)})")
                
                # Store in memory only
                self.expected_states[smartlock_id] = auth_states
                self.last_change_times[smartlock_id] = time.time()
                
                logger.info(f"💾 Saved COMPLETE authorization state in RAM for smartlock {smartlock_id}: "
                          f"{len(relevant_auths)} authorizations with ALL properties (source: {source}, reason: {reason})")
                
                # Enable monitoring for this smartlock
                self.enable_monitoring(smartlock_id)
                
            except Exception as e:
                logger.error(f"❌ Failed to save complete authorization state for smartlock {smartlock_id}: {e}")

    def remove_authorization_from_expected_state(self, smartlock_id: int, auth_id: str, reason: str = "deleted"):
        """
        Remove a specific authorization from expected state (when it's deleted)
        
        Args:
            smartlock_id: The smartlock ID
            auth_id: The authorization ID to remove
            reason: Reason for removal (e.g., "deleted", "api_delete", "mqtt_delete")
        """
        with self.lock:
            try:
                expected_state = self.expected_states.get(smartlock_id, {})
                
                if auth_id in expected_state:
                    auth_name = expected_state[auth_id].get("name", "Unknown")
                    del expected_state[auth_id]
                    
                    # Update the expected state
                    self.expected_states[smartlock_id] = expected_state
                    self.last_change_times[smartlock_id] = time.time()
                    
                    logger.info(f"🗑️ Removed authorization '{auth_name}' (ID: {auth_id}) from expected state for smartlock {smartlock_id} (reason: {reason})")
                    
                    # If no more authorizations for this smartlock, disable monitoring
                    if not expected_state:
                        logger.info(f"🔒 No more expected authorizations for smartlock {smartlock_id}, disabling monitoring")
                        self.disable_monitoring(smartlock_id)
                else:
                    logger.debug(f"Authorization {auth_id} not found in expected state for smartlock {smartlock_id}")
                    
            except Exception as e:
                logger.error(f"❌ Error removing authorization {auth_id} from expected state: {e}")
    
    def clear_expected_state(self, smartlock_id: int):
        """Clear the expected state for a smartlock (disable monitoring)"""
        with self.lock:
            if smartlock_id in self.expected_states:
                del self.expected_states[smartlock_id]
            
            if smartlock_id in self.last_change_times:
                del self.last_change_times[smartlock_id]
            
            self.disable_monitoring(smartlock_id)
            
            logger.info(f"🗑️ Cleared expected state for smartlock {smartlock_id} from RAM")
    
    def _check_restoration_rate_limit(self, smartlock_id: int) -> bool:
        """Check if restoration rate limit has been exceeded (anti-loop protection)"""
        current_time = time.time()
        
        # Clean up old restoration counts (older than 1 minute)
        minute_ago = current_time - 60.0
        
        # Get current count for this smartlock (reset if older than 1 minute)
        last_time = self.last_change_times.get(smartlock_id, 0)
        if last_time < minute_ago:
            self.last_restoration_count[smartlock_id] = 0
        
        current_count = self.last_restoration_count.get(smartlock_id, 0)
        
        if current_count >= self.max_restorations_per_minute:
            logger.warning(f"🚫 Rate limit exceeded for smartlock {smartlock_id}: {current_count}/{self.max_restorations_per_minute} restorations in last minute")
            return False
        
        return True
    
    def _increment_restoration_count(self, smartlock_id: int):
        """Increment restoration count for rate limiting"""
        current_count = self.last_restoration_count.get(smartlock_id, 0)
        self.last_restoration_count[smartlock_id] = current_count + 1
        logger.debug(f"📊 Restoration count for smartlock {smartlock_id}: {self.last_restoration_count[smartlock_id]}/{self.max_restorations_per_minute}")
    
    def is_in_cooldown(self, smartlock_id: int) -> bool:
        """Check if a smartlock is currently in cooldown period"""
        with self.lock:
            current_time = time.time()
            last_restoration = self.restoration_cooldowns.get(smartlock_id, 0)
            return (current_time - last_restoration) < self.cooldown_duration
    
    def get_cooldown_remaining(self, smartlock_id: int) -> float:
        """Get remaining cooldown time in seconds"""
        with self.lock:
            current_time = time.time()
            last_restoration = self.restoration_cooldowns.get(smartlock_id, 0)
            remaining = self.cooldown_duration - (current_time - last_restoration)
            return max(0.0, remaining)

# Global instance (RAM-only)
auth_state_manager = AuthorizationStateManager()
