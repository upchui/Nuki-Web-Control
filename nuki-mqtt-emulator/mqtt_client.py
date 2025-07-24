import os
import json
import logging
import threading
import time
import hashlib
from typing import Dict, Any, Optional, List
import paho.mqtt.client as mqtt
from datetime import datetime
import uuid

# Import log manager
from log_manager import LogManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthorizationIDMapper:
    """Manages bidirectional mapping between string IDs and numeric IDs for authorizations"""
    
    def __init__(self):
        self.string_to_numeric: Dict[str, int] = {}  # string_id -> numeric_id
        self.numeric_to_string: Dict[int, str] = {}  # numeric_id -> string_id
        self.lock = threading.RLock()
    
    def register_mapping(self, string_id: str, numeric_id: int):
        """Register a bidirectional mapping between string and numeric IDs"""
        with self.lock:
            # Remove any existing mappings to prevent conflicts
            if string_id in self.string_to_numeric:
                old_numeric = self.string_to_numeric[string_id]
                if old_numeric in self.numeric_to_string:
                    del self.numeric_to_string[old_numeric]
            
            if numeric_id in self.numeric_to_string:
                old_string = self.numeric_to_string[numeric_id]
                if old_string in self.string_to_numeric:
                    del self.string_to_numeric[old_string]
            
            # Register new mapping
            self.string_to_numeric[string_id] = numeric_id
            self.numeric_to_string[numeric_id] = string_id
            logger.debug(f"Registered ID mapping: {string_id} <-> {numeric_id}")
    
    def get_numeric_id(self, string_id: str) -> Optional[int]:
        """Get numeric ID from string ID"""
        with self.lock:
            return self.string_to_numeric.get(string_id)
    
    def get_string_id(self, numeric_id: int) -> Optional[str]:
        """Get string ID from numeric ID"""
        with self.lock:
            return self.numeric_to_string.get(numeric_id)
    
    def remove_mapping(self, string_id: str):
        """Remove mapping for a string ID"""
        with self.lock:
            if string_id in self.string_to_numeric:
                numeric_id = self.string_to_numeric[string_id]
                del self.string_to_numeric[string_id]
                if numeric_id in self.numeric_to_string:
                    del self.numeric_to_string[numeric_id]
                logger.debug(f"Removed ID mapping: {string_id} <-> {numeric_id}")


class MQTTDataStore:
    """In-memory data store that gets populated from MQTT topics"""
    
    def __init__(self):
        self.lock = threading.RLock()
        
        # Data structures to store MQTT data
        self.smartlocks: Dict[int, Dict[str, Any]] = {}
        self.authorizations: Dict[str, Dict[str, Any]] = {}
        self.keypad_codes: Dict[int, List[Dict[str, Any]]] = {}  # smartlock_id -> list of codes
        self.timecontrol_entries: Dict[int, List[Dict[str, Any]]] = {}  # smartlock_id -> list of entries
        self.logs: List[Dict[str, Any]] = []
        self.account_users: Dict[int, Dict[str, Any]] = {}
        
        # ID mapping for safe authorization management
        self.id_mapper = AuthorizationIDMapper()
        
        # Initialize with some default data
        self._initialize_default_data()
    
    def _initialize_default_data(self):
        """Initialize with empty data structures - will be populated from MQTT"""
        # Start with completely empty data structures - real data will come from MQTT
        self.smartlocks = {}
        self.authorizations = {}
        self.keypad_codes = {}
        self.timecontrol_entries = {}
        self.logs = []
        
        # Initialize minimal account users (these can be managed via API)
        self.account_users = {}
        
        # Do NOT create any default data - everything should come from MQTT
        logger.info("Initialized empty data structures - waiting for MQTT data")
    
    
    def get_smartlocks(self) -> List[Dict[str, Any]]:
        """Get all smartlocks"""
        with self.lock:
            return list(self.smartlocks.values())
    
    def get_smartlock(self, smartlock_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific smartlock"""
        with self.lock:
            return self.smartlocks.get(smartlock_id)
    
    def update_smartlock_state(self, smartlock_id: int, state_update: Dict[str, Any], mqtt_client=None):
        """Update smartlock state"""
        with self.lock:
            if smartlock_id not in self.smartlocks:
                # Create new smartlock if it doesn't exist
                self.create_smartlock(smartlock_id, mqtt_client)
            
            self.smartlocks[smartlock_id]["state"].update(state_update)
            self.smartlocks[smartlock_id]["state"]["timestamp"] = datetime.utcnow().isoformat()
            self.smartlocks[smartlock_id]["dateUpdated"] = datetime.utcnow().isoformat()
    
    def create_smartlock(self, smartlock_id: int, mqtt_client=None):
        """Create a new smartlock from MQTT discovery"""
        # Get device name from mapping if available
        device_name_from_map = None
        if mqtt_client and hasattr(mqtt_client, 'device_name_map'):
            device_name_from_map = mqtt_client.device_name_map.get(smartlock_id)
        
        # Determine device type and name based on smartlock_id and device name
        if smartlock_id == 1001:
            device_type = 0  # Lock
            device_name = "Nuki Lock"
        elif smartlock_id == 1002:
            device_type = 2  # Opener
            device_name = "Nuki Opener"
        elif device_name_from_map:
            # Use the device name from MQTT topic discovery
            if "opener" in device_name_from_map.lower():
                device_type = 2  # Opener
                device_name = f"Nuki Opener ({device_name_from_map})"
            else:
                device_type = 0  # Lock
                device_name = f"Nuki Lock ({device_name_from_map})"
        else:
            device_type = 0  # Default to Lock
            device_name = f"Nuki Device {smartlock_id}"
        
        self.smartlocks[smartlock_id] = {
            "smartlockId": smartlock_id,
            "name": device_name,
            "type": device_type,
            "state": {
                "state": 1,
                "stateName": "unknown",
                "batteryCritical": False,
                "batteryCharging": False,
                "batteryCharge": 100,
                "timestamp": datetime.utcnow().isoformat()
            },
            "config": {},
            "firmwareVersion": "3.2.8",
            "hardwareVersion": "1.0",
            "serverState": 1,
            "adminPinState": 1,
            "virtualDevice": False,
            "dateCreated": datetime.utcnow().isoformat(),
            "dateUpdated": datetime.utcnow().isoformat()
        }
        logger.info(f"Created new smartlock {smartlock_id} ({device_name}) from MQTT discovery")
    
    def get_authorizations(self) -> List[Dict[str, Any]]:
        """Get all authorizations - convert keypad codes to authorization format"""
        with self.lock:
            # Convert keypad codes to authorization format for API compatibility
            auth_list = []
            
            # Add keypad codes as authorizations
            for smartlock_id, codes in self.keypad_codes.items():
                for code in codes:
                    # Generate globally unique IDs by combining smartlock_id and codeId
                    code_id = code.get("codeId", "unknown")
                    auth_id = f"{smartlock_id}_{code_id}"  # Unique string ID
                    unique_auth_id = smartlock_id * 100000 + int(code_id) if str(code_id).isdigit() else smartlock_id * 100000  # Unique numeric authId
                    
                    # Convert date format from "2025-07-22 01:22:21" to "2025-07-22T01:22:21.000Z"
                    def convert_date(date_str):
                        if not date_str or date_str == "0000-00-00 00:00:00":
                            return None
                        try:
                            # Parse the date and convert to ISO format with Z suffix
                            from datetime import datetime
                            dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                            return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                        except:
                            return None
                    
                    # Convert weekdays to bit representation - CORRECTED MAPPING
                    weekdays = code.get("allowedWeekdays", [])
                    weekday_bits = 0
                    if weekdays and len(weekdays) > 0:
                        # Corrected weekday mapping to match expected output
                        weekday_map = {"mon": 64, "tue": 32, "wed": 16, "thu": 8, "fri": 4, "sat": 2, "sun": 1}
                        weekday_bits = sum(weekday_map.get(day.lower(), 0) for day in weekdays)
                    
                    # Convert time to minutes - FIXED to return 0 for "00:00"
                    def convert_time_to_minutes(time_str):
                        if not time_str:
                            return 0
                        if time_str == "00:00":
                            return 0  # Return 0 instead of None for "00:00"
                        try:
                            hours, minutes = map(int, time_str.split(":"))
                            return hours * 60 + minutes
                        except:
                            return 0
                    
                    # Get the actual values from the code data - FIXED field mapping
                    allowed_from = code.get("allowedFrom")
                    allowed_until = code.get("allowedUntil") 
                    allowed_from_time = code.get("allowedFromTime")
                    allowed_until_time = code.get("allowedUntilTime")
                    date_created = code.get("dateCreated")
                    time_limited = code.get("timeLimited", 0)
                    
                    # Base authorization object with unique IDs
                    auth = {
                        "id": auth_id,  # Unique string ID: "smartlockId_codeId"
                        "smartlockId": smartlock_id,  # Use original smartlock ID from MQTT
                        "authId": unique_auth_id,  # Unique numeric authId
                        "code": code.get("code"),
                        "type": 13,  # Keypad type
                        "name": code.get("name", "Unknown"),
                        "enabled": bool(code.get("enabled", 1)),
                        "remoteAllowed": True,  # Set to true as in expected format
                        "lockCount": code.get("lockCount", 0),
                        "creationDate": convert_date(date_created)  # FIXED: Use correct field name
                    }
                    
                    # Only add time-related fields if timeLimited is 1
                    if time_limited == 1:
                        auth.update({
                            "allowedFromDate": convert_date(allowed_from),  # FIXED: Apply conversion
                            "allowedUntilDate": convert_date(allowed_until),  # FIXED: Apply conversion
                            "allowedWeekDays": weekday_bits,  # FIXED: Use corrected mapping
                            "allowedFromTime": convert_time_to_minutes(allowed_from_time),  # FIXED: Return 0 for "00:00"
                            "allowedUntilTime": convert_time_to_minutes(allowed_until_time),  # FIXED: Return 0 for "00:00"
                        })
                    
                    # Debug logging to see what we're converting
                    logger.info(f"Converting keypad code: {code}")
                    logger.info(f"Converted to auth: {auth}")
                    
                    auth_list.append(auth)
            
            # DO NOT add regular authorizations - only return keypad codes as authorizations
            # The regular authorizations (like "Büro - Alex Wohnung", "Nuki Keypad", etc.) 
            # should be filtered out as requested
            
            return auth_list
    
    def get_authorization(self, auth_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific authorization - check both regular auths and keypad codes"""
        with self.lock:
            # First check regular authorizations
            if auth_id in self.authorizations:
                return self.authorizations[auth_id]
            
            # Then check keypad codes using new unique ID format
            for smartlock_id, codes in self.keypad_codes.items():
                for code in codes:
                    code_id = code.get("codeId", "unknown")
                    # Check both old format (just codeId) and new format (smartlockId_codeId)
                    expected_new_id = f"{smartlock_id}_{code_id}"
                    if str(code_id) == auth_id or expected_new_id == auth_id:
                        # Convert keypad code to authorization format with unique IDs
                        auth = self._convert_keypad_to_auth_unique(code, smartlock_id)
                        # Register the ID mapping for future reference
                        numeric_id = code.get("codeId")
                        if numeric_id:
                            unique_auth_id = smartlock_id * 100000 + int(numeric_id) if str(numeric_id).isdigit() else smartlock_id * 100000
                            self.id_mapper.register_mapping(expected_new_id, unique_auth_id)
                        return auth
            
            return None
    
    def get_authorization_safe(self, auth_id: str) -> Optional[Dict[str, Any]]:
        """Safely get authorization with additional validation"""
        with self.lock:
            auth = self.get_authorization(auth_id)
            if auth:
                # Additional validation: ensure the auth_id matches what we expect
                if auth.get("id") == auth_id:
                    logger.info(f"Found authorization {auth_id}: {auth.get('name')} (smartlock: {auth.get('smartlockId')})")
                    return auth
                else:
                    logger.warning(f"ID mismatch for authorization {auth_id}: found {auth.get('id')}")
            
            logger.warning(f"Authorization {auth_id} not found")
            return None
    
    def validate_auth_for_deletion(self, auth: Dict[str, Any], expected_auth_id: str) -> bool:
        """Validate that this authorization is safe to delete"""
        auth_id = auth.get("id")
        auth_name = auth.get("name", "Unknown")
        smartlock_id = auth.get("smartlockId")
        
        # Basic validation
        if auth_id != expected_auth_id:
            logger.error(f"ID validation failed: expected {expected_auth_id}, got {auth_id}")
            return False
        
        # Log what we're about to delete for verification
        logger.info(f"Validating deletion of authorization: ID={auth_id}, Name='{auth_name}', Smartlock={smartlock_id}")
        
        return True
    
    def _convert_keypad_to_auth(self, code: Dict[str, Any], smartlock_id: int) -> Dict[str, Any]:
        """Convert keypad code to authorization format (legacy method)"""
        code_id = code.get("codeId", "unknown")
        auth_id = str(code_id)
        
        # Convert date format from "2025-07-22 01:22:21" to "2025-07-22T01:22:21.000Z"
        def convert_date(date_str):
            if not date_str or date_str == "0000-00-00 00:00:00":
                return None
            try:
                from datetime import datetime
                dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            except:
                return None
        
        # Convert weekdays to bit representation
        weekdays = code.get("allowedWeekdays", [])
        weekday_bits = 0
        if weekdays and len(weekdays) > 0:
            weekday_map = {"mon": 64, "tue": 32, "wed": 16, "thu": 8, "fri": 4, "sat": 2, "sun": 1}
            weekday_bits = sum(weekday_map.get(day.lower(), 0) for day in weekdays)
        
        # Convert time to minutes
        def convert_time_to_minutes(time_str):
            if not time_str:
                return 0
            if time_str == "00:00":
                return 0
            try:
                hours, minutes = map(int, time_str.split(":"))
                return hours * 60 + minutes
            except:
                return 0
        
        # Get values
        allowed_from = code.get("allowedFrom")
        allowed_until = code.get("allowedUntil") 
        allowed_from_time = code.get("allowedFromTime")
        allowed_until_time = code.get("allowedUntilTime")
        date_created = code.get("dateCreated")
        time_limited = code.get("timeLimited", 0)
        
        # Base authorization object
        auth = {
            "id": auth_id,
            "smartlockId": smartlock_id,
            "authId": code.get("codeId"),
            "code": code.get("code"),
            "type": 13,  # Keypad type
            "name": code.get("name", "Unknown"),
            "enabled": bool(code.get("enabled", 1)),
            "remoteAllowed": True,
            "lockCount": code.get("lockCount", 0),
            "creationDate": convert_date(date_created)
        }
        
        # Only add time-related fields if timeLimited is 1
        if time_limited == 1:
            auth.update({
                "allowedFromDate": convert_date(allowed_from),
                "allowedUntilDate": convert_date(allowed_until),
                "allowedWeekDays": weekday_bits,
                "allowedFromTime": convert_time_to_minutes(allowed_from_time),
                "allowedUntilTime": convert_time_to_minutes(allowed_until_time),
            })
        
        return auth
    
    def _convert_keypad_to_auth_unique(self, code: Dict[str, Any], smartlock_id: int) -> Dict[str, Any]:
        """Convert keypad code to authorization format with unique IDs"""
        code_id = code.get("codeId", "unknown")
        auth_id = f"{smartlock_id}_{code_id}"  # Unique string ID
        unique_auth_id = smartlock_id * 100000 + int(code_id) if str(code_id).isdigit() else smartlock_id * 100000  # Unique numeric authId
        
        # Convert date format from "2025-07-22 01:22:21" to "2025-07-22T01:22:21.000Z"
        def convert_date(date_str):
            if not date_str or date_str == "0000-00-00 00:00:00":
                return None
            try:
                from datetime import datetime
                dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            except:
                return None
        
        # Convert weekdays to bit representation
        weekdays = code.get("allowedWeekdays", [])
        weekday_bits = 0
        if weekdays and len(weekdays) > 0:
            weekday_map = {"mon": 64, "tue": 32, "wed": 16, "thu": 8, "fri": 4, "sat": 2, "sun": 1}
            weekday_bits = sum(weekday_map.get(day.lower(), 0) for day in weekdays)
        
        # Convert time to minutes
        def convert_time_to_minutes(time_str):
            if not time_str:
                return 0
            if time_str == "00:00":
                return 0
            try:
                hours, minutes = map(int, time_str.split(":"))
                return hours * 60 + minutes
            except:
                return 0
        
        # Get values
        allowed_from = code.get("allowedFrom")
        allowed_until = code.get("allowedUntil") 
        allowed_from_time = code.get("allowedFromTime")
        allowed_until_time = code.get("allowedUntilTime")
        date_created = code.get("dateCreated")
        time_limited = code.get("timeLimited", 0)
        
        # Base authorization object with unique IDs
        auth = {
            "id": auth_id,  # Unique string ID: "smartlockId_codeId"
            "smartlockId": smartlock_id,
            "authId": unique_auth_id,  # Unique numeric authId
            "code": code.get("code"),
            "type": 13,  # Keypad type
            "name": code.get("name", "Unknown"),
            "enabled": bool(code.get("enabled", 1)),
            "remoteAllowed": True,
            "lockCount": code.get("lockCount", 0),
            "creationDate": convert_date(date_created)
        }
        
        # Only add time-related fields if timeLimited is 1
        if time_limited == 1:
            auth.update({
                "allowedFromDate": convert_date(allowed_from),
                "allowedUntilDate": convert_date(allowed_until),
                "allowedWeekDays": weekday_bits,
                "allowedFromTime": convert_time_to_minutes(allowed_from_time),
                "allowedUntilTime": convert_time_to_minutes(allowed_until_time),
            })
        
        return auth
    
    def add_authorization(self, auth_data: Dict[str, Any]) -> str:
        """Add a new authorization"""
        with self.lock:
            auth_id = str(uuid.uuid4())
            auth_data["id"] = auth_id
            auth_data["dateCreated"] = datetime.utcnow().isoformat()
            auth_data["dateUpdated"] = datetime.utcnow().isoformat()
            auth_data["lockCount"] = 0
            self.authorizations[auth_id] = auth_data
            return auth_id
    
    def update_authorization(self, auth_id: str, updates: Dict[str, Any]):
        """Update an authorization"""
        with self.lock:
            if auth_id in self.authorizations:
                self.authorizations[auth_id].update(updates)
                self.authorizations[auth_id]["dateUpdated"] = datetime.utcnow().isoformat()
    
    def delete_authorization(self, auth_id: str):
        """Delete an authorization"""
        with self.lock:
            if auth_id in self.authorizations:
                del self.authorizations[auth_id]
    
    def get_keypad_codes(self, smartlock_id: int) -> List[Dict[str, Any]]:
        """Get keypad codes for a smartlock"""
        with self.lock:
            return self.keypad_codes.get(smartlock_id, [])
    
    def add_keypad_code(self, smartlock_id: int, code_data: Dict[str, Any]) -> int:
        """Add a keypad code"""
        with self.lock:
            if smartlock_id not in self.keypad_codes:
                self.keypad_codes[smartlock_id] = []
            
            # Generate new code ID
            existing_codes = self.keypad_codes[smartlock_id]
            max_id = max([code.get("codeId", 0) for code in existing_codes], default=0)
            new_code_id = max_id + 1
            
            code_data["codeId"] = new_code_id
            code_data["dateCreated"] = datetime.utcnow().isoformat()
            self.keypad_codes[smartlock_id].append(code_data)
            return new_code_id
    
    def update_keypad_code(self, smartlock_id: int, code_id: int, updates: Dict[str, Any]):
        """Update a keypad code"""
        with self.lock:
            codes = self.keypad_codes.get(smartlock_id, [])
            for code in codes:
                if code.get("codeId") == code_id:
                    code.update(updates)
                    code["dateUpdated"] = datetime.utcnow().isoformat()
                    break
    
    def delete_keypad_code(self, smartlock_id: int, code_id: int):
        """Delete a keypad code"""
        with self.lock:
            codes = self.keypad_codes.get(smartlock_id, [])
            # Find the code to delete and log it
            code_to_delete = None
            for code in codes:
                if code.get("codeId") == code_id:
                    code_to_delete = code
                    break
            
            if code_to_delete:
                logger.info(f"Deleting keypad code: ID={code_id}, Name='{code_to_delete.get('name', 'Unknown')}', Smartlock={smartlock_id}")
                # Remove the ID mapping
                string_id = str(code_id)
                self.id_mapper.remove_mapping(string_id)
            else:
                logger.warning(f"Keypad code {code_id} not found for smartlock {smartlock_id}")
            
            # Remove the code from the list
            self.keypad_codes[smartlock_id] = [code for code in codes if code.get("codeId") != code_id]
    
    def get_timecontrol_entries(self, smartlock_id: int) -> List[Dict[str, Any]]:
        """Get timecontrol entries for a smartlock"""
        with self.lock:
            return self.timecontrol_entries.get(smartlock_id, [])
    
    def add_timecontrol_entry(self, smartlock_id: int, entry_data: Dict[str, Any]) -> int:
        """Add a timecontrol entry"""
        with self.lock:
            if smartlock_id not in self.timecontrol_entries:
                self.timecontrol_entries[smartlock_id] = []
            
            # Generate new entry ID
            existing_entries = self.timecontrol_entries[smartlock_id]
            max_id = max([entry.get("entryId", 0) for entry in existing_entries], default=0)
            new_entry_id = max_id + 1
            
            entry_data["entryId"] = new_entry_id
            entry_data["dateCreated"] = datetime.utcnow().isoformat()
            self.timecontrol_entries[smartlock_id].append(entry_data)
            return new_entry_id
    
    def update_timecontrol_entry(self, smartlock_id: int, entry_id: int, updates: Dict[str, Any]):
        """Update a timecontrol entry"""
        with self.lock:
            entries = self.timecontrol_entries.get(smartlock_id, [])
            for entry in entries:
                if entry.get("entryId") == entry_id:
                    entry.update(updates)
                    entry["dateUpdated"] = datetime.utcnow().isoformat()
                    break
    
    def delete_timecontrol_entry(self, smartlock_id: int, entry_id: int):
        """Delete a timecontrol entry"""
        with self.lock:
            entries = self.timecontrol_entries.get(smartlock_id, [])
            self.timecontrol_entries[smartlock_id] = [entry for entry in entries if entry.get("entryId") != entry_id]
    
    def _generate_content_hash(self, log_entry: Dict[str, Any]) -> str:
        """Generate a content-based hash for duplicate detection (same as LogManager)"""
        # Use key fields that make a log entry unique
        smartlock_id = log_entry.get('smartlockId', '')
        action = log_entry.get('action', '')
        trigger = log_entry.get('trigger', '')
        date = log_entry.get('date', '')
        name = log_entry.get('name', '')
        auth_id = log_entry.get('authId', '')
        source = log_entry.get('source', '')
        
        # Create a unique content string
        content_string = f"{smartlock_id}_{action}_{trigger}_{date}_{name}_{auth_id}_{source}"
        
        # Generate MD5 hash
        return hashlib.md5(content_string.encode('utf-8')).hexdigest()
    
    def _is_duplicate_log(self, new_log: Dict[str, Any], existing_logs: List[Dict[str, Any]]) -> bool:
        """Check if a log entry is a duplicate based on content (same as LogManager)"""
        new_hash = self._generate_content_hash(new_log)
        
        for existing_log in existing_logs:
            existing_hash = self._generate_content_hash(existing_log)
            if new_hash == existing_hash:
                logger.debug(f"Duplicate log detected in memory: {new_log.get('action', 'unknown')} at {new_log.get('date', 'unknown')}")
                return True
        
        return False

    def add_log_entry(self, log_data: Dict[str, Any], log_manager=None):
        """Add a log entry with duplicate detection"""
        with self.lock:
            # Convert to Nuki Web API format
            converted_log = self._convert_mqtt_log_to_api_format(log_data)
            
            # Check for duplicates in memory before adding
            if self._is_duplicate_log(converted_log, self.logs):
                logger.info(f"Skipping duplicate log entry in memory: {converted_log.get('action', 'unknown')} at {converted_log.get('date', 'unknown')}")
                return
            
            # Add to memory
            self.logs.append(converted_log)
            
            # Also save to persistent storage if log_manager is provided
            if log_manager:
                smartlock_id = converted_log.get("smartlockId")
                if smartlock_id:
                    log_manager.add_log_entry(smartlock_id, converted_log)
            
            # Keep only last 1000 log entries in memory
            if len(self.logs) > 1000:
                self.logs = self.logs[-1000:]
    
    def _convert_mqtt_log_to_api_format(self, mqtt_log: Dict[str, Any]) -> Dict[str, Any]:
        """Convert MQTT log format to Nuki Web API format"""
        import uuid
        from datetime import datetime
        
        # Generate unique ID (similar to MongoDB ObjectID format)
        log_id = str(uuid.uuid4()).replace('-', '')[:24]
        
        # Action mapping: MQTT string -> Nuki API number
        action_mapping = {
            "unlock": 1,
            "lock": 2,
            "unlatch": 3,
            "lockNgo": 4,
            "lockNgoUnlatch": 5,
            "fullLock": 6,
            "activateRTO": 1,
            "deactivateRTO": 2,
            "electricStrikeActuation": 3,
            "activateCM": 1,
            "deactivateCM": 2
        }
        
        # Trigger mapping: MQTT string -> Nuki API number
        trigger_mapping = {
            "fingerprint": 255,
            "keypad": 255,
            "code": 255,  # Keypad code entry
            "arrowkey": 255,  # Keypad arrow key
            "autoLock": 6,
            "autolock": 6,
            "button": 2,
            "manual": 1,
            "app": 0,
            "auto": 6,
            "system": 0
        }
        
        # Source mapping based on trigger type
        source_mapping = {
            "fingerprint": 2,  # Biometric
            "keypad": 2,       # Keypad
            "code": 2,         # Keypad code
            "arrowkey": 2,     # Keypad arrow key
            "autoLock": 0,     # System
            "autolock": 0,     # System
            "button": 0,       # Physical button
            "manual": 0,       # Manual
            "app": 1,          # App
            "auto": 0,         # Automatic
            "system": 0        # System
        }
        
        # Extract values from MQTT log - FIXED to use correct field names
        smartlock_id = mqtt_log.get("smartlockId", 1001)
        action_str = str(mqtt_log.get("action", "")).lower()
        trigger_str = str(mqtt_log.get("trigger", "")).lower()
        
        # FIXED: Use authorizationId and authorizationName from MQTT log
        auth_id = mqtt_log.get("authorizationId") or mqtt_log.get("authId")
        name = mqtt_log.get("authorizationName") or mqtt_log.get("name", "")
        
        # For keypad actions, also check codeId
        code_id = mqtt_log.get("codeId")
        
        # Resolve user name intelligently - prioritize authorizationName from MQTT
        if name and name.strip():
            resolved_name = name.strip()
            logger.info(f"Using authorizationName from MQTT: {resolved_name}")
        else:
            resolved_name = self._resolve_user_name(smartlock_id, auth_id or code_id, trigger_str, name)
        
        # Convert action
        action_num = action_mapping.get(action_str, 1)
        
        # Convert trigger
        trigger_num = trigger_mapping.get(trigger_str, 0)
        
        # Determine source
        source = source_mapping.get(trigger_str, 0)
        
        # Create date from individual time fields or use timestamp
        if all(key in mqtt_log for key in ["timeYear", "timeMonth", "timeDay", "timeHour", "timeMinute", "timeSecond"]):
            # Build date from individual fields
            try:
                dt = datetime(
                    year=mqtt_log["timeYear"],
                    month=mqtt_log["timeMonth"],
                    day=mqtt_log["timeDay"],
                    hour=mqtt_log["timeHour"],
                    minute=mqtt_log["timeMinute"],
                    second=mqtt_log["timeSecond"]
                )
                date_str = dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            except (ValueError, TypeError):
                date_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        else:
            # Use current timestamp
            date_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # Build the API format log entry
        api_log = {
            "id": log_id,
            "smartlockId": smartlock_id,
            "deviceType": 5,  # Always 5 for locks
            "name": resolved_name,
            "action": action_num,
            "trigger": trigger_num,
            "state": mqtt_log.get("state", 0),
            "autoUnlock": mqtt_log.get("autoUnlock", False),
            "date": date_str,
            "source": source
        }
        
        # Add authId if present (convert to string if needed)
        final_auth_id = auth_id or code_id
        if final_auth_id is not None:
            if isinstance(final_auth_id, (int, float)):
                # Convert numeric authId to string format similar to MongoDB ObjectID
                auth_id_str = f"{int(final_auth_id):024x}"[:24]  # Convert to hex and pad to 24 chars
            else:
                auth_id_str = str(final_auth_id)
            api_log["authId"] = auth_id_str
        
        logger.info(f"Converted MQTT log to API format: {resolved_name} (authId: {final_auth_id})")
        
        return api_log
    
    def _resolve_user_name(self, smartlock_id: int, auth_id: Any, trigger: str, original_name: str) -> str:
        """Intelligently resolve user name based on available information"""
        
        # If we already have a non-empty name, use it
        if original_name and original_name.strip():
            return original_name.strip()
        
        # Try to resolve based on auth_id and trigger type
        resolved_name = None
        
        # 1. First check if we have recent MQTT authorization data
        if auth_id is not None:
            auth_id_str = str(auth_id)
            # Check the authorization ID to name mapping from MQTT
            if auth_id_str in self.authorization_id_to_name:
                resolved_name = self.authorization_id_to_name[auth_id_str]
                logger.info(f"Resolved name from MQTT auth mapping: {resolved_name}")
            
            # Also check if this matches the last authorization for this smartlock
            elif (smartlock_id in self.last_authorization_id and 
                  self.last_authorization_id[smartlock_id] == auth_id_str and
                  smartlock_id in self.last_authorization_name):
                resolved_name = self.last_authorization_name[smartlock_id]
                logger.info(f"Resolved name from last MQTT auth: {resolved_name}")
        
        # 2. Try to find user by auth_id in keypad codes
        if not resolved_name and auth_id is not None:
            try:
                auth_id_str = str(auth_id)
                # Check keypad codes for this smartlock
                keypad_codes = self.keypad_codes.get(smartlock_id, [])
                for code in keypad_codes:
                    if str(code.get("codeId", "")) == auth_id_str:
                        code_name = code.get("name", "").strip()
                        if code_name:
                            resolved_name = code_name
                            logger.info(f"Resolved name from keypad codes: {resolved_name}")
                            break
                
                # If not found in keypad codes, check account users
                if not resolved_name:
                    for user in self.account_users.values():
                        # Try to match by some identifier (this is a simplified approach)
                        if str(user.get("id", "")) == auth_id_str:
                            user_name = user.get("name", "").strip()
                            if user_name:
                                resolved_name = user_name
                                logger.info(f"Resolved name from account users: {resolved_name}")
                                break
            except (ValueError, TypeError):
                pass
        
        # 3. If still no name found, use trigger-based fallbacks
        if not resolved_name:
            trigger_names = {
                "keypad": "Keypad-Benutzer",
                "fingerprint": "Fingerabdruck-Benutzer", 
                "app": "App-Benutzer",
                "manual": "Manuell",
                "button": "Taste",
                "autolock": "Automatisch",
                "auto": "Automatisch",
                "system": "System"
            }
            resolved_name = trigger_names.get(trigger.lower(), "Unbekannter Benutzer")
        
        # 4. Final fallback
        if not resolved_name:
            resolved_name = "System"
        
        return resolved_name
    
    def get_logs(self, smartlock_id: Optional[int] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get log entries"""
        with self.lock:
            logs = self.logs
            if smartlock_id is not None:
                logs = [log for log in logs if log.get("smartlockId") == smartlock_id]
            
            # Sort by timestamp descending and limit
            logs = sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)
            return logs[:limit]
    
    def get_account_users(self) -> List[Dict[str, Any]]:
        """Get all account users"""
        with self.lock:
            return list(self.account_users.values())
    
    def get_account_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific account user"""
        with self.lock:
            return self.account_users.get(user_id)
    
    def add_account_user(self, user_data: Dict[str, Any]) -> int:
        """Add an account user"""
        with self.lock:
            # Generate new user ID
            max_id = max(self.account_users.keys(), default=0)
            new_user_id = max_id + 1
            
            user_data["id"] = new_user_id
            user_data["dateCreated"] = datetime.utcnow().isoformat()
            user_data["dateUpdated"] = datetime.utcnow().isoformat()
            self.account_users[new_user_id] = user_data
            return new_user_id
    
    def update_account_user(self, user_id: int, updates: Dict[str, Any]):
        """Update an account user"""
        with self.lock:
            if user_id in self.account_users:
                self.account_users[user_id].update(updates)
                self.account_users[user_id]["dateUpdated"] = datetime.utcnow().isoformat()
    
    def delete_account_user(self, user_id: int):
        """Delete an account user"""
        with self.lock:
            if user_id in self.account_users:
                del self.account_users[user_id]


class MQTTClient:
    def __init__(self):
        self.client = mqtt.Client()
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect
        
        # MQTT Configuration
        self.mqtt_host = os.getenv("MQTT_HOST", "localhost")
        self.mqtt_port = int(os.getenv("MQTT_PORT", "1883"))
        self.mqtt_username = os.getenv("MQTT_USERNAME")
        self.mqtt_password = os.getenv("MQTT_PASSWORD")
        
        # Dynamic topic discovery - no fixed prefix
        self.discovered_topics = set()
        self.smartlock_topic_map = {}  # smartlock_id -> topic_prefix
        self.device_name_map = {}  # smartlock_id -> device_name
        
        # Authorization tracking for better user name resolution
        self.last_authorization_id = {}  # smartlock_id -> last authId
        self.last_authorization_name = {}  # smartlock_id -> last auth name
        self.authorization_id_to_name = {}  # authId -> name mapping
        
        # Track our own published messages to avoid processing them
        self.published_messages = set()  # Track message hashes to avoid self-processing
        
        # Connection state
        self.connected = False
        self.reconnect_delay = 5
        
        # Data store
        self.data_store = MQTTDataStore()
        
        # Log manager for persistent storage
        log_storage_path = os.getenv("LOG_STORAGE_PATH", "/data-emulator/logs")
        max_logs_per_smartlock = int(os.getenv("MAX_LOGS_PER_SMARTLOCK", "500"))
        self.log_manager = LogManager(log_storage_path, max_logs_per_smartlock)
        
        # Setup authentication if provided
        if self.mqtt_username and self.mqtt_password:
            self.client.username_pw_set(self.mqtt_username, self.mqtt_password)
    
    def connect(self):
        """Connect to MQTT broker"""
        try:
            logger.info(f"Connecting to MQTT broker at {self.mqtt_host}:{self.mqtt_port}")
            self.client.connect(self.mqtt_host, self.mqtt_port, 60)
            self.client.loop_start()
        except Exception as e:
            logger.error(f"Failed to connect to MQTT broker: {e}")
            # Start reconnection thread
            threading.Thread(target=self.reconnect_loop, daemon=True).start()
    
    def reconnect_loop(self):
        """Reconnection loop for handling connection failures"""
        while not self.connected:
            try:
                time.sleep(self.reconnect_delay)
                logger.info("Attempting to reconnect to MQTT broker...")
                self.client.connect(self.mqtt_host, self.mqtt_port, 60)
                self.client.loop_start()
                break
            except Exception as e:
                logger.error(f"Reconnection failed: {e}")
                self.reconnect_delay = min(self.reconnect_delay * 2, 60)  # Exponential backoff, max 60s
    
    def on_connect(self, client, userdata, flags, rc):
        """Callback for when the client receives a CONNACK response from the server"""
        if rc == 0:
            logger.info("Connected to MQTT broker successfully")
            self.connected = True
            self.reconnect_delay = 5  # Reset reconnect delay
            
            # Subscribe to all relevant topics
            self.subscribe_to_topics()
            
            # Publish initial state for all smartlocks
            self.publish_initial_states()
        else:
            logger.error(f"Failed to connect to MQTT broker, return code {rc}")
            self.connected = False
    
    def on_disconnect(self, client, userdata, rc):
        """Callback for when the client disconnects from the server"""
        logger.warning(f"Disconnected from MQTT broker, return code {rc}")
        self.connected = False
        if rc != 0:
            # Unexpected disconnection, start reconnection
            threading.Thread(target=self.reconnect_loop, daemon=True).start()
    
    def subscribe_to_topics(self):
        """Subscribe to wildcard topics to discover all Nuki devices dynamically"""
        # Subscribe to broad patterns to catch all possible Nuki topics
        wildcard_topics = [
            "+/+/action",
            "+/+/state",
            "+/+/json",
            "+/+/keypad/+",
            "+/+/timecontrol/+",
            "+/+/authorization/+",
            "+/+/configuration/+",
            "+/+/battery/+",
            "+/+/query/+",
            "+/+/authorizationId",
            "+/+/authorizationName",
            "+/+/trigger",
            "+/+/log",
            "+/+/shortLog",
            "+/+/rollingLog",
            "#"  # Subscribe to everything to discover topics
        ]
        
        for topic in wildcard_topics:
            self.client.subscribe(topic)
            logger.info(f"Subscribed to wildcard topic: {topic}")
    
    def publish_initial_states(self):
        """Publish initial states for all smartlocks"""
        # Skip initial publishing since we're discovering topics dynamically
        # The emulator will respond to incoming MQTT messages instead
        logger.info("Skipping initial state publishing - waiting for dynamic topic discovery")
    
    def _generate_message_hash(self, topic: str, payload: str) -> str:
        """Generate a hash for a message to track our own publications"""
        import hashlib
        message_content = f"{topic}:{payload}"
        return hashlib.md5(message_content.encode('utf-8')).hexdigest()
    
    def on_message(self, client, userdata, msg):
        """Callback for when a PUBLISH message is received from the server"""
        try:
            topic = msg.topic
            payload = msg.payload.decode('utf-8')
            
            # Check if this is our own published message
            message_hash = self._generate_message_hash(topic, payload)
            if message_hash in self.published_messages:
                logger.debug(f"Ignoring our own published message on topic {topic}")
                self.published_messages.discard(message_hash)  # Remove to prevent memory leak
                return
            
            logger.info(f"Received message on topic {topic}: {payload}")
            
            # Parse topic to extract device and action type
            topic_parts = topic.split('/')
            if len(topic_parts) < 3:
                logger.warning(f"Invalid topic format: {topic}")
                return
            
            topic_prefix = topic_parts[0]  # e.g., "nukihub"
            device_name = topic_parts[1]  # e.g., "lock", "opener"
            action_type = topic_parts[2]  # e.g., "action", "keypad", "json"
            
            # Get smartlock ID from device name with topic prefix
            smartlock_id = self.get_smartlock_id_from_name(device_name, topic_prefix)
            if not smartlock_id:
                logger.warning(f"Unknown device name: {device_name} with prefix: {topic_prefix}")
                return
            
            # Store topic prefix for this smartlock
            self.smartlock_topic_map[smartlock_id] = topic_prefix
            
            # Handle different message types
            if action_type == "json":
                self.handle_json_state_update(smartlock_id, payload)
            elif action_type == "state":
                self.handle_state_update(smartlock_id, payload)
            elif action_type == "action":
                self.handle_lock_action(smartlock_id, payload)
            elif action_type == "keypad":
                if len(topic_parts) > 3:
                    if topic_parts[3] == "actionJson":
                        self.handle_keypad_action(smartlock_id, payload)
                    elif topic_parts[3] == "json":
                        self.handle_keypad_codes_update(smartlock_id, payload)
            elif action_type == "timecontrol":
                if len(topic_parts) > 3:
                    if topic_parts[3] == "actionJson":
                        self.handle_timecontrol_action(smartlock_id, payload)
                    elif topic_parts[3] == "json":
                        self.handle_timecontrol_update(smartlock_id, payload)
            elif action_type == "authorization":
                if len(topic_parts) > 3:
                    if topic_parts[3] == "actionJson":
                        self.handle_authorization_action(smartlock_id, payload)
                    elif topic_parts[3] == "json":
                        self.handle_authorization_update(smartlock_id, payload)
            elif action_type == "configuration":
                if len(topic_parts) > 3 and topic_parts[3] == "basicJson":
                    self.handle_configuration_update(smartlock_id, payload)
            elif action_type == "battery":
                if len(topic_parts) > 3 and topic_parts[3] == "basicJson":
                    self.handle_battery_update(smartlock_id, payload)
            elif action_type == "log":
                self.handle_log_update(smartlock_id, payload)
            elif action_type == "query":
                if len(topic_parts) > 3:
                    self.handle_query_action(smartlock_id, topic_parts[3], payload)
            elif action_type == "authorizationId":
                self.handle_authorization_id_update(smartlock_id, payload)
            elif action_type == "authorizationName":
                self.handle_authorization_name_update(smartlock_id, payload)
            elif action_type == "trigger":
                self.handle_trigger_update(smartlock_id, payload)
                
        except Exception as e:
            logger.error(f"Error processing MQTT message: {e}")
    
    def generate_smartlock_id(self, topic_prefix: str, device_name: str) -> int:
        """Generate unique smartlock ID based on MQTT topic structure"""
        # Create unique key from topic structure
        topic_key = f"{topic_prefix}_{device_name}"
        
        # Generate hash-based ID in range 1000-9999
        import hashlib
        hash_value = int(hashlib.md5(topic_key.encode()).hexdigest()[:8], 16)
        smartlock_id = 1000 + (hash_value % 9000)
        
        logger.info(f"Generated smartlock ID {smartlock_id} for topic key: {topic_key}")
        return smartlock_id
    
    def get_smartlock_id_from_name(self, name: str, topic_prefix: str) -> Optional[int]:
        """Map device name to smartlock ID - supports ANY topic prefix and device name"""
        
        # Only ignore opener devices explicitly (any device with "opener" in name)
        if "opener" in name.lower():
            logger.info(f"Ignoring opener device: {name}")
            return None
        
        # Create unique topic key for this prefix/device combination
        topic_key = f"{topic_prefix}_{name}"
        
        # Check if we already have a mapping for this exact prefix/device combination
        existing_mapping = None
        for smartlock_id, stored_topic_key in self.device_name_map.items():
            if stored_topic_key == topic_key:
                existing_mapping = smartlock_id
                break
        
        if existing_mapping:
            logger.info(f"Using existing mapping: {topic_prefix}/{name} -> {existing_mapping}")
            return existing_mapping
        
        # Generate new ID for this device
        smartlock_id = self.generate_smartlock_id(topic_prefix, name)
        
        # Store the mappings
        self.smartlock_topic_map[smartlock_id] = topic_prefix
        self.device_name_map[smartlock_id] = topic_key  # Store full topic key
        
        logger.info(f"Created new smartlock mapping: {topic_prefix}/{name} -> ID {smartlock_id}")
        return smartlock_id
    
    def get_device_name_from_id(self, smartlock_id: int) -> Optional[str]:
        """Map smartlock ID to device name for MQTT topics"""
        # First check if we have a stored mapping
        if smartlock_id in self.device_name_map:
            topic_key = self.device_name_map[smartlock_id]
            # Extract device name from topic_key (format: "prefix_device")
            if "_" in topic_key:
                return topic_key.split("_", 1)[1]  # Return device part
            return topic_key
        
        # Fallback to hardcoded mappings for legacy IDs
        id_to_name = {
            1001: "lock",
            1002: "opener"
        }
        return id_to_name.get(smartlock_id)
    
    def handle_lock_action(self, smartlock_id: int, payload: str):
        """Handle lock/unlock actions"""
        try:
            # Parse action (could be JSON or simple string)
            auth_id = None
            trigger = "manual"
            name = ""
            
            try:
                action_data = json.loads(payload)
                action = action_data.get("action", payload)
                # Extract additional information if available
                auth_id = action_data.get("authId")
                trigger = action_data.get("trigger", "manual")
                name = action_data.get("name", "")
            except json.JSONDecodeError:
                action = payload.strip()
            
            # Map action to state
            action_mapping = {
                "lock": {"state": 1, "stateName": "locked"},
                "unlock": {"state": 3, "stateName": "unlocked"},
                "unlatch": {"state": 5, "stateName": "unlatched"},
                "lockNgo": {"state": 1, "stateName": "locked"},
                "lockNgoUnlatch": {"state": 5, "stateName": "unlatched"},
                "fullLock": {"state": 1, "stateName": "locked"},
                "activateRTO": {"state": 3, "stateName": "RTOactive"},
                "deactivateRTO": {"state": 1, "stateName": "locked"},
                "electricStrikeActuation": {"state": 5, "stateName": "open"},
                "activateCM": {"state": 3, "stateName": "unlocked"},
                "deactivateCM": {"state": 1, "stateName": "locked"}
            }
            
            new_state = action_mapping.get(str(action).lower())
            if not new_state:
                logger.warning(f"Unknown action: {action}")
                return
            
            # Update smartlock state in data store
            self.data_store.update_smartlock_state(smartlock_id, new_state, self)
            
            # Create log entry with better user information
            log_entry = {
                "smartlockId": smartlock_id,
                "action": str(action),
                "trigger": trigger,
                "state": new_state["state"],
                "stateName": new_state["stateName"],
                "completionStatus": 1,  # Success
                "name": name,  # Will be resolved by _resolve_user_name
                "authId": auth_id
            }
            self.data_store.add_log_entry(log_entry, self.log_manager)
            
            logger.info(f"Updated smartlock {smartlock_id} state to {new_state['stateName']}")
            
            # Publish state update
            self.publish_state_update(smartlock_id)
            
        except Exception as e:
            logger.error(f"Error handling lock action: {e}")
    
    def handle_keypad_action(self, smartlock_id: int, payload: str):
        """Handle keypad code management actions"""
        try:
            action_data = json.loads(payload)
            action = action_data.get("action")
            
            if action == "add":
                self.data_store.add_keypad_code(smartlock_id, action_data)
                logger.info(f"Added keypad code for smartlock {smartlock_id}")
            elif action == "update":
                code_id = action_data.get("codeId")
                if code_id:
                    self.data_store.update_keypad_code(smartlock_id, code_id, action_data)
                    logger.info(f"Updated keypad code {code_id} for smartlock {smartlock_id}")
            elif action == "delete":
                code_id = action_data.get("codeId")
                if code_id:
                    # Delete from data store
                    self.data_store.delete_keypad_code(smartlock_id, code_id)
                    logger.info(f"Deleted keypad code {code_id} for smartlock {smartlock_id} from data store")
                    
                    # Also remove from MQTT retained messages by publishing empty message
                    device_name = self.get_device_name_from_id(smartlock_id)
                    if device_name:
                        topic_prefix = self.smartlock_topic_map.get(smartlock_id, "nukihub")
                        # Clear individual keypad code topics if they exist
                        for i in range(10):  # Clear up to 10 possible keypad codes
                            code_topic = f"{topic_prefix}/{device_name}/keypad/code_{i}"
                            self.client.publish(code_topic, "", retain=True)
            elif action == "check":
                # Simulate keypad code check
                code = str(action_data.get("code", ""))
                codes = self.data_store.get_keypad_codes(smartlock_id)
                valid_code = any(c.get("code") == code and c.get("enabled") for c in codes)
                if valid_code:
                    self.handle_lock_action(smartlock_id, "unlock")
            
            # Publish updated keypad codes (this will reflect the deletion)
            self.publish_keypad_codes(smartlock_id)
            self.publish_command_result(smartlock_id, "success")
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in keypad action: {e}")
            self.publish_command_result(smartlock_id, "invalidJson")
        except Exception as e:
            logger.error(f"Error in keypad action: {e}")
            self.publish_command_result(smartlock_id, "failed")
    
    def handle_timecontrol_action(self, smartlock_id: int, payload: str):
        """Handle timecontrol entry management"""
        try:
            action_data = json.loads(payload)
            action = action_data.get("action")
            
            if action == "add":
                self.data_store.add_timecontrol_entry(smartlock_id, action_data)
            elif action == "update":
                entry_id = action_data.get("entryId")
                if entry_id:
                    self.data_store.update_timecontrol_entry(smartlock_id, entry_id, action_data)
            elif action == "delete":
                entry_id = action_data.get("entryId")
                if entry_id:
                    self.data_store.delete_timecontrol_entry(smartlock_id, entry_id)
            
            # Publish updated timecontrol entries
            self.publish_timecontrol_entries(smartlock_id)
            self.publish_command_result(smartlock_id, "success")
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in timecontrol action: {e}")
            self.publish_command_result(smartlock_id, "invalidJson")
        except Exception as e:
            logger.error(f"Error in timecontrol action: {e}")
            self.publish_command_result(smartlock_id, "failed")
    
    def handle_authorization_action(self, smartlock_id: int, payload: str):
        """Handle authorization management"""
        try:
            action_data = json.loads(payload)
            action = action_data.get("action")
            
            if action == "add":
                # Create new authorization
                auth_data = {
                    "smartlockId": smartlock_id,
                    "name": action_data.get("name", "Unknown"),
                    "type": action_data.get("type", 0),
                    "enabled": bool(action_data.get("enabled", 1)),
                    "remoteAllowed": bool(action_data.get("remoteAllowed", 1)),
                    "code": action_data.get("code"),
                    "accountUserId": action_data.get("accountUserId"),
                    "allowedFromDate": action_data.get("allowedFrom"),
                    "allowedUntilDate": action_data.get("allowedUntil"),
                    "allowedWeekDays": action_data.get("allowedWeekdays"),
                    "allowedFromTime": action_data.get("allowedFromTime"),
                    "allowedUntilTime": action_data.get("allowedUntilTime"),
                    "fingerprints": {}
                }
                auth_id = self.data_store.add_authorization(auth_data)
                logger.info(f"Created authorization {auth_id} for smartlock {smartlock_id}")
                
            elif action == "update":
                # Find authorization by authId (numeric) or by name
                auth_id = action_data.get("authId")
                target_auth = None
                
                if auth_id:
                    # Find by numeric authId
                    for aid, auth in self.data_store.authorizations.items():
                        if auth.get("smartlockId") == smartlock_id and hash(aid) % 1000000 == auth_id:
                            target_auth = aid
                            break
                
                if target_auth:
                    update_data = {}
                    if "name" in action_data:
                        update_data["name"] = action_data["name"]
                    if "enabled" in action_data:
                        update_data["enabled"] = bool(action_data["enabled"])
                    if "remoteAllowed" in action_data:
                        update_data["remoteAllowed"] = bool(action_data["remoteAllowed"])
                    if "allowedFrom" in action_data:
                        update_data["allowedFromDate"] = action_data["allowedFrom"]
                    if "allowedUntil" in action_data:
                        update_data["allowedUntilDate"] = action_data["allowedUntil"]
                    if "allowedWeekdays" in action_data:
                        update_data["allowedWeekDays"] = action_data["allowedWeekdays"]
                    if "allowedFromTime" in action_data:
                        update_data["allowedFromTime"] = action_data["allowedFromTime"]
                    if "allowedUntilTime" in action_data:
                        update_data["allowedUntilTime"] = action_data["allowedUntilTime"]
                    
                    self.data_store.update_authorization(target_auth, update_data)
                    logger.info(f"Updated authorization {target_auth} for smartlock {smartlock_id}")
                
            elif action == "delete":
                # Find and delete authorization
                auth_id = action_data.get("authId")
                target_auth = None
                
                if auth_id:
                    # Find by numeric authId
                    for aid, auth in self.data_store.authorizations.items():
                        if auth.get("smartlockId") == smartlock_id and hash(aid) % 1000000 == auth_id:
                            target_auth = aid
                            break
                
                if target_auth:
                    self.data_store.delete_authorization(target_auth)
                    logger.info(f"Deleted authorization {target_auth} for smartlock {smartlock_id}")
            
            # Publish updated authorizations
            self.publish_authorizations(smartlock_id)
            self.publish_command_result(smartlock_id, "success")
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in authorization action: {e}")
            self.publish_command_result(smartlock_id, "invalidJson")
        except Exception as e:
            logger.error(f"Error in authorization action: {e}")
            self.publish_command_result(smartlock_id, "failed")
    
    def handle_json_state_update(self, smartlock_id: int, payload: str):
        """Handle JSON state updates from MQTT"""
        try:
            state_data = json.loads(payload)
            logger.info(f"Updating smartlock {smartlock_id} state from JSON: {state_data}")
            
            # Update the smartlock state with real data
            self.data_store.update_smartlock_state(smartlock_id, state_data, self)
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in state update: {e}")
        except Exception as e:
            logger.error(f"Error handling JSON state update: {e}")
    
    def handle_state_update(self, smartlock_id: int, payload: str):
        """Handle simple state updates from MQTT"""
        try:
            state_name = payload.strip()
            logger.info(f"Updating smartlock {smartlock_id} state to: {state_name}")
            
            # Map state names to state numbers
            state_mapping = {
                "locked": {"state": 1, "stateName": "locked"},
                "unlocked": {"state": 3, "stateName": "unlocked"},
                "unlatched": {"state": 5, "stateName": "unlatched"},
                "online": {"state": 1, "stateName": "online"},
                "RTOactive": {"state": 3, "stateName": "RTOactive"}
            }
            
            state_update = state_mapping.get(state_name, {"stateName": state_name})
            self.data_store.update_smartlock_state(smartlock_id, state_update)
            
        except Exception as e:
            logger.error(f"Error handling state update: {e}")
    
    def handle_keypad_codes_update(self, smartlock_id: int, payload: str):
        """Handle keypad codes updates from MQTT"""
        try:
            codes_data = json.loads(payload)
            logger.info(f"Updating keypad codes for smartlock {smartlock_id}")
            
            # Replace all keypad codes with the new data
            with self.data_store.lock:
                self.data_store.keypad_codes[smartlock_id] = codes_data
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in keypad codes update: {e}")
        except Exception as e:
            logger.error(f"Error handling keypad codes update: {e}")
    
    def handle_timecontrol_update(self, smartlock_id: int, payload: str):
        """Handle timecontrol entries updates from MQTT"""
        try:
            entries_data = json.loads(payload)
            logger.info(f"Updating timecontrol entries for smartlock {smartlock_id}")
            
            # Replace all timecontrol entries with the new data
            with self.data_store.lock:
                self.data_store.timecontrol_entries[smartlock_id] = entries_data
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in timecontrol update: {e}")
        except Exception as e:
            logger.error(f"Error handling timecontrol update: {e}")
    
    def handle_authorization_update(self, smartlock_id: int, payload: str):
        """Handle authorization updates from MQTT"""
        try:
            auths_data = json.loads(payload)
            logger.info(f"Updating authorizations for smartlock {smartlock_id}")
            
            # Update authorizations for this smartlock
            with self.data_store.lock:
                # Remove existing authorizations for this smartlock
                self.data_store.authorizations = {
                    auth_id: auth for auth_id, auth in self.data_store.authorizations.items()
                    if auth.get("smartlockId") != smartlock_id
                }
                
                # Add new authorizations
                for auth in auths_data:
                    auth_id = auth.get("id", str(uuid.uuid4()))
                    auth["id"] = auth_id
                    auth["smartlockId"] = smartlock_id
                    self.data_store.authorizations[auth_id] = auth
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in authorization update: {e}")
        except Exception as e:
            logger.error(f"Error handling authorization update: {e}")
    
    def handle_configuration_update(self, smartlock_id: int, payload: str):
        """Handle configuration updates from MQTT"""
        try:
            config_data = json.loads(payload)
            logger.info(f"Updating configuration for smartlock {smartlock_id}")
            
            # Update smartlock configuration and name
            with self.data_store.lock:
                if smartlock_id in self.data_store.smartlocks:
                    self.data_store.smartlocks[smartlock_id]["config"] = config_data
                    if "name" in config_data:
                        self.data_store.smartlocks[smartlock_id]["name"] = config_data["name"]
                    self.data_store.smartlocks[smartlock_id]["dateUpdated"] = datetime.utcnow().isoformat()
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in configuration update: {e}")
        except Exception as e:
            logger.error(f"Error handling configuration update: {e}")
    
    def handle_battery_update(self, smartlock_id: int, payload: str):
        """Handle battery updates from MQTT"""
        try:
            battery_data = json.loads(payload)
            logger.info(f"Updating battery info for smartlock {smartlock_id}")
            
            # Update battery information in smartlock state
            battery_update = {}
            if "critical" in battery_data:
                battery_update["batteryCritical"] = bool(int(battery_data["critical"]))
            if "charging" in battery_data:
                battery_update["batteryCharging"] = bool(int(battery_data["charging"]))
            if "level" in battery_data:
                battery_update["batteryCharge"] = int(battery_data["level"])
            if "keypadCritical" in battery_data:
                battery_update["keypadBatteryCritical"] = bool(int(battery_data["keypadCritical"]))
            if "doorSensorCritical" in battery_data:
                battery_update["doorsensorBatteryCritical"] = bool(int(battery_data["doorSensorCritical"]))
            
            if battery_update:
                self.data_store.update_smartlock_state(smartlock_id, battery_update)
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in battery update: {e}")
        except Exception as e:
            logger.error(f"Error handling battery update: {e}")
    
    def handle_log_update(self, smartlock_id: int, payload: str):
        """Handle log updates from MQTT"""
        try:
            log_data = json.loads(payload)
            logger.info(f"Received log data for smartlock {smartlock_id}")
            
            # If it's a list of logs, add them all
            if isinstance(log_data, list):
                for log_entry in log_data:
                    log_entry["smartlockId"] = smartlock_id
                    self.data_store.add_log_entry(log_entry, self.log_manager)
            else:
                # Single log entry
                log_data["smartlockId"] = smartlock_id
                self.data_store.add_log_entry(log_data, self.log_manager)
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in log update: {e}")
        except Exception as e:
            logger.error(f"Error handling log update: {e}")
    
    def handle_query_action(self, smartlock_id: int, query_type: str, payload: str):
        """Handle query actions"""
        try:
            if payload == "1":  # Query triggered
                device_name = self.get_device_name_from_id(smartlock_id)
                if not device_name:
                    return
                
                # Get topic prefix from discovered topics or use default
                topic_prefix = self.smartlock_topic_map.get(smartlock_id, "nukihub")
                
                if query_type == "lockstate":
                    self.publish_state_update(smartlock_id)
                elif query_type == "keypad":
                    self.publish_keypad_codes(smartlock_id)
                elif query_type == "config":
                    # Publish configuration (placeholder)
                    config_topic = f"{topic_prefix}/{device_name}/configuration/basicJson"
                    config = {"name": self.data_store.get_smartlock(smartlock_id).get("name", "Unknown")}
                    self.client.publish(config_topic, json.dumps(config), retain=True)
                elif query_type == "battery":
                    # Publish battery info
                    battery_topic = f"{topic_prefix}/{device_name}/battery/basicJson"
                    smartlock = self.data_store.get_smartlock(smartlock_id)
                    if smartlock:
                        battery_info = {
                            "critical": smartlock["state"].get("batteryCritical", False),
                            "charging": smartlock["state"].get("batteryCharging", False),
                            "level": smartlock["state"].get("batteryCharge", 100)
                        }
                        self.client.publish(battery_topic, json.dumps(battery_info), retain=True)
                
        except Exception as e:
            logger.error(f"Error handling query action: {e}")
    
    def publish_state_update(self, smartlock_id: int):
        """Publish smartlock state update to MQTT"""
        if not self.connected:
            return
        
        device_name = self.get_device_name_from_id(smartlock_id)
        if not device_name:
            return
        
        # Get topic prefix from discovered topics or use default
        topic_prefix = self.smartlock_topic_map.get(smartlock_id, "nukihub")
        
        smartlock = self.data_store.get_smartlock(smartlock_id)
        if smartlock:
            # Publish JSON state
            json_topic = f"{topic_prefix}/{device_name}/json"
            self.client.publish(json_topic, json.dumps(smartlock["state"]), retain=True)
            
            # Publish simple state
            state_topic = f"{topic_prefix}/{device_name}/state"
            self.client.publish(state_topic, smartlock["state"].get("stateName", "unknown"), retain=True)
            
            logger.info(f"Published state update for smartlock {smartlock_id}")
    
    def publish_keypad_codes(self, smartlock_id: int):
        """Publish keypad codes to MQTT"""
        if not self.connected:
            return
        
        device_name = self.get_device_name_from_id(smartlock_id)
        if not device_name:
            return
        
        # Get topic prefix from discovered topics or use default
        topic_prefix = self.smartlock_topic_map.get(smartlock_id, "nukihub")
        
        keypad_codes = self.data_store.get_keypad_codes(smartlock_id)
        topic = f"{topic_prefix}/{device_name}/keypad/json"
        self.client.publish(topic, json.dumps(keypad_codes), retain=True)
        logger.info(f"Published keypad codes for smartlock {smartlock_id}")
    
    def publish_timecontrol_entries(self, smartlock_id: int):
        """Publish timecontrol entries to MQTT"""
        if not self.connected:
            return
        
        device_name = self.get_device_name_from_id(smartlock_id)
        if not device_name:
            return
        
        # Get topic prefix from discovered topics or use default
        topic_prefix = self.smartlock_topic_map.get(smartlock_id, "nukihub")
        
        entries = self.data_store.get_timecontrol_entries(smartlock_id)
        topic = f"{topic_prefix}/{device_name}/timecontrol/json"
        self.client.publish(topic, json.dumps(entries), retain=True)
        logger.info(f"Published timecontrol entries for smartlock {smartlock_id}")
    
    def publish_authorizations(self, smartlock_id: int):
        """Publish authorizations to MQTT"""
        if not self.connected:
            return
        
        device_name = self.get_device_name_from_id(smartlock_id)
        if not device_name:
            return
        
        # Get topic prefix from discovered topics or use default
        topic_prefix = self.smartlock_topic_map.get(smartlock_id, "nukihub")
        
        auths = [auth for auth in self.data_store.get_authorizations() if auth["smartlockId"] == smartlock_id]
        topic = f"{topic_prefix}/{device_name}/authorization/json"
        self.client.publish(topic, json.dumps(auths), retain=True)
        logger.info(f"Published authorizations for smartlock {smartlock_id}")
    
    def publish_command_result(self, smartlock_id: int, result: str):
        """Publish command result to MQTT"""
        if not self.connected:
            return
        
        device_name = self.get_device_name_from_id(smartlock_id)
        if not device_name:
            return
        
        # Get topic prefix from discovered topics or use default
        topic_prefix = self.smartlock_topic_map.get(smartlock_id, "nukihub")
        
        topic = f"{topic_prefix}/{device_name}/configuration/commandResultJson"
        payload = json.dumps({"result": result, "timestamp": datetime.utcnow().isoformat()})
        
        self.client.publish(topic, payload)
        logger.info(f"Published command result to {topic}: {result}")
    
    def publish_action(self, smartlock_id: int, action: str):
        """Publish an action to MQTT (for API-triggered actions)"""
        if not self.connected:
            logger.warning("MQTT not connected, cannot publish action")
            # Still handle locally even if MQTT is not connected
            self.handle_lock_action(smartlock_id, action)
            return
        
        device_name = self.get_device_name_from_id(smartlock_id)
        if not device_name:
            logger.warning(f"Unknown smartlock ID: {smartlock_id}")
            return
        
        # Get topic prefix from discovered topics or use default
        topic_prefix = self.smartlock_topic_map.get(smartlock_id, "nukihub")
        
        topic = f"{topic_prefix}/{device_name}/action"
        self.client.publish(topic, action)
        logger.info(f"Published action to {topic}: {action}")
        
        # Also handle the action locally to update state
        self.handle_lock_action(smartlock_id, action)
    
    def publish_keypad_action(self, smartlock_id: int, action_data: dict):
        """Publish keypad action to MQTT"""
        if not self.connected:
            logger.warning("MQTT not connected, cannot publish keypad action")
            # Still handle locally
            self.handle_keypad_action(smartlock_id, json.dumps(action_data))
            return
        
        device_name = self.get_device_name_from_id(smartlock_id)
        if not device_name:
            logger.warning(f"Unknown smartlock ID: {smartlock_id}")
            return
        
        topic_prefix = self.smartlock_topic_map.get(smartlock_id, "nukihub")
        topic = f"{topic_prefix}/{device_name}/keypad/actionJson"
        
        payload = json.dumps(action_data)
        
        # Track this message to avoid processing our own publication
        message_hash = self._generate_message_hash(topic, payload)
        self.published_messages.add(message_hash)
        
        self.client.publish(topic, payload)
        logger.info(f"Published keypad action to {topic}: {payload}")
        
        # Handle locally ONLY - don't rely on MQTT echo
        self.handle_keypad_action(smartlock_id, payload)
    
    def publish_timecontrol_action(self, smartlock_id: int, action_data: dict):
        """Publish timecontrol action to MQTT"""
        if not self.connected:
            logger.warning("MQTT not connected, cannot publish timecontrol action")
            self.handle_timecontrol_action(smartlock_id, json.dumps(action_data))
            return
        
        device_name = self.get_device_name_from_id(smartlock_id)
        if not device_name:
            logger.warning(f"Unknown smartlock ID: {smartlock_id}")
            return
        
        topic_prefix = self.smartlock_topic_map.get(smartlock_id, "nukihub")
        topic = f"{topic_prefix}/{device_name}/timecontrol/actionJson"
        
        payload = json.dumps(action_data)
        self.client.publish(topic, payload)
        logger.info(f"Published timecontrol action to {topic}: {payload}")
        
        # Handle locally
        self.handle_timecontrol_action(smartlock_id, payload)
    
    def publish_authorization_action(self, smartlock_id: int, action_data: dict):
        """Publish authorization action to MQTT"""
        if not self.connected:
            logger.warning("MQTT not connected, cannot publish authorization action")
            self.handle_authorization_action(smartlock_id, json.dumps(action_data))
            return
        
        device_name = self.get_device_name_from_id(smartlock_id)
        if not device_name:
            logger.warning(f"Unknown smartlock ID: {smartlock_id}")
            return
        
        topic_prefix = self.smartlock_topic_map.get(smartlock_id, "nukihub")
        topic = f"{topic_prefix}/{device_name}/authorization/actionJson"
        
        payload = json.dumps(action_data)
        self.client.publish(topic, payload)
        logger.info(f"Published authorization action to {topic}: {payload}")
        
        # Handle locally
        self.handle_authorization_action(smartlock_id, payload)
    
    def publish_configuration_action(self, smartlock_id: int, config_data: dict):
        """Publish configuration action to MQTT"""
        if not self.connected:
            logger.warning("MQTT not connected, cannot publish configuration action")
            self.handle_configuration_update(smartlock_id, json.dumps(config_data))
            return
        
        device_name = self.get_device_name_from_id(smartlock_id)
        if not device_name:
            logger.warning(f"Unknown smartlock ID: {smartlock_id}")
            return
        
        topic_prefix = self.smartlock_topic_map.get(smartlock_id, "nukihub")
        topic = f"{topic_prefix}/{device_name}/configuration/action"
        
        payload = json.dumps(config_data)
        self.client.publish(topic, payload)
        logger.info(f"Published configuration action to {topic}: {payload}")
        
        # Handle locally
        self.handle_configuration_update(smartlock_id, payload)
    
    def handle_authorization_id_update(self, smartlock_id: int, payload: str):
        """Handle authorization ID updates from MQTT"""
        try:
            auth_id = payload.strip()
            if auth_id and auth_id != "0":
                self.last_authorization_id[smartlock_id] = auth_id
                logger.info(f"Updated last authorization ID for smartlock {smartlock_id}: {auth_id}")
        except Exception as e:
            logger.error(f"Error handling authorization ID update: {e}")
    
    def handle_authorization_name_update(self, smartlock_id: int, payload: str):
        """Handle authorization name updates from MQTT"""
        try:
            auth_name = payload.strip()
            if auth_name:
                self.last_authorization_name[smartlock_id] = auth_name
                # Also map the last auth ID to this name
                last_auth_id = self.last_authorization_id.get(smartlock_id)
                if last_auth_id:
                    self.authorization_id_to_name[last_auth_id] = auth_name
                logger.info(f"Updated last authorization name for smartlock {smartlock_id}: {auth_name}")
        except Exception as e:
            logger.error(f"Error handling authorization name update: {e}")
    
    def handle_trigger_update(self, smartlock_id: int, payload: str):
        """Handle trigger updates from MQTT"""
        try:
            trigger = payload.strip()
            logger.info(f"Received trigger update for smartlock {smartlock_id}: {trigger}")
            # Store trigger information for potential log creation
            # This could be used to create more accurate log entries
        except Exception as e:
            logger.error(f"Error handling trigger update: {e}")
    
    def query_data(self, smartlock_id: int, query_type: str):
        """Query data from MQTT device"""
        if not self.connected:
            logger.warning("MQTT not connected, cannot query data")
            return
        
        device_name = self.get_device_name_from_id(smartlock_id)
        if not device_name:
            logger.warning(f"Unknown smartlock ID: {smartlock_id}")
            return
        
        topic_prefix = self.smartlock_topic_map.get(smartlock_id, "nukihub")
        topic = f"{topic_prefix}/{device_name}/query/{query_type}"
        
        self.client.publish(topic, "1")
        logger.info(f"Published query to {topic}: 1")
        
        # Also handle locally to ensure we have data
        self.handle_query_action(smartlock_id, query_type, "1")
    
    def disconnect(self):
        """Disconnect from MQTT broker"""
        if self.connected:
            self.client.loop_stop()
            self.client.disconnect()
            self.connected = False
            logger.info("Disconnected from MQTT broker")

# Global MQTT client instance
mqtt_client = MQTTClient()
