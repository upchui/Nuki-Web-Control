import os
import json
import logging
import asyncio
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class LogManager:
    """Manages persistent log storage for MQTT emulator"""
    
    def __init__(self, storage_path: str = "/data-emulator/logs", max_logs_per_smartlock: int = 500):
        self.storage_path = Path(storage_path)
        self.max_logs_per_smartlock = max_logs_per_smartlock
        
        # Create storage directory if it doesn't exist
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"LogManager initialized with storage path: {self.storage_path}")
        logger.info(f"Max logs per smartlock: {self.max_logs_per_smartlock}")
    
    def get_log_file_path(self, smartlock_id: int) -> Path:
        """Get the log file path for a specific smartlock"""
        return self.storage_path / f"smartlock_{smartlock_id}_logs.json"
    
    def _generate_content_hash(self, log_entry: Dict[str, Any]) -> str:
        """Generate a content-based hash for duplicate detection"""
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
        """Check if a log entry is a duplicate based on content"""
        new_hash = self._generate_content_hash(new_log)
        
        for existing_log in existing_logs:
            existing_hash = self._generate_content_hash(existing_log)
            if new_hash == existing_hash:
                logger.debug(f"Duplicate log detected: {new_log.get('action', 'unknown')} at {new_log.get('date', 'unknown')}")
                return True
        
        return False
    
    def load_logs_from_disk(self, smartlock_id: int) -> List[Dict[str, Any]]:
        """Load logs for a specific smartlock from disk"""
        log_file = self.get_log_file_path(smartlock_id)
        
        if not log_file.exists():
            logger.debug(f"Log file does not exist for smartlock {smartlock_id}: {log_file}")
            return []
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                logs = data.get('logs', [])
                logger.debug(f"Loaded {len(logs)} logs for smartlock {smartlock_id}")
                return logs
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            logger.error(f"Error loading logs for smartlock {smartlock_id}: {e}")
            return []
    
    def save_logs_to_disk(self, smartlock_id: int, logs: List[Dict[str, Any]]):
        """Save logs for a specific smartlock to disk"""
        log_file = self.get_log_file_path(smartlock_id)
        
        # Rotate logs if necessary
        if len(logs) > self.max_logs_per_smartlock:
            # Keep only the most recent logs (sorted by date descending)
            logs = sorted(logs, key=lambda x: x.get('date', ''), reverse=True)
            logs = logs[:self.max_logs_per_smartlock]
            logger.info(f"Rotated logs for smartlock {smartlock_id}, kept {len(logs)} most recent entries")
        
        data = {
            'smartlock_id': smartlock_id,
            'logs': logs,
            'last_updated': datetime.utcnow().isoformat() + 'Z',
            'total_count': len(logs)
        }
        
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.debug(f"Saved {len(logs)} logs for smartlock {smartlock_id} to {log_file}")
        except Exception as e:
            logger.error(f"Error saving logs for smartlock {smartlock_id}: {e}")
    
    def add_log_entry(self, smartlock_id: int, log_entry: Dict[str, Any]):
        """Add a single log entry and save to disk (with duplicate detection)"""
        # Load existing logs
        logs = self.load_logs_from_disk(smartlock_id)
        
        # Check for duplicates
        if self._is_duplicate_log(log_entry, logs):
            logger.info(f"Skipping duplicate log entry for smartlock {smartlock_id}: {log_entry.get('action', 'unknown')} at {log_entry.get('date', 'unknown')}")
            return
        
        # Add new log entry at the beginning (most recent first)
        logs.insert(0, log_entry)
        
        # Save back to disk (with automatic rotation)
        self.save_logs_to_disk(smartlock_id, logs)
        
        logger.debug(f"Added log entry for smartlock {smartlock_id}: {log_entry.get('action', 'unknown')}")
    
    def get_logs(self, smartlock_id: Optional[int] = None, limit: int = 10000) -> List[Dict[str, Any]]:
        """Get logs from disk with optional filtering"""
        # Apply reasonable upper limit to prevent memory issues
        effective_limit = min(limit, 50000) if limit > 0 else 50000
        
        if smartlock_id is not None:
            # Get logs for specific smartlock
            logs = self.load_logs_from_disk(smartlock_id)
            # Sort by date descending and limit
            logs = sorted(logs, key=lambda x: x.get('date', ''), reverse=True)
            return logs[:effective_limit]
        else:
            # Get logs from all smartlocks
            all_logs = []
            
            # Find all log files
            for log_file in self.storage_path.glob("smartlock_*_logs.json"):
                try:
                    # Extract smartlock_id from filename
                    filename = log_file.stem  # e.g., "smartlock_1001_logs"
                    parts = filename.split('_')
                    if len(parts) >= 2:
                        sl_id = int(parts[1])
                        logs = self.load_logs_from_disk(sl_id)
                        all_logs.extend(logs)
                except (ValueError, IndexError) as e:
                    logger.warning(f"Could not parse smartlock ID from filename {log_file}: {e}")
            
            # Sort all logs by date descending and limit
            all_logs = sorted(all_logs, key=lambda x: x.get('date', ''), reverse=True)
            return all_logs[:effective_limit]
    
    def get_all_smartlock_ids(self) -> List[int]:
        """Get all smartlock IDs that have log files"""
        smartlock_ids = []
        
        for log_file in self.storage_path.glob("smartlock_*_logs.json"):
            try:
                # Extract smartlock_id from filename
                filename = log_file.stem  # e.g., "smartlock_1001_logs"
                parts = filename.split('_')
                if len(parts) >= 2:
                    smartlock_id = int(parts[1])
                    smartlock_ids.append(smartlock_id)
            except (ValueError, IndexError) as e:
                logger.warning(f"Could not parse smartlock ID from filename {log_file}: {e}")
        
        return sorted(smartlock_ids)
    
    def cleanup_old_logs(self):
        """Cleanup old logs across all smartlocks"""
        smartlock_ids = self.get_all_smartlock_ids()
        
        for smartlock_id in smartlock_ids:
            logs = self.load_logs_from_disk(smartlock_id)
            if len(logs) > self.max_logs_per_smartlock:
                logger.info(f"Cleaning up old logs for smartlock {smartlock_id}: {len(logs)} -> {self.max_logs_per_smartlock}")
                self.save_logs_to_disk(smartlock_id, logs)
    
    def enforce_log_limits_on_startup(self):
        """Enforce log limits on all existing log files during startup"""
        smartlock_ids = self.get_all_smartlock_ids()
        total_cleaned = 0
        
        logger.info(f"Enforcing log limits on startup (max: {self.max_logs_per_smartlock} per smartlock)")
        
        for smartlock_id in smartlock_ids:
            logs = self.load_logs_from_disk(smartlock_id)
            original_count = len(logs)
            
            if original_count > self.max_logs_per_smartlock:
                # Sort by date descending and keep only the most recent logs
                logs = sorted(logs, key=lambda x: x.get('date', ''), reverse=True)
                logs = logs[:self.max_logs_per_smartlock]
                
                # Save the truncated logs back to disk
                self.save_logs_to_disk(smartlock_id, logs)
                
                cleaned_count = original_count - len(logs)
                total_cleaned += cleaned_count
                
                logger.info(f"Enforced limit for smartlock {smartlock_id}: {original_count} -> {len(logs)} logs (removed {cleaned_count})")
            else:
                logger.debug(f"Smartlock {smartlock_id}: {original_count} logs (within limit)")
        
        if total_cleaned > 0:
            logger.info(f"Startup log limit enforcement completed: {total_cleaned} old logs removed across all smartlocks")
        else:
            logger.info("Startup log limit enforcement completed: all log files already within limits")
        
        return total_cleaned
    
    def remove_duplicate_logs(self, smartlock_id: Optional[int] = None):
        """Remove duplicate logs from existing log files"""
        smartlock_ids = [smartlock_id] if smartlock_id else self.get_all_smartlock_ids()
        
        total_removed = 0
        
        for sl_id in smartlock_ids:
            logs = self.load_logs_from_disk(sl_id)
            if not logs:
                continue
            
            # Remove duplicates while preserving order
            unique_logs = []
            seen_hashes = set()
            
            for log in logs:
                content_hash = self._generate_content_hash(log)
                if content_hash not in seen_hashes:
                    unique_logs.append(log)
                    seen_hashes.add(content_hash)
                else:
                    total_removed += 1
                    logger.debug(f"Removing duplicate log: {log.get('action', 'unknown')} at {log.get('date', 'unknown')}")
            
            if len(unique_logs) < len(logs):
                logger.info(f"Removed {len(logs) - len(unique_logs)} duplicate logs for smartlock {sl_id}")
                self.save_logs_to_disk(sl_id, unique_logs)
        
        if total_removed > 0:
            logger.info(f"Duplicate cleanup completed: {total_removed} duplicate logs removed")
        else:
            logger.info("Duplicate cleanup completed: no duplicates found")
        
        return total_removed
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored logs"""
        stats = {
            'total_smartlocks': 0,
            'total_logs': 0,
            'smartlock_stats': {}
        }
        
        smartlock_ids = self.get_all_smartlock_ids()
        stats['total_smartlocks'] = len(smartlock_ids)
        
        for smartlock_id in smartlock_ids:
            logs = self.load_logs_from_disk(smartlock_id)
            log_count = len(logs)
            stats['total_logs'] += log_count
            
            # Get oldest and newest log dates
            oldest_date = None
            newest_date = None
            if logs:
                sorted_logs = sorted(logs, key=lambda x: x.get('date', ''))
                oldest_date = sorted_logs[0].get('date') if sorted_logs else None
                newest_date = sorted_logs[-1].get('date') if sorted_logs else None
            
            stats['smartlock_stats'][smartlock_id] = {
                'log_count': log_count,
                'oldest_log': oldest_date,
                'newest_log': newest_date
            }
        
        return stats


class LogCollector:
    """Collects logs automatically from MQTT and stores them persistently"""
    
    def __init__(self, mqtt_client, log_manager: LogManager, collection_interval: int = 60):
        self.mqtt_client = mqtt_client
        self.log_manager = log_manager
        self.collection_interval = collection_interval
        self.running = False
        self.task = None
        
        logger.info(f"LogCollector initialized with {collection_interval}s interval")
    
    async def start(self):
        """Start the log collection background task"""
        if self.running:
            logger.warning("LogCollector is already running")
            return
        
        self.running = True
        self.task = asyncio.create_task(self._collection_loop())
        logger.info("LogCollector started")
    
    async def stop(self):
        """Stop the log collection background task"""
        if not self.running:
            return
        
        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        
        logger.info("LogCollector stopped")
    
    async def _collection_loop(self):
        """Main collection loop that runs every interval"""
        logger.info(f"Starting log collection loop with {self.collection_interval}s interval")
        
        while self.running:
            try:
                await self._collect_and_store_logs()
                await asyncio.sleep(self.collection_interval)
            except asyncio.CancelledError:
                logger.info("Log collection loop cancelled")
                break
            except Exception as e:
                logger.error(f"Error in log collection loop: {e}")
                # Continue running even if there's an error
                await asyncio.sleep(self.collection_interval)
    
    async def _collect_and_store_logs(self):
        """Collect logs from MQTT data store and save to disk (with duplicate detection)"""
        try:
            # Get all smartlocks from MQTT data store
            smartlocks = self.mqtt_client.data_store.get_smartlocks()
            
            if not smartlocks:
                logger.debug("No smartlocks found in MQTT data store")
                return
            
            total_new_logs = 0
            total_duplicates_skipped = 0
            
            for smartlock in smartlocks:
                smartlock_id = smartlock.get('smartlockId')
                if not smartlock_id:
                    continue
                
                # Get logs from MQTT data store (in-memory)
                mqtt_logs = self.mqtt_client.data_store.get_logs(smartlock_id=smartlock_id, limit=10000)
                
                if not mqtt_logs:
                    continue
                
                # Load existing logs from disk
                existing_logs = self.log_manager.load_logs_from_disk(smartlock_id)
                
                # Find new logs using both ID-based and content-based filtering
                existing_log_ids = {log.get('id') for log in existing_logs if log.get('id')}
                
                # First filter: exclude logs with existing IDs
                id_filtered_logs = [log for log in mqtt_logs if log.get('id') not in existing_log_ids]
                
                # Second filter: exclude content duplicates
                truly_new_logs = []
                for log in id_filtered_logs:
                    if not self.log_manager._is_duplicate_log(log, existing_logs):
                        truly_new_logs.append(log)
                    else:
                        total_duplicates_skipped += 1
                
                if truly_new_logs:
                    # Merge new logs with existing logs
                    all_logs = truly_new_logs + existing_logs
                    
                    # Save to disk (with automatic rotation)
                    self.log_manager.save_logs_to_disk(smartlock_id, all_logs)
                    
                    total_new_logs += len(truly_new_logs)
                    logger.info(f"Collected {len(truly_new_logs)} new logs for smartlock {smartlock_id}")
                    
                    if len(id_filtered_logs) > len(truly_new_logs):
                        duplicates_for_smartlock = len(id_filtered_logs) - len(truly_new_logs)
                        logger.info(f"Skipped {duplicates_for_smartlock} duplicate logs for smartlock {smartlock_id}")
            
            if total_new_logs > 0:
                logger.info(f"Log collection completed: {total_new_logs} new logs collected, {total_duplicates_skipped} duplicates skipped")
            else:
                if total_duplicates_skipped > 0:
                    logger.info(f"Log collection completed: no new logs found, {total_duplicates_skipped} duplicates skipped")
                else:
                    logger.debug("Log collection completed: no new logs found")
                
        except Exception as e:
            logger.error(f"Error during log collection: {e}")
    
    def force_collection(self):
        """Force an immediate log collection (non-async)"""
        if self.running:
            # Create a new task for immediate collection
            asyncio.create_task(self._collect_and_store_logs())
            logger.info("Forced log collection triggered")
