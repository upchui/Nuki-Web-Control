document.addEventListener('DOMContentLoaded', () => {
    // Check authentication first
    checkAuthentication();
    
    // UI Elements
    const smartlocksContainer = document.getElementById('smartlocks-container');
    const authsContainer = document.getElementById('auths-container');
    const syncAllButton = document.getElementById('sync-all-button');
    const blockingOverlay = document.getElementById('blocking-overlay');
    const logoutButton = document.getElementById('logout-button');
    const usernameDisplay = document.getElementById('username-display');

    // Admin UI Elements
    const usersContainer = document.getElementById('users-container');
    const addUserButton = document.getElementById('add-user-button');
    const userModal = document.getElementById('user-modal');
    const userForm = document.getElementById('user-form');
    const userModalTitle = document.getElementById('user-modal-title');
    const permissionsModal = document.getElementById('permissions-modal');
    const permissionsForm = document.getElementById('permissions-form');
    const permissionsModalTitle = document.getElementById('permissions-modal-title');

    // Logs UI Elements
    const logsContainer = document.getElementById('logs-container');
    const logsCount = document.getElementById('logs-count');
    const smartlockFilter = document.getElementById('smartlock-filter');
    const logTypeFilter = document.getElementById('log-type-filter');
    const dateFilter = document.getElementById('date-filter');
    const refreshLogsButton = document.getElementById('refresh-logs-button');
    const clearFiltersButton = document.getElementById('clear-filters-button');

    // Smartlock Filter UI Elements
    const smartlockNameFilter = document.getElementById('smartlock-name-filter');
    const smartlockStateFilter = document.getElementById('smartlock-state-filter');
    const clearSmartlockFiltersButton = document.getElementById('clear-smartlock-filters-button');

    // Authorization Filter UI Elements
    const authNameFilter = document.getElementById('auth-name-filter');
    const authCodeFilter = document.getElementById('auth-code-filter');
    const authSmartlockFilterSelect = document.getElementById('auth-smartlock-filter');
    const authStatusFilter = document.getElementById('auth-status-filter');
    const clearAuthFiltersButton = document.getElementById('clear-auth-filters-button');

    // Modal UI Elements
    const authModal = document.getElementById('auth-modal');
    const authForm = document.getElementById('auth-form');
    const authModalTitle = document.getElementById('auth-modal-title');
    const addAuthButton = document.getElementById('add-auth-button');

    // Form fields
    const authIdInput = document.getElementById('auth-id');
    const originalSmartlockIdsInput = document.getElementById('original-smartlock-ids');
    const originalPinCodeInput = document.getElementById('original-pin-code');
    const authNameInput = document.getElementById('auth-name');
    const authSmartlockSelect = document.getElementById('auth-smartlock-select');
    const authTypeSelect = document.getElementById('auth-type-select');
    const pinContainer = document.getElementById('pin-container');
    const pinInputs = document.querySelectorAll('.pin-input');
    const authEnabledCheckbox = document.getElementById('auth-enabled');
    const timeLimitToggle = document.getElementById('time-limit-toggle');
    const timeRestrictionPanel = document.getElementById('time-restriction-panel');
    //const fingerprintsSection = document.getElementById('fingerprints-section');
    //const fingerprintsList = document.getElementById('fingerprints-list');

    // Centralized State
    let allSmartlocks = [];
    let allSmartlocksForAuthEditing = []; // Includes read-only smartlocks for auth editing
    let allAuths = [];
    let allLogs = [];
    let filteredLogs = [];
    let filteredSmartlocks = [];
    let filteredAuths = [];
    let userPermissions = null;
    let currentUserInfo = null;

    // --- DATA FETCHING & STATE MANAGEMENT ---

    const refreshAllData = async () => {
        try {
            const fetchOptions = { cache: 'no-cache' };
            const [smartlocksRes, smartlocksForAuthRes, authsRes] = await Promise.all([
                fetch('/api/smartlocks', fetchOptions),
                fetch('/api/smartlocks/all', fetchOptions),
                fetch('/api/smartlock/auths', fetchOptions)
            ]);

            if (!smartlocksRes.ok || !smartlocksForAuthRes.ok || !authsRes.ok) {
                throw new Error('Failed to fetch data from the server.');
            }

            allSmartlocks = await smartlocksRes.json();
            allSmartlocksForAuthEditing = await smartlocksForAuthRes.json();
            allAuths = await authsRes.json();

            renderSmartlocks();
            renderAuths();

        } catch (error) {
            console.error("Error refreshing data:", error);
            smartlocksContainer.innerHTML = '<tr><td colspan="3">Error loading data. Please check the connection and API token.</td></tr>';
            authsContainer.innerHTML = '';
        }
    };

    // --- LOGS FUNCTIONALITY ---

    const fetchLogs = async () => {
        try {
            allLogs = [];
            
            // Show loading indicator
            logsContainer.innerHTML = '<tr><td colspan="5">Loading logs...</td></tr>';
            logsCount.textContent = 'Loading logs...';
            
            // Strategy 1: Try to fetch logs with different date ranges to get more historical data
            const dateRanges = [
                // Current period
                { fromDate: null, toDate: null, label: 'recent' },
                // Last 30 days
                { 
                    fromDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), 
                    toDate: new Date().toISOString(), 
                    label: 'last 30 days' 
                },
                // Last 90 days
                { 
                    fromDate: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(), 
                    toDate: new Date().toISOString(), 
                    label: 'last 90 days' 
                },
                // This year
                { 
                    fromDate: new Date('2025-01-01T00:00:00.000Z').toISOString(), 
                    toDate: new Date().toISOString(), 
                    label: 'this year' 
                },
                // Last year
                { 
                    fromDate: new Date('2024-01-01T00:00:00.000Z').toISOString(), 
                    toDate: new Date('2024-12-31T23:59:59.999Z').toISOString(), 
                    label: 'last year' 
                }
            ];

            // Try fetching from general endpoint with different date ranges
            for (const range of dateRanges) {
                try {
                    const params = new URLSearchParams({ limit: '10000' });
                    if (range.fromDate) params.append('fromDate', range.fromDate);
                    if (range.toDate) params.append('toDate', range.toDate);
                    
                    // Ensure authorization header is included
                    const token = localStorage.getItem('authToken');
                    const fetchOptions = { 
                        cache: 'no-cache',
                        headers: {}
                    };
                    if (token) {
                        fetchOptions.headers['Authorization'] = `Bearer ${token}`;
                    }
                    
                    const response = await fetch(`/api/smartlock/log?${params}`, fetchOptions);
                    if (response.ok) {
                        const logs = await response.json();
                        if (logs.length > 0) {
                            allLogs.push(...logs);
                            console.log(`Fetched ${logs.length} logs from general endpoint (${range.label})`);
                        }
                    }
                } catch (error) {
                    console.warn(`Failed to fetch logs for ${range.label}:`, error);
                }
            }

            // Strategy 2: Try individual smartlocks if we don't have enough logs
            if (allLogs.length < 50) {
                for (const smartlock of allSmartlocks) {
                    for (const range of dateRanges) {
                        try {
                            const params = new URLSearchParams({ limit: '50' });
                            if (range.fromDate) params.append('fromDate', range.fromDate);
                            if (range.toDate) params.append('toDate', range.toDate);
                            
                            const response = await fetch(`/api/smartlock/${smartlock.smartlockId}/log?${params}`, { cache: 'no-cache' });
                            if (response.ok) {
                                const logs = await response.json();
                                if (logs.length > 0) {
                                    allLogs.push(...logs);
                                    console.log(`Fetched ${logs.length} logs for smartlock ${smartlock.name} (${range.label})`);
                                }
                            }
                        } catch (error) {
                            console.warn(`Failed to fetch logs for smartlock ${smartlock.name} (${range.label}):`, error);
                        }
                    }
                }
            }

            // Strategy 3: Try pagination with different starting points
            if (allLogs.length > 0) {
                const oldestLog = allLogs.reduce((oldest, log) => 
                    new Date(log.date) < new Date(oldest.date) ? log : oldest
                );
                
                // Try to get logs older than the oldest one we have
                try {
                    const params = new URLSearchParams({ 
                        limit: '50',
                        id: oldestLog.id
                    });
                    const response = await fetch(`/api/smartlock/log?${params}`, { cache: 'no-cache' });
                    if (response.ok) {
                        const olderLogs = await response.json();
                        // Check if we got different logs
                        const newLogs = olderLogs.filter(log => !allLogs.some(existing => existing.id === log.id));
                        if (newLogs.length > 0) {
                            allLogs.push(...newLogs);
                            console.log(`Fetched ${newLogs.length} additional older logs via pagination`);
                        }
                    }
                } catch (error) {
                    console.warn('Failed to fetch older logs via pagination:', error);
                }
            }
            
            // Remove duplicates based on log ID
            const uniqueLogs = [];
            const seenIds = new Set();
            for (const log of allLogs) {
                if (!seenIds.has(log.id)) {
                    seenIds.add(log.id);
                    uniqueLogs.push(log);
                }
            }
            allLogs = uniqueLogs;
            
            console.log(`Total unique logs loaded: ${allLogs.length}`);
            
            // Sort logs by date (newest first)
            allLogs.sort((a, b) => new Date(b.date) - new Date(a.date));
            
            populateSmartlockFilter();
            applyFilters();
        } catch (error) {
            console.error("Error fetching logs:", error);
            logsContainer.innerHTML = '<tr><td colspan="5">Error loading logs. Please check the connection.</td></tr>';
            logsCount.textContent = 'Error loading logs';
        }
    };

    const populateSmartlockFilter = () => {
        smartlockFilter.innerHTML = '<option value="">All Smart Locks</option>';
        allSmartlocks.forEach(smartlock => {
            smartlockFilter.innerHTML += `<option value="${smartlock.smartlockId}">${smartlock.name}</option>`;
        });
    };

    const applyFilters = () => {
        const smartlockId = smartlockFilter.value;
        const logType = logTypeFilter.value;
        const selectedDate = dateFilter.value;

        filteredLogs = allLogs.filter(log => {
            if (smartlockId && log.smartlockId !== parseInt(smartlockId)) return false;
            if (logType && getLogTypeName(log.action) !== logType) return false;
            if (selectedDate) {
                const logDate = new Date(log.date).toISOString().split('T')[0];
                if (logDate !== selectedDate) return false;
            }
            return true;
        });

        renderLogs();
    };

    const getLogTypeName = (action) => {
        const actionMap = {
            1: 'unlock',
            2: 'lock', 
            3: 'unlatch',
            4: 'lock',
            5: 'unlatch',
            240: 'sync',
            241: 'sync',
            242: 'error',
            243: 'sync',
            252: 'sync',
            253: 'sync',
            254: 'sync',
            255: 'sync'
        };
        return actionMap[action] || 'other';
    };

    const getActionName = (action) => {
        const actionNames = {
            1: 'Unlock',
            2: 'Lock',
            3: 'Unlatch', 
            4: "Lock 'n' Go",
            5: "Lock 'n' Go with Unlatch",
            240: 'Door Opened',
            241: 'Door Closed',
            242: 'Door Sensor Jammed',
            243: 'Firmware Update',
            252: 'Initialization',
            253: 'Calibration',
            254: 'Log Enabled',
            255: 'Log Disabled'
        };
        return actionNames[action] || `Action ${action}`;
    };

    const renderLogs = () => {
        // Update log count display
        const totalLogs = allLogs.length;
        const filteredCount = filteredLogs.length;
        
        if (totalLogs === 0) {
            logsCount.textContent = 'No logs available';
        } else if (filteredCount === totalLogs) {
            logsCount.textContent = `Showing all ${totalLogs} logs`;
        } else {
            logsCount.textContent = `Showing ${filteredCount} of ${totalLogs} logs`;
        }

        logsContainer.innerHTML = '';
        if (filteredLogs.length === 0) {
            logsContainer.innerHTML = '<tr><td colspan="5">No logs found matching the current filters.</td></tr>';
            return;
        }

        const smartlockMap = new Map(allSmartlocks.map(smartlock => [smartlock.smartlockId, smartlock.name]));

        filteredLogs.sort((a, b) => new Date(b.date) - new Date(a.date));

        filteredLogs.forEach(log => {
            const row = document.createElement('tr');
            const timestamp = new Date(log.date).toLocaleString();
            const smartlockName = smartlockMap.get(log.smartlockId) || 'Unknown';
            const logType = getLogTypeName(log.action);
            const actionName = getActionName(log.action);
            
            row.innerHTML = `
                <td data-label="Timestamp">${timestamp}</td>
                <td data-label="Smart Lock">${smartlockName}</td>
                <td data-label="Type"><span class="log-type log-type-${logType}">${logType}</span></td>
                <td data-label="Message">${actionName}</td>
                <td data-label="User/Auth">${log.name || 'System'}</td>
            `;
            logsContainer.appendChild(row);
        });
    };

    const clearFilters = () => {
        smartlockFilter.value = '';
        logTypeFilter.value = '';
        dateFilter.value = '';
        applyFilters();
    };

    // --- SMARTLOCK FILTERING ---

    const applySmartlockFilters = () => {
        const nameFilter = smartlockNameFilter ? smartlockNameFilter.value.toLowerCase() : '';
        const stateFilter = smartlockStateFilter ? smartlockStateFilter.value : '';

        // Start with permission-filtered smartlocks
        let smartlocksToShow = allSmartlocks;
        if (currentUserInfo && !currentUserInfo.is_admin && userPermissions) {
            smartlocksToShow = allSmartlocks.filter(smartlock => 
                hasSmartlockPermission(smartlock.smartlockId)
            );
        }

        // Apply filters
        filteredSmartlocks = smartlocksToShow.filter(smartlock => {
            // Name filter
            if (nameFilter && !smartlock.name.toLowerCase().includes(nameFilter)) {
                return false;
            }

            // State filter
            if (stateFilter) {
                const currentState = getStateName(smartlock.state.state);
                if (currentState !== stateFilter) {
                    return false;
                }
            }

            return true;
        });

        renderFilteredSmartlocks();
    };

    const renderFilteredSmartlocks = () => {
        smartlocksContainer.innerHTML = '';
        
        filteredSmartlocks.forEach(smartlock => {
            const row = document.createElement('tr');
            row.dataset.smartlockId = smartlock.smartlockId;
            
            // Battery status
            const state = smartlock.state || {};
            let batteryHtml = '';
            if (state.batteryCharge !== undefined && state.batteryCharge !== null) {
                const batteryLevel = state.batteryCharge;
                const isCharging = state.batteryCharging || false;
                const isCritical = state.batteryCritical || false;
                
                let batteryClass = 'battery-good';
                if (isCritical || batteryLevel < 20) {
                    batteryClass = 'battery-critical';
                } else if (batteryLevel < 50) {
                    batteryClass = 'battery-low';
                }
                
                const chargingIcon = isCharging ? '⚡' : '';
                batteryHtml = `<span class="battery-status ${batteryClass}">${batteryLevel}% ${chargingIcon}</span>`;
            } else if (state.batteryCritical) {
                batteryHtml = '<span class="battery-status battery-critical">Critical</span>';
            } else {
                batteryHtml = '<span class="battery-status">Unknown</span>';
            }
            
            row.innerHTML = `
                <td data-label="Name">${smartlock.name}</td>
                <td data-label="State">${getStateName(smartlock.state.state)} <span class="sync-status"></span></td>
                <td data-label="Battery">${batteryHtml}</td>
                <td data-label="Actions" class="actions">
                    <button>Lock</button>
                    <button>Unlatch</button>
                    <button>Sync</button>
                </td>
            `;
            const buttons = row.querySelectorAll('button');
            buttons[0].onclick = () => lock(smartlock.smartlockId);
            buttons[1].onclick = () => unlatch(smartlock.smartlockId);
            buttons[2].onclick = () => syncSmartlock(smartlock.smartlockId);
            smartlocksContainer.appendChild(row);
        });
        
        // Hide Sync All button if no smartlocks are visible
        if (syncAllButton) {
            syncAllButton.style.display = filteredSmartlocks.length > 0 ? 'block' : 'none';
        }

        // Show filter info
        if (filteredSmartlocks.length === 0) {
            smartlocksContainer.innerHTML = '<tr><td colspan="4">No smartlocks found matching the current filters.</td></tr>';
        }
    };

    const clearSmartlockFilters = () => {
        if (smartlockNameFilter) smartlockNameFilter.value = '';
        if (smartlockStateFilter) smartlockStateFilter.value = '';
        applySmartlockFilters();
    };

    // --- AUTHORIZATION FILTERING ---

    const populateAuthSmartlockFilter = () => {
        if (!authSmartlockFilterSelect) return;
        
        authSmartlockFilterSelect.innerHTML = '<option value="">All Smartlocks</option>';
        allSmartlocks.forEach(smartlock => {
            authSmartlockFilterSelect.innerHTML += `<option value="${smartlock.smartlockId}">${smartlock.name}</option>`;
        });
    };

    const applyAuthFilters = () => {
        const nameFilter = authNameFilter ? authNameFilter.value.toLowerCase() : '';
        const codeFilter = authCodeFilter ? authCodeFilter.value : '';
        const smartlockFilter = authSmartlockFilterSelect ? authSmartlockFilterSelect.value : '';
        const statusFilter = authStatusFilter ? authStatusFilter.value : '';

        // Start with permission-filtered auths
        // Use allSmartlocksForAuthEditing to get proper smartlock names (including read-only ones)
        const smartlockMap = new Map((allSmartlocksForAuthEditing || allSmartlocks).map(smartlock => [smartlock.smartlockId, smartlock.name]));
        const keypadAuths = allAuths.filter(auth => auth.type === 13);

        const groupedAuths = keypadAuths.reduce((acc, auth) => {
            const key = `${auth.name}-${auth.code}`;
            if (!acc[key]) {
                acc[key] = {
                    ...auth,
                    smartlockIds: [],
                    smartlockNames: [],
                    authIds: []
                };
            }
            acc[key].smartlockIds.push(auth.smartlockId);
            acc[key].smartlockNames.push(smartlockMap.get(auth.smartlockId) || 'N/A');
            acc[key].authIds.push(auth.id);
            return acc;
        }, {});

        // Filter grouped auths based on permissions
        let authsToShow = Object.values(groupedAuths).filter(auth => {
            // Admin can see all
            if (currentUserInfo && currentUserInfo.is_admin) {
                return true;
            }
            
            // For non-admin users, check if they have any permissions for this auth
            if (currentUserInfo && !currentUserInfo.is_admin && userPermissions) {
                // Check if user has can_not_edit set for any of the auth IDs
                const hasCanNotEdit = auth.authIds.some(authId => {
                    const specificAccess = userPermissions.specific_auth_access.find(access => access.auth_id === authId);
                    return specificAccess && specificAccess.can_not_edit;
                });

                // If can_not_edit is set, hide the authorization completely
                if (hasCanNotEdit) {
                    return false;
                }

                // Otherwise, check normal permissions
                const canEdit = auth.authIds.some(authId => canEditAuth(authId));
                const canDelete = auth.authIds.some(authId => canDeleteAuth(authId));
                const hasGeneralPermissions = userPermissions.auth_permissions.can_create_auth || 
                                            userPermissions.auth_permissions.can_edit_auth || 
                                            userPermissions.auth_permissions.can_delete_auth;
                
                // Show auth only if user has specific permissions for it OR general permissions
                return canEdit || canDelete || hasGeneralPermissions;
            }
            
            // For API token users, show all (fallback)
            return true;
        });

        // Apply filters
        filteredAuths = authsToShow.filter(auth => {
            // Name filter
            if (nameFilter && !auth.name.toLowerCase().includes(nameFilter)) {
                return false;
            }

            // Code filter
            if (codeFilter && (!auth.code || !auth.code.toString().includes(codeFilter))) {
                return false;
            }

            // Smartlock filter
            if (smartlockFilter) {
                const smartlockId = parseInt(smartlockFilter);
                if (!auth.smartlockIds.includes(smartlockId)) {
                    return false;
                }
            }

            // Status filter
            if (statusFilter) {
                const authStatus = auth.enabled ? 'enabled' : 'disabled';
                if (authStatus !== statusFilter) {
                    return false;
                }
            }

            return true;
        });

        renderFilteredAuths();
    };

    const renderFilteredAuths = () => {
        authsContainer.innerHTML = '';
        
        // Check if user has any authorization permissions at all
        if (currentUserInfo && !currentUserInfo.is_admin && userPermissions) {
            const hasAnyAuthPermission = userPermissions.auth_permissions.can_create_auth || 
                                       userPermissions.auth_permissions.can_edit_auth || 
                                       userPermissions.auth_permissions.can_delete_auth ||
                                       userPermissions.specific_auth_access.length > 0;
            
            if (!hasAnyAuthPermission) {
                authsContainer.innerHTML = '<tr><td colspan="5">No authorization permissions. Contact your administrator for access.</td></tr>';
                return;
            }
        }

        filteredAuths.forEach(auth => {
            const row = document.createElement('tr');
            const status = auth.enabled ? 'Enabled' : 'Disabled';
            let fingerprintHtml = '';
            if (auth.fingerprints && Object.keys(auth.fingerprints).length > 0) {
                fingerprintHtml = `<span>👆</span>`;
            }
            
            // Check permissions for edit/delete buttons
            const canEdit = auth.authIds.some(authId => canEditAuth(authId));
            const canDelete = auth.authIds.some(authId => canDeleteAuth(authId));
            
            // Build action buttons based on permissions
            let actionButtons = '';
            if (canEdit) {
                actionButtons += '<button class="btn-edit">Edit</button>';
            }
            if (canDelete) {
                actionButtons += '<button class="btn-delete">Delete</button>';
            }
            if (!canEdit && !canDelete) {
                actionButtons = '<span class="no-permissions">No permissions</span>';
            }
            
            row.innerHTML = `
                <td data-label="Name">${auth.name} ${fingerprintHtml}</td>
                <td data-label="Code">${auth.code || 'N/A'}</td>
                <td data-label="Smartlock">${auth.smartlockNames.join(', ')}</td>
                <td data-label="Status">${status}</td>
                <td data-label="Actions" class="actions">
                    ${actionButtons}
                </td>
            `;
            
            // Add event listeners for buttons
            const editButton = row.querySelector('.btn-edit');
            const deleteButton = row.querySelector('.btn-delete');
            
            if (editButton) {
                editButton.onclick = () => openAuthModal(auth);
            }
            if (deleteButton) {
                deleteButton.onclick = () => deleteAuth(auth.authIds);
            }
            
            authsContainer.appendChild(row);
        });
        
        // Show message if no authorizations are visible
        if (filteredAuths.length === 0) {
            authsContainer.innerHTML = '<tr><td colspan="5">No authorizations found matching the current filters.</td></tr>';
        }
    };

    const clearAuthFilters = () => {
        if (authNameFilter) authNameFilter.value = '';
        if (authCodeFilter) authCodeFilter.value = '';
        if (authSmartlockFilterSelect) authSmartlockFilterSelect.value = '';
        if (authStatusFilter) authStatusFilter.value = '';
        applyAuthFilters();
    };

    // --- UI RENDERING ---

    const getStateName = (state) => {
        const stateNames = { 0: 'uncalibrated', 1: 'locked', 2: 'unlocking', 3: 'unlocked', 4: 'locking', 5: 'unlatched', 6: 'unlocked (lock\'n\'go)', 7: 'unlatching', 253: 'boot run', 254: 'motor blocked', 255: 'undefined' };
        return stateNames[state] || 'unknown';
    };

    const renderSmartlocks = () => {
        // Initialize filters and render filtered smartlocks
        applySmartlockFilters();
        
        // Populate auth smartlock filter dropdown
        populateAuthSmartlockFilter();
    };

    const renderAuths = () => {
        // Initialize filters and render filtered authorizations
        applyAuthFilters();
    };

    const populateSelects = (selectedSmartlockIds = []) => {
        authSmartlockSelect.innerHTML = '';
        
        // Use allSmartlocksForAuthEditing which includes read-only smartlocks from specific auth access
        const smartlocksForAuthEditing = allSmartlocksForAuthEditing || [];
        
        // Determine if this is a new authorization (no selected smartlocks) or editing existing
        const isNewAuthorization = selectedSmartlockIds.length === 0;
        
        // Create combined list of smartlocks to show
        const smartlocksToShow = new Map();
        
        // Add all smartlocks from auth editing endpoint
        smartlocksForAuthEditing.forEach(smartlock => {
            const canModify = smartlock.user_can_modify !== false; // Default to true if not specified
            smartlocksToShow.set(smartlock.smartlockId, {
                ...smartlock,
                canModify: canModify
            });
        });
        
        // For existing authorizations: If we don't have some selected smartlocks in our list,
        // create dummy entries (this handles edge cases)
        if (!isNewAuthorization) {
            selectedSmartlockIds.forEach(smartlockId => {
                if (!smartlocksToShow.has(smartlockId)) {
                    smartlocksToShow.set(smartlockId, {
                        smartlockId: smartlockId,
                        name: `Smartlock ${smartlockId}`, // Fallback name
                        canModify: false // Always read-only for unknown smartlocks
                    });
                }
            });
        }
        
        // Render the smartlocks
        if (smartlocksToShow.size > 0) {
            const htmlParts = [];
            Array.from(smartlocksToShow.values()).forEach(smartlock => {
                const isChecked = selectedSmartlockIds.includes(smartlock.smartlockId);
                const isDisabled = !smartlock.canModify ? 'disabled' : '';
                const readOnlyClass = !smartlock.canModify ? 'read-only' : '';
                const readOnlyText = !smartlock.canModify ? ' (read-only)' : '';
                
                htmlParts.push(`
                    <label class="${readOnlyClass}">
                        <input type="checkbox" value="${smartlock.smartlockId}" ${isChecked ? 'checked' : ''} ${isDisabled}>
                        ${smartlock.name}${readOnlyText}
                    </label>
                `);
            });
            
            authSmartlockSelect.innerHTML = htmlParts.join('');
            
            // Count editable vs read-only smartlocks
            const editableCount = Array.from(smartlocksToShow.values()).filter(sl => sl.canModify).length;
            const readOnlyCount = smartlocksToShow.size - editableCount;
            
            // Add info message if user has read-only smartlocks
            if (readOnlyCount > 0 && editableCount === 0) {
                authSmartlockSelect.innerHTML += '<div class="smartlocks-info">You can see the selected smartlocks but cannot modify the selection. Contact your administrator for access to other smartlocks.</div>';
            } else if (readOnlyCount > 0) {
                authSmartlockSelect.innerHTML += '<div class="smartlocks-info">Some smartlocks are read-only. You can only modify smartlocks you have direct access to.</div>';
            }
        } else {
            // No smartlocks to show at all
            authSmartlockSelect.innerHTML = '<div class="no-smartlocks-warning">No smartlocks available. Contact your administrator for access.</div>';
        }
    };

    // --- FINGERPRINTS FUNCTIONALITY ---

    const renderFingerprints = (auth) => {
        if (!auth || !auth.fingerprints || Object.keys(auth.fingerprints).length === 0) {
            return
            fingerprintsList.innerHTML = '<div class="no-fingerprints">No fingerprints registered</div>';
            fingerprintsSection.style.display = 'none';
            return;
        }
        return;
        fingerprintsSection.style.display = 'block';
        fingerprintsList.innerHTML = '';

        Object.entries(auth.fingerprints).forEach(([fingerprintId, fingerprintName]) => {
            const fingerprintItem = document.createElement('div');
            fingerprintItem.className = 'fingerprint-item';
            fingerprintItem.dataset.fingerprintId = fingerprintId;

            fingerprintItem.innerHTML = `
                <div class="fingerprint-info">
                    <span class="fingerprint-icon">👆</span>
                    <span class="fingerprint-name">${fingerprintName}</span>
                    <span class="fingerprint-id">${fingerprintId.substring(0, 17)}...</span>
                </div>
                <!--<div class="fingerprint-actions">
                    <button type="button" class="btn-small btn-edit" onclick="editFingerprint('${fingerprintId}')">Edit</button>
                    <button type="button" class="btn-small btn-delete" onclick="deleteFingerprint('${fingerprintId}')">Delete</button>
                </div>-->
            `;

            fingerprintsList.appendChild(fingerprintItem);
        });
    };

    window.editFingerprint = (fingerprintId) => {
        const fingerprintItem = document.querySelector(`[data-fingerprint-id="${fingerprintId}"]`);
        const nameSpan = fingerprintItem.querySelector('.fingerprint-name');
        const actionsDiv = fingerprintItem.querySelector('.fingerprint-actions');
        
        const currentName = nameSpan.textContent;
        
        nameSpan.innerHTML = `<input type="text" class="fingerprint-name-input" value="${currentName}">`;
        actionsDiv.innerHTML = `
            <button type="button" class="btn-small btn-save" onclick="saveFingerprint('${fingerprintId}')">Save</button>
            <button type="button" class="btn-small btn-cancel" onclick="cancelEditFingerprint('${fingerprintId}', '${currentName}')">Cancel</button>
        `;
        
        const input = nameSpan.querySelector('.fingerprint-name-input');
        input.focus();
        input.select();
    };

    window.saveFingerprint = (fingerprintId) => {
        const fingerprintItem = document.querySelector(`[data-fingerprint-id="${fingerprintId}"]`);
        const input = fingerprintItem.querySelector('.fingerprint-name-input');
        const newName = input.value.trim();
        
        if (!newName) {
            alert('Fingerprint name cannot be empty');
            return;
        }
        
        // Update the fingerprint name in the current auth data
        const authIds = authIdInput.value ? JSON.parse(authIdInput.value) : [];
        if (authIds.length > 0) {
            // Find the auth with fingerprints
            const authWithFingerprints = allAuths.find(a => 
                authIds.includes(a.id) && 
                a.fingerprints && 
                a.fingerprints[fingerprintId]
            );
            
            if (authWithFingerprints) {
                authWithFingerprints.fingerprints[fingerprintId] = newName;
                renderFingerprints(authWithFingerprints);
            }
        }
    };

    window.cancelEditFingerprint = (fingerprintId, originalName) => {
        const fingerprintItem = document.querySelector(`[data-fingerprint-id="${fingerprintId}"]`);
        const nameSpan = fingerprintItem.querySelector('.fingerprint-name');
        const actionsDiv = fingerprintItem.querySelector('.fingerprint-actions');
        
        nameSpan.innerHTML = originalName;
        actionsDiv.innerHTML = `
            <!--<button type="button" class="btn-small btn-edit" onclick="editFingerprint('${fingerprintId}')">Edit</button>
            <button type="button" class="btn-small btn-delete" onclick="deleteFingerprint('${fingerprintId}')">Delete</button>-->
        `;
    };

    window.deleteFingerprint = (fingerprintId) => {
        if (!confirm('Are you sure you want to delete this fingerprint?')) {
            return;
        }
        
        // Remove the fingerprint from the current auth data
        const authIds = authIdInput.value ? JSON.parse(authIdInput.value) : [];
        if (authIds.length > 0) {
            // Find the auth with fingerprints and remove the fingerprint
            const authWithFingerprints = allAuths.find(a => 
                authIds.includes(a.id) && 
                a.fingerprints && 
                a.fingerprints[fingerprintId]
            );
            
            if (authWithFingerprints) {
                delete authWithFingerprints.fingerprints[fingerprintId];
                renderFingerprints(authWithFingerprints);
            }
        }
    };

    // --- MODAL HANDLING ---

    const openAuthModal = (auth = null) => {
        authForm.reset();
        pinContainer.style.display = 'block'; // Always show pin container
        timeRestrictionPanel.style.display = 'none';
        timeRestrictionPanel.innerHTML = '';
        //fingerprintsSection.style.display = 'none';
        //fingerprintsList.innerHTML = '';

        if (auth) {
            authModalTitle.textContent = 'Edit Authorization';
            authIdInput.value = JSON.stringify(auth.authIds);
            originalSmartlockIdsInput.value = JSON.stringify(auth.smartlockIds);
            originalPinCodeInput.value = auth.code || '';
            authNameInput.value = auth.name;
            authEnabledCheckbox.checked = auth.enabled;
            
            // Handle both grouped auth objects and single auth objects
            let smartlockIds;
            if (auth.smartlockIds) {
                // This is a grouped auth object
                smartlockIds = auth.smartlockIds;
            } else if (auth.smartlockId) {
                // This is a single auth object
                smartlockIds = [auth.smartlockId];
            } else {
                smartlockIds = [];
            }
            
            populateSelects(smartlockIds);
            authTypeSelect.value = '13'; // Hardcode to keypad
            authTypeSelect.disabled = true;

            if (auth.code) {
                const codeString = String(auth.code).padStart(6, '0');
                pinInputs.forEach((input, index) => {
                    input.value = codeString[index];
                });
            }

            const hasTimeRestrictions = hasActiveTimeRestrictions(auth);
            timeLimitToggle.checked = hasTimeRestrictions;
            if (hasTimeRestrictions) {
                timeRestrictionPanel.innerHTML = createTimeRestrictionPanel(auth);
                timeRestrictionPanel.style.display = 'block';
                setupTimeRestrictionHandlers();
            }

            // Show fingerprints section for existing auths
            renderFingerprints(auth);

        } else {
            authModalTitle.textContent = 'Create Authorization';
            authIdInput.value = '';
            originalSmartlockIdsInput.value = '';
            originalPinCodeInput.value = '';
            authEnabledCheckbox.checked = true;
            authTypeSelect.value = '13'; // Hardcode to keypad
            authTypeSelect.disabled = true;
            populateSelects([]);
        }
        authModal.style.display = 'block';
    };

    const closeModal = (modal) => {
        modal.style.display = 'none';
    };

    document.querySelectorAll('.modal .close-button').forEach(button => {
        button.onclick = () => {
            closeModal(authModal);
        };
    });

    window.onclick = (event) => {
        if (event.target == authModal) closeModal(authModal);
    };

    addAuthButton.onclick = () => openAuthModal();

    // --- TIME RESTRICTION HELPERS ---

    const hasActiveTimeRestrictions = (auth) => {
        return !!(auth.allowedFromDate || auth.allowedUntilDate || auth.allowedWeekDays > 0 || auth.allowedFromTime > 0 || auth.allowedUntilTime > 0);
    };

    const createTimeRestrictionPanel = (auth) => {
        const fromDate = auth.allowedFromDate ? formatDateForInput(auth.allowedFromDate) : '';
        const untilDate = auth.allowedUntilDate ? formatDateForInput(auth.allowedUntilDate) : '';
        const fromTime = formatTimeForInput(auth.allowedFromTime || 0);
        const untilTime = formatTimeForInput(auth.allowedUntilTime || 0);

        return `
            <div class="time-section">
                <h4>Date Range</h4>
                <div class="form-row">
                    <div class="form-group">
                        <label for="auth-from-date">From Date:</label>
                        <input type="datetime-local" id="auth-from-date" value="${fromDate}">
                    </div>
                    <div class="form-group">
                        <label for="auth-until-date">Until Date:</label>
                        <input type="datetime-local" id="auth-until-date" value="${untilDate}">
                    </div>
                </div>
                <div class="form-group">
                    <label class="checkbox-label">
                        <input type="checkbox" id="clear-until-date" ${!auth.allowedUntilDate ? 'checked' : ''}>
                        No end date (permanent access)
                    </label>
                </div>
            </div>
            <div class="time-section">
                <h4>Weekly Schedule</h4>
                <div class="weekdays-grid" id="auth-weekdays">
                    ${createWeekdaysHtml(auth.allowedWeekDays || 0)}
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label for="auth-from-time">Daily From:</label>
                        <input type="time" id="auth-from-time" value="${fromTime}">
                    </div>
                    <div class="form-group">
                        <label for="auth-until-time">Daily Until:</label>
                        <input type="time" id="auth-until-time" value="${untilTime}">
                    </div>
                </div>
            </div>
        `;
    };

    const createWeekdaysHtml = (allowedWeekDays) => {
        const days = [
            { name: 'Mon', value: 64 }, { name: 'Tue', value: 32 }, { name: 'Wed', value: 16 },
            { name: 'Thu', value: 8 }, { name: 'Fri', value: 4 }, { name: 'Sat', value: 2 }, { name: 'Sun', value: 1 }
        ];
        return days.map(day => `
            <label class="weekday-label">
                <input type="checkbox" value="${day.value}" ${(allowedWeekDays & day.value) ? 'checked' : ''}>
                <span class="weekday-name">${day.name}</span>
            </label>
        `).join('');
    };

    const formatDateForInput = (dateString) => {
        if (!dateString) return '';
        try {
            return new Date(dateString).toISOString().slice(0, 16);
        } catch (e) { return ''; }
    };

    const formatTimeForInput = (minutes) => {
        if (minutes === null || minutes === undefined) return '';
        const hours = Math.floor(minutes / 60);
        const mins = minutes % 60;
        return `${String(hours).padStart(2, '0')}:${String(mins).padStart(2, '0')}`;
    };

    const parseTimeToMinutes = (timeString) => {
        if (!timeString) return 0;
        const [hours, minutes] = timeString.split(':').map(Number);
        return hours * 60 + minutes;
    };

    const handleFromDateChange = (inputElement) => {
        let value = inputElement.value;
        
        // Wenn leer, aktuelle Zeit setzen
        if (!value) {
            const now = new Date();
            value = now.toISOString().slice(0, 16); // YYYY-MM-DDTHH:MM
            inputElement.value = value;
            return;
        }
        
        // Wenn nur Datum (YYYY-MM-DD), Zeit hinzufügen
        if (value.length === 10 && value.includes('-')) {
            inputElement.value = value + 'T00:00'; // Standard: Mitternacht
        }
    };

    const setupTimeRestrictionHandlers = () => {
        const clearUntilDateCheckbox = document.getElementById('clear-until-date');
        const untilDateInput = document.getElementById('auth-until-date');
        const fromDateInput = document.getElementById('auth-from-date');
        
        if (clearUntilDateCheckbox) {
            clearUntilDateCheckbox.addEventListener('change', (e) => {
                untilDateInput.disabled = e.target.checked;
                if (e.target.checked) untilDateInput.value = '';
            });
            untilDateInput.disabled = clearUntilDateCheckbox.checked;
        }
        
        // From Date Handler
        if (fromDateInput) {
            fromDateInput.addEventListener('blur', () => {
                handleFromDateChange(fromDateInput);
            });
            fromDateInput.addEventListener('change', () => {
                handleFromDateChange(fromDateInput);
            });
        }
    };

    timeLimitToggle.addEventListener('change', (e) => {
        if (e.target.checked) {
            const authId = authIdInput.value;
            const auth = authId ? allAuths.find(a => a.id === authId) : {};
            timeRestrictionPanel.innerHTML = createTimeRestrictionPanel(auth || {});
            timeRestrictionPanel.style.display = 'block';
            setupTimeRestrictionHandlers();
        } else {
            timeRestrictionPanel.style.display = 'none';
            timeRestrictionPanel.innerHTML = '';
        }
    });

    // --- EVENT HANDLERS & ACTIONS ---

    syncAllButton.addEventListener('click', async () => {
        const smartlockRows = document.querySelectorAll('tr[data-smartlock-id]');
        smartlockRows.forEach(row => {
            row.classList.add('syncing');
            const syncStatus = row.querySelector('.sync-status');
            syncStatus.textContent = 'Syncing...';
        });

        try {
            const response = await fetch('/api/smartlocks/sync', { method: 'POST' });
            if (!response.ok) throw new Error('Failed to sync all smartlocks');
            await refreshAllData();
        } catch (error) {
            console.error(error);
            smartlockRows.forEach(row => {
                const syncStatus = row.querySelector('.sync-status');
                syncStatus.textContent = 'Sync failed';
                setTimeout(() => {
                    syncStatus.textContent = '';
                    row.classList.remove('syncing');
                }, 3000);
            });
        }
    });

    const syncSmartlock = async (smartlockId) => {
        const smartlockRow = document.querySelector(`tr[data-smartlock-id='${smartlockId}']`);
        const syncStatus = smartlockRow.querySelector('.sync-status');
        try {
            smartlockRow.classList.add('syncing');
            syncStatus.textContent = 'Syncing...';
            const response = await fetch(`/api/smartlocks/${smartlockId}/sync`, { method: 'POST' });
            if (!response.ok) throw new Error('Failed to sync smartlock');
            await refreshAllData();
        } catch (error) {
            console.error(error);
            syncStatus.textContent = 'Sync failed';
        } finally {
            setTimeout(() => {
                syncStatus.textContent = '';
                smartlockRow.classList.remove('syncing');
            }, 3000);
        }
    };

    window.lock = async (smartlockId) => {
        try {
            const response = await fetch(`/api/smartlocks/${smartlockId}/action/lock`, { method: 'POST' });
            if (!response.ok) throw new Error('Failed to send lock command');
            alert('Lock command sent');
            await refreshAllData();
        } catch (error) {
            console.error(error);
            alert('Error sending lock command');
        }
    };

    window.unlatch = async (smartlockId) => {
        try {
            const response = await fetch(`/api/smartlocks/${smartlockId}/action/unlatch`, { method: 'POST' });
            if (!response.ok) throw new Error('Failed to send unlatch command');
            alert('Unlatch command sent');
            await refreshAllData();
        } catch (error) {
            console.error(error);
            alert('Error sending unlatch command');
        }
    };

    authForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const authIds = authIdInput.value ? JSON.parse(authIdInput.value) : [];
        const originalSmartlockIds = originalSmartlockIdsInput.value ? JSON.parse(originalSmartlockIdsInput.value) : [];
        const originalPinCode = originalPinCodeInput.value;

        const name = authNameInput.value;
        const type = 13; // Hardcoded to keypad
        const enabled = authEnabledCheckbox.checked;
        
        const selectedSmartlockIds = Array.from(authSmartlockSelect.querySelectorAll('input:checked')).map(input => parseInt(input.value));

        if (selectedSmartlockIds.length === 0) {
            alert('Please select at least one smart lock.');
            return;
        }

        let code = null;
        if (type === 13) {
            code = Array.from(pinInputs).map(input => input.value).join('');
        if (code && (code.length !== 6 || !/^[1-9][1-9]{5}$/.test(code))) {
            alert('Please enter a 6-digit PIN. All digits must be 1-9.');
            return;
        }
        }

        const payload = { name, type, enabled };
        if (code) payload.code = parseInt(code);

        if (timeLimitToggle.checked) {
            const fromDate = document.getElementById('auth-from-date').value;
            const untilDate = document.getElementById('auth-until-date').value;
            const clearUntilDate = document.getElementById('clear-until-date').checked;
            const fromTime = document.getElementById('auth-from-time').value;
            const untilTime = document.getElementById('auth-until-time').value;
            
            let weekdays = 0;
            document.querySelectorAll('#auth-weekdays input:checked').forEach(cb => {
                weekdays |= parseInt(cb.value);
            });

            if (fromDate) {
                payload.allowedFromDate = new Date(fromDate).toISOString();
            } else {
                // Fallback: aktuelle Zeit setzen wenn fromDate leer ist
                payload.allowedFromDate = new Date().toISOString();
            }
            if (untilDate && !clearUntilDate) payload.allowedUntilDate = new Date(untilDate).toISOString();
            if (weekdays > 0) payload.allowedWeekDays = weekdays;
            payload.allowedFromTime = fromTime ? parseTimeToMinutes(fromTime) : 0;
            payload.allowedUntilTime = untilTime ? parseTimeToMinutes(untilTime) : 1439;
        }

        try {
            const isEdit = authIds.length > 0;

            if (isEdit) {
                // For existing authorizations, use enhanced approach with permission preservation
                const toAdd = selectedSmartlockIds.filter(id => !originalSmartlockIds.includes(id));
                const toRemove = originalSmartlockIds.filter(id => !selectedSmartlockIds.includes(id));
                const toUpdate = selectedSmartlockIds.filter(id => originalSmartlockIds.includes(id));

                // STEP 1: Collect permissions from auths that will be removed
                const permissionsToPreserve = [];
                if (toRemove.length > 0) {
                    for (const smartlockId of toRemove) {
                        const authToRemove = allAuths.find(a => a.smartlockId === smartlockId && authIds.includes(a.id));
                        if (authToRemove) {
                            try {
                                const permissionsResponse = await fetch(`/api/admin/auth/${authToRemove.id}/permissions`);
                                if (permissionsResponse.ok) {
                                    const permissions = await permissionsResponse.json();
                                    if (permissions.length > 0) {
                                        permissionsToPreserve.push({
                                            oldAuthId: authToRemove.id,
                                            smartlockId: smartlockId,
                                            permissions: permissions
                                        });
                                    }
                                }
                            } catch (error) {
                                // Silently continue if permission fetching fails
                            }
                        }
                    }
                }

                // STEP 2: Remove authorizations from smartlocks that are no longer selected
                if (toRemove.length > 0) {
                    const authsToRemove = toRemove.map(smartlockId => {
                        const auth = allAuths.find(a => a.smartlockId === smartlockId && authIds.includes(a.id));
                        return auth ? auth.id : null;
                    }).filter(id => id);
                    
                    if (authsToRemove.length > 0) {
                        await fetch(`/api/smartlock/auth?allow_edit_as_delete=true`, {
                            method: 'DELETE',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(authsToRemove)
                        });
                    }
                }

                // STEP 3: Add authorizations to newly selected smartlocks
                if (toAdd.length > 0) {
                    const creationPayload = { ...payload, smartlockIds: toAdd };
                    const createResponse = await fetch('/api/smartlock/auth', {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(creationPayload)
                    });
                    
                    if (!createResponse.ok) {
                        throw new Error(`Failed to create authorization: ${createResponse.status}`);
                    }
                }

                // STEP 4: Copy permissions to newly created authorizations
                if (toAdd.length > 0 && permissionsToPreserve.length > 0) {
                    // Wait for new auths to be created and find them
                    let retryCount = 0;
                    const maxRetries = 10;
                    let newAuths = [];
                    
                    while (retryCount < maxRetries) {
                        await new Promise(resolve => setTimeout(resolve, 800));
                        await refreshAllData();
                        
                        // Find newly created auths
                        newAuths = allAuths.filter(auth => {
                            return auth.name === name && 
                                   auth.code === (code ? parseInt(code) : null) && 
                                   toAdd.includes(auth.smartlockId);
                        });
                        
                        if (newAuths.length >= toAdd.length) {
                            // Copy permissions to new auths
                            for (const newAuth of newAuths) {
                                for (const preserved of permissionsToPreserve) {
                                    try {
                                        await fetch(`/api/admin/auth/${newAuth.id}/permissions/copy`, {
                                            method: 'POST',
                                            headers: { 'Content-Type': 'application/json' },
                                            body: JSON.stringify({ old_auth_id: preserved.oldAuthId })
                                        });
                                    } catch (error) {
                                        // Silently continue if permission copying fails
                                    }
                                }
                            }
                            break;
                        }
                        retryCount++;
                    }
                }

                // STEP 5: Update existing authorizations (this preserves fingerprints)
                for (const smartlockId of toUpdate) {
                    const authToUpdate = allAuths.find(a => a.smartlockId === smartlockId && authIds.includes(a.id));
                    if (authToUpdate) {
                        const response = await fetch(`/api/smartlock/${smartlockId}/auth/${authToUpdate.id}`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify(payload),
                        });
                        
                        if (!response.ok) {
                            throw new Error(`Failed to update authorization for smartlock ${smartlockId}`);
                        }
                    }
                }
            } else {
                // NEW: Two-Step Approach for creating authorizations
                
                // Step 1: Create authorization WITHOUT enabled field and time restrictions
                const createPayload = { name, type };
                if (code) createPayload.code = parseInt(code);
                createPayload.smartlockIds = selectedSmartlockIds;
                
                const createResponse = await fetch('/api/smartlock/auth', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(createPayload)
                });
                
                if (!createResponse.ok) {
                    throw new Error('Failed to create authorization');
                }
                
                // Step 2: If time restrictions are enabled, update each created authorization
                if (timeLimitToggle.checked) {
                    // Prepare time restriction payload
                    const timePayload = { name, enabled };
                    if (code) timePayload.code = parseInt(code);
                    
                    const fromDate = document.getElementById('auth-from-date').value;
                    const untilDate = document.getElementById('auth-until-date').value;
                    const clearUntilDate = document.getElementById('clear-until-date').checked;
                    const fromTime = document.getElementById('auth-from-time').value;
                    const untilTime = document.getElementById('auth-until-time').value;
                    
                    let weekdays = 0;
                    document.querySelectorAll('#auth-weekdays input:checked').forEach(cb => {
                        weekdays |= parseInt(cb.value);
                    });

                    if (fromDate) {
                        timePayload.allowedFromDate = new Date(fromDate).toISOString();
                    } else {
                        // Fallback: aktuelle Zeit setzen wenn fromDate leer ist
                        timePayload.allowedFromDate = new Date().toISOString();
                    }
                    if (untilDate && !clearUntilDate) timePayload.allowedUntilDate = new Date(untilDate).toISOString();
                    if (weekdays > 0) timePayload.allowedWeekDays = weekdays;
                    timePayload.allowedFromTime = fromTime ? parseTimeToMinutes(fromTime) : 0;
                    timePayload.allowedUntilTime = untilTime ? parseTimeToMinutes(untilTime) : 1439;
                    
                    // Wait for authorizations to be created with retry logic
                    let newAuths = [];
                    let retryCount = 0;
                    const maxRetries = 10;
                    const retryDelay = 500; // 500ms
                    
                    while (newAuths.length < selectedSmartlockIds.length && retryCount < maxRetries) {
                        // Wait before checking
                        if (retryCount > 0) {
                            await new Promise(resolve => setTimeout(resolve, retryDelay));
                        }
                        
                        // Refresh data to get the newly created authorizations
                        await refreshAllData();
                        
                        // Find the newly created authorizations by name and code
                        newAuths = allAuths.filter(auth => 
                            auth.name === name && 
                            auth.code === (code ? parseInt(code) : null) &&
                            selectedSmartlockIds.includes(auth.smartlockId)
                        );
                        
                        console.log(`Retry ${retryCount + 1}: Found ${newAuths.length} of ${selectedSmartlockIds.length} expected authorizations`);
                        retryCount++;
                    }
                    
                    if (newAuths.length === 0) {
                        console.warn('No newly created authorizations found after retries');
                        throw new Error('Failed to find newly created authorizations for time restrictions');
                    }
                    
                    if (newAuths.length < selectedSmartlockIds.length) {
                        console.warn(`Only found ${newAuths.length} of ${selectedSmartlockIds.length} expected authorizations`);
                    }
                    
                    // Update each newly created authorization with time restrictions
                    let successCount = 0;
                    for (const auth of newAuths) {
                        try {
                            const updateResponse = await fetch(`/api/smartlock/${auth.smartlockId}/auth/${auth.id}`, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify(timePayload)
                            });
                            
                            if (updateResponse.ok) {
                                successCount++;
                                console.log(`Successfully added time restrictions to authorization ${auth.id} on smartlock ${auth.smartlockId}`);
                            } else {
                                console.warn(`Failed to add time restrictions to authorization ${auth.id} on smartlock ${auth.smartlockId}: ${updateResponse.status}`);
                            }
                        } catch (error) {
                            console.error(`Error updating authorization ${auth.id} on smartlock ${auth.smartlockId}:`, error);
                        }
                    }
                    
                    console.log(`Time restrictions applied to ${successCount} of ${newAuths.length} authorizations`);
                }
                
                // Step 3: Always update enabled field if it's different from default (true)
                if (!enabled) {
                    // Wait for authorizations to be created with retry logic (if not already done)
                    let newAuths = [];
                    let retryCount = 0;
                    const maxRetries = 10;
                    const retryDelay = 500; // 500ms
                    
                    while (newAuths.length < selectedSmartlockIds.length && retryCount < maxRetries) {
                        // Wait before checking
                        if (retryCount > 0) {
                            await new Promise(resolve => setTimeout(resolve, retryDelay));
                        }
                        
                        // Refresh data to get the newly created authorizations
                        await refreshAllData();
                        
                        // Find the newly created authorizations by name and code
                        newAuths = allAuths.filter(auth => 
                            auth.name === name && 
                            auth.code === (code ? parseInt(code) : null) &&
                            selectedSmartlockIds.includes(auth.smartlockId)
                        );
                        
                        console.log(`Enabled field retry ${retryCount + 1}: Found ${newAuths.length} of ${selectedSmartlockIds.length} expected authorizations`);
                        retryCount++;
                    }
                    
                    if (newAuths.length === 0) {
                        console.warn('No newly created authorizations found for enabled field update');
                    } else {
                        // Update each newly created authorization with enabled=false
                        const enabledPayload = { name, enabled };
                        if (code) enabledPayload.code = parseInt(code);
                        
                        let enabledSuccessCount = 0;
                        for (const auth of newAuths) {
                            try {
                                const updateResponse = await fetch(`/api/smartlock/${auth.smartlockId}/auth/${auth.id}`, {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify(enabledPayload)
                                });
                                
                                if (updateResponse.ok) {
                                    enabledSuccessCount++;
                                    console.log(`Successfully set enabled=false for authorization ${auth.id} on smartlock ${auth.smartlockId}`);
                                } else {
                                    console.warn(`Failed to set enabled=false for authorization ${auth.id} on smartlock ${auth.smartlockId}: ${updateResponse.status}`);
                                }
                            } catch (error) {
                                console.error(`Error updating enabled field for authorization ${auth.id} on smartlock ${auth.smartlockId}:`, error);
                            }
                        }
                        
                        console.log(`Enabled field updated for ${enabledSuccessCount} of ${newAuths.length} authorizations`);
                    }
                }
            }

            alert('Authorization saved successfully with fingerprints preserved.');
            closeModal(authModal);
            blockingOverlay.style.display = 'flex';
            setTimeout(() => location.reload(), 2000);
        } catch (error) {
            console.error(error);
            alert(`Error saving authorization: ${error.message}`);
        }
    });

    window.deleteAuth = async (authIds) => {
        if (!confirm('Are you sure you want to delete this authorization?')) return;
        try {
            const response = await fetch(`/api/smartlock/auth`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(authIds)
            });
            if (!response.ok) throw new Error('Failed to delete authorization');
            alert('Authorization deleted');
            blockingOverlay.style.display = 'flex';
            setTimeout(() => location.reload(), 2000);
        } catch (error) {
            console.error(error);
            alert('Error deleting authorization');
        }
    };

    pinInputs.forEach((input, index) => {
        input.addEventListener('input', () => {
            if (input.value.length === 1 && index < pinInputs.length - 1) {
                pinInputs[index + 1].focus();
            }
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && input.value.length === 0 && index > 0) {
                pinInputs[index - 1].focus();
            }
        });
        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pasteData = e.clipboardData.getData('text');
            if (/^[1-9][1-9]{5}$/.test(pasteData)) {
                pinInputs.forEach((pinInput, i) => {
                    pinInput.value = pasteData[i];
                });
                pinInputs[pinInputs.length - 1].focus();
            }
        });
    });

    // --- LOGS EVENT HANDLERS ---

    refreshLogsButton.addEventListener('click', fetchLogs);
    clearFiltersButton.addEventListener('click', clearFilters);
    smartlockFilter.addEventListener('change', applyFilters);
    logTypeFilter.addEventListener('change', applyFilters);
    dateFilter.addEventListener('change', applyFilters);

    // --- SMARTLOCK FILTER EVENT HANDLERS ---

    if (smartlockNameFilter) {
        smartlockNameFilter.addEventListener('input', applySmartlockFilters);
    }
    if (smartlockStateFilter) {
        smartlockStateFilter.addEventListener('change', applySmartlockFilters);
    }
    if (clearSmartlockFiltersButton) {
        clearSmartlockFiltersButton.addEventListener('click', clearSmartlockFilters);
    }

    // --- AUTHORIZATION FILTER EVENT HANDLERS ---

    if (authNameFilter) {
        authNameFilter.addEventListener('input', applyAuthFilters);
    }
    if (authCodeFilter) {
        authCodeFilter.addEventListener('input', applyAuthFilters);
    }
    if (authSmartlockFilterSelect) {
        authSmartlockFilterSelect.addEventListener('change', applyAuthFilters);
    }
    if (authStatusFilter) {
        authStatusFilter.addEventListener('change', applyAuthFilters);
    }
    if (clearAuthFiltersButton) {
        clearAuthFiltersButton.addEventListener('click', clearAuthFilters);
    }

    // --- NAVIGATION ---
    const navLinks = document.querySelectorAll('.nav-link');
    const pageContents = document.querySelectorAll('.page-content');

    // Function to switch to a specific page
    const switchToPage = (target) => {
        navLinks.forEach(navLink => navLink.classList.remove('active'));
        pageContents.forEach(content => content.classList.remove('active'));

        const targetLink = document.querySelector(`[data-target="${target}"]`);
        const targetElement = document.getElementById(target);
        
        if (targetLink && targetElement) {
            targetLink.classList.add('active');
            targetElement.classList.add('active');
            
            // Save current page to localStorage (except for initial login)
            localStorage.setItem('currentPage', target);
            
            // Load logs when logs page is accessed
            if (target === 'logs') {
                fetchLogs();
            }
        }
    };

    // Initialize page navigation
    const initializeNavigation = () => {
        // Check if this is a fresh login (no currentPage stored or coming from login)
        const currentPage = localStorage.getItem('currentPage');
        const isFromLogin = sessionStorage.getItem('fromLogin') === 'true';
        
        if (isFromLogin || !currentPage) {
            // Fresh login or no saved page - always start with smartlocks
            switchToPage('smartlocks');
            sessionStorage.removeItem('fromLogin'); // Clear the flag
        } else {
            // Reload - restore the saved page
            switchToPage(currentPage);
        }
    };

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const target = link.dataset.target;
            switchToPage(target);
        });
    });

    // Initialize navigation after authentication check
    initializeNavigation();

    // --- PERMISSION FUNCTIONS ---
    
    const loadUserPermissions = async () => {
        try {
            const response = await fetch('/api/user/info');
            if (!response.ok) {
                throw new Error('Failed to load user permissions');
            }
            const userInfo = await response.json();
            currentUserInfo = userInfo;
            userPermissions = userInfo.permissions;
            console.log('User permissions loaded:', userPermissions);
            return userPermissions;
        } catch (error) {
            console.error('Error loading user permissions:', error);
            return null;
        }
    };
    
    const refreshUserPermissions = async () => {
        try {
            const response = await fetch('/api/user/permissions/refresh');
            if (!response.ok) {
                throw new Error('Failed to refresh user permissions');
            }
            userPermissions = await response.json();
            console.log('User permissions refreshed:', userPermissions);
            updateUIBasedOnPermissions();
            return userPermissions;
        } catch (error) {
            console.error('Error refreshing user permissions:', error);
            return null;
        }
    };
    
    const hasSmartlockPermission = (smartlockId) => {
        if (!userPermissions || !currentUserInfo) return false;
        if (currentUserInfo.is_admin) return true;
        
        return userPermissions.smartlock_permissions.some(perm => 
            perm.smartlock_id === smartlockId && perm.can_view
        );
    };
    
    const canCreateAuth = () => {
        if (!userPermissions || !currentUserInfo) return false;
        if (currentUserInfo.is_admin) return true;
        
        return userPermissions.auth_permissions.can_create_auth;
    };
    
    const canEditAuth = (authId) => {
        if (!userPermissions || !currentUserInfo) return false;
        if (currentUserInfo.is_admin) return true;
        
        // Check specific permission first
        const specificAccess = userPermissions.specific_auth_access.find(access => access.auth_id === authId);
        if (specificAccess) {
            // If can_not_edit is true, user cannot edit regardless of other permissions
            if (specificAccess.can_not_edit) {
                return false;
            }
            return specificAccess.can_edit;
        }
        
        // Check general permission
        return userPermissions.auth_permissions.can_edit_auth;
    };
    
    const canDeleteAuth = (authId) => {
        if (!userPermissions || !currentUserInfo) return false;
        if (currentUserInfo.is_admin) return true;
        
        // Check specific permission first
        const specificAccess = userPermissions.specific_auth_access.find(access => access.auth_id === authId);
        if (specificAccess) {
            // If can_not_edit is true, user cannot delete regardless of other permissions
            if (specificAccess.can_not_edit) {
                return false;
            }
            return specificAccess.can_delete;
        }
        
        // Check general permission
        return userPermissions.auth_permissions.can_delete_auth;
    };
    
    const updateUIBasedOnPermissions = () => {
        // Update Create Authorization button
        if (addAuthButton) {
            addAuthButton.style.display = canCreateAuth() ? 'block' : 'none';
        }
        
        // Re-render all data to apply permission filters
        renderSmartlocks();
        renderAuths();
        populateSmartlockFilter();
    };

    // --- AUTHENTICATION FUNCTIONS ---
    
    function checkAuthentication() {
        const token = localStorage.getItem('authToken');
        const username = localStorage.getItem('username');
        
        if (!token) {
            // No token, redirect to login
            window.location.href = '/login.html';
            return;
        }
        
        // Verify token with backend
        fetch('/api/verify-token', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        })
        .then(response => {
            if (!response.ok) {
                // Token is invalid, redirect to login
                localStorage.removeItem('authToken');
                localStorage.removeItem('username');
                window.location.href = '/login.html';
                return;
            }
            return response.json();
        })
        .then(async data => {
            if (data && data.username) {
                // Token is valid, show username
                usernameDisplay.textContent = `Willkommen, ${data.username}`;
                
                // Show admin menu if user is admin
                if (data.is_admin) {
                    const adminLink = document.querySelector('.admin-only');
                    if (adminLink) {
                        adminLink.style.display = 'flex';
                        adminLink.classList.add('visible');
                    }
                }
                
                // Load user permissions for database users
                if (data.user_id) {
                    await loadUserPermissions();
                    updateUIBasedOnPermissions();
                }
            }
        })
        .catch(error => {
            console.error('Error verifying token:', error);
            localStorage.removeItem('authToken');
            localStorage.removeItem('username');
            window.location.href = '/login.html';
        });
    }
    
    function logout() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('username');
        window.location.href = '/login.html';
    }
    
    // Add authorization header to all API requests
    const originalFetch = window.fetch;
    window.fetch = function(url, options = {}) {
        const token = localStorage.getItem('authToken');
        if (token && url.startsWith('/api/')) {
            options.headers = {
                ...options.headers,
                'Authorization': `Bearer ${token}`
            };
        }
        return originalFetch(url, options);
    };
    
    // Logout button event listener
    if (logoutButton) {
        logoutButton.addEventListener('click', logout);
    }

    // --- ADMIN FUNCTIONS ---
    
    let allUsers = [];
    
    const fetchUsers = async () => {
        try {
            const response = await fetch('/api/admin/users');
            if (!response.ok) throw new Error('Failed to fetch users');
            allUsers = await response.json();
            renderUsers();
        } catch (error) {
            console.error('Error fetching users:', error);
            usersContainer.innerHTML = '<tr><td colspan="5">Error loading users</td></tr>';
        }
    };
    
    const renderUsers = () => {
        usersContainer.innerHTML = '';
        allUsers.forEach(user => {
            const row = document.createElement('tr');
            const adminStatus = user.is_admin ? 'Admin' : 'User';
            const adminClass = user.is_admin ? 'user-admin' : 'user-regular';
            const createdDate = new Date(user.created_at).toLocaleDateString();
            const lastLogin = user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never';
            
            row.innerHTML = `
                <td data-label="Username">${user.username}</td>
                <td data-label="Admin"><span class="user-status ${adminClass}">${adminStatus}</span></td>
                <td data-label="Created">${createdDate}</td>
                <td data-label="Last Login">${lastLogin}</td>
                <td data-label="Actions" class="user-actions">
                    <button class="btn-info" onclick="editUser(${user.id})">Edit</button>
                    <button class="btn-warning" onclick="toggleAdmin(${user.id}, ${!user.is_admin})">
                        ${user.is_admin ? 'Remove Admin' : 'Make Admin'}
                    </button>
                    <button class="btn-success" onclick="editPermissions(${user.id})">Permissions</button>
                    <button class="btn-danger" onclick="deleteUser(${user.id})">Delete</button>
                </td>
            `;
            usersContainer.appendChild(row);
        });
    };
    
    const openUserModal = (user = null) => {
        const userIdInput = document.getElementById('user-id');
        const usernameInput = document.getElementById('user-username');
        const passwordInput = document.getElementById('user-password');
        const isAdminCheckbox = document.getElementById('user-is-admin');
        
        if (user) {
            userModalTitle.textContent = 'Edit User';
            userIdInput.value = user.id;
            usernameInput.value = user.username;
            passwordInput.value = '';
            passwordInput.placeholder = 'Leave empty to keep current password';
            passwordInput.required = false;
            isAdminCheckbox.checked = user.is_admin;
        } else {
            userModalTitle.textContent = 'Create User';
            userIdInput.value = '';
            usernameInput.value = '';
            passwordInput.value = '';
            passwordInput.placeholder = 'Password';
            passwordInput.required = true;
            isAdminCheckbox.checked = false;
        }
        
        userModal.style.display = 'block';
    };
    
    const openPermissionsModal = async (userId) => {
        try {
            const user = allUsers.find(u => u.id === userId);
            if (!user) return;
            
            permissionsModalTitle.textContent = `Permissions for ${user.username}`;
            document.getElementById('permissions-user-id').value = userId;
            
            // Fetch user permissions
            const response = await fetch(`/api/admin/users/${userId}/permissions`);
            if (!response.ok) throw new Error('Failed to fetch permissions');
            const permissions = await response.json();
            
            // Populate smartlock permissions
            const smartlockPermissionsContainer = document.getElementById('smartlock-permissions');
            smartlockPermissionsContainer.innerHTML = '';
            
            allSmartlocks.forEach(smartlock => {
                const permission = permissions.smartlock_permissions.find(p => p.smartlock_id === smartlock.smartlockId);
                const canView = permission ? permission.can_view : false;
                
                const permissionItem = document.createElement('div');
                permissionItem.className = 'permission-item';
                permissionItem.innerHTML = `
                    <div class="permission-item-header">${smartlock.name}</div>
                    <div class="permission-controls">
                        <div class="permission-checkbox">
                            <input type="checkbox" id="smartlock-${smartlock.smartlockId}" ${canView ? 'checked' : ''}>
                            <label for="smartlock-${smartlock.smartlockId}">Can view and control</label>
                        </div>
                    </div>
                `;
                smartlockPermissionsContainer.appendChild(permissionItem);
            });
            
            // Populate auth permissions
            document.getElementById('can-create-auth').checked = permissions.auth_permissions.can_create_auth;
            document.getElementById('can-edit-auth').checked = permissions.auth_permissions.can_edit_auth;
            document.getElementById('can-delete-auth').checked = permissions.auth_permissions.can_delete_auth;
            
            // Populate specific auth permissions
            const specificAuthContainer = document.getElementById('specific-auth-permissions');
            specificAuthContainer.innerHTML = '';
            
            // Group auths by name and code for display
            const smartlockMap = new Map(allSmartlocks.map(smartlock => [smartlock.smartlockId, smartlock.name]));
            const keypadAuths = allAuths.filter(auth => auth.type === 13);
            const groupedAuths = keypadAuths.reduce((acc, auth) => {
                const key = `${auth.name}-${auth.code}`;
                if (!acc[key]) {
                    acc[key] = {
                        ...auth,
                        smartlockIds: [],
                        smartlockNames: [],
                        authIds: []
                    };
                }
                acc[key].smartlockIds.push(auth.smartlockId);
                acc[key].smartlockNames.push(smartlockMap.get(auth.smartlockId) || 'N/A');
                acc[key].authIds.push(auth.id);
                return acc;
            }, {});
            
            Object.values(groupedAuths).forEach(auth => {
                const authPermissionItem = document.createElement('div');
                authPermissionItem.className = 'auth-permission-item';
                
                const canEdit = permissions.specific_auth_access.some(access => 
                    auth.authIds.includes(access.auth_id) && access.can_edit
                );
                const canDelete = permissions.specific_auth_access.some(access => 
                    auth.authIds.includes(access.auth_id) && access.can_delete
                );
                
                const canNotEdit = permissions.specific_auth_access.some(access => 
                    auth.authIds.includes(access.auth_id) && access.can_not_edit
                );
                
                authPermissionItem.innerHTML = `
                    <div class="auth-permission-header">
                        <div class="auth-name">${auth.name}</div>
                        <div class="auth-code">${auth.code || 'N/A'}</div>
                    </div>
                    <div class="auth-smartlocks">Smartlocks: ${auth.smartlockNames.join(', ')}</div>
                    <div class="auth-permission-controls">
                        <div class="permission-checkbox">
                            <input type="checkbox" id="auth-edit-${auth.authIds[0]}" ${canEdit ? 'checked' : ''} ${canNotEdit ? 'disabled' : ''}>
                            <label for="auth-edit-${auth.authIds[0]}">Can edit</label>
                        </div>
                        <div class="permission-checkbox">
                            <input type="checkbox" id="auth-delete-${auth.authIds[0]}" ${canDelete ? 'checked' : ''} ${canNotEdit ? 'disabled' : ''}>
                            <label for="auth-delete-${auth.authIds[0]}">Can delete</label>
                        </div>
                        <div class="permission-checkbox can-not-edit">
                            <input type="checkbox" id="auth-not-edit-${auth.authIds[0]}" ${canNotEdit ? 'checked' : ''}>
                            <label for="auth-not-edit-${auth.authIds[0]}">Can not edit (hide authorization)</label>
                        </div>
                    </div>
                `;
                specificAuthContainer.appendChild(authPermissionItem);
                
                // Add event listener for "Can not edit" checkbox
                const notEditCheckbox = authPermissionItem.querySelector(`#auth-not-edit-${auth.authIds[0]}`);
                const editCheckbox = authPermissionItem.querySelector(`#auth-edit-${auth.authIds[0]}`);
                const deleteCheckbox = authPermissionItem.querySelector(`#auth-delete-${auth.authIds[0]}`);
                
                if (notEditCheckbox) {
                    notEditCheckbox.addEventListener('change', (e) => {
                        if (e.target.checked) {
                            // When "Can not edit" is checked, disable and uncheck other checkboxes
                            editCheckbox.checked = false;
                            editCheckbox.disabled = true;
                            deleteCheckbox.checked = false;
                            deleteCheckbox.disabled = true;
                        } else {
                            // When "Can not edit" is unchecked, enable other checkboxes
                            editCheckbox.disabled = false;
                            deleteCheckbox.disabled = false;
                        }
                    });
                }
            });
            
            permissionsModal.style.display = 'block';
            
        } catch (error) {
            console.error('Error opening permissions modal:', error);
            alert('Error loading permissions');
        }
    };
    
    // Global functions for button clicks
    window.editUser = (userId) => {
        const user = allUsers.find(u => u.id === userId);
        if (user) openUserModal(user);
    };
    
    window.deleteUser = async (userId) => {
        const user = allUsers.find(u => u.id === userId);
        if (!user) return;
        
        if (!confirm(`Are you sure you want to delete user "${user.username}"?`)) return;
        
        try {
            const response = await fetch(`/api/admin/users/${userId}`, { method: 'DELETE' });
            if (!response.ok) throw new Error('Failed to delete user');
            
            alert('User deleted successfully');
            fetchUsers();
        } catch (error) {
            console.error('Error deleting user:', error);
            alert('Error deleting user');
        }
    };
    
    window.toggleAdmin = async (userId, makeAdmin) => {
        const user = allUsers.find(u => u.id === userId);
        if (!user) return;
        
        const action = makeAdmin ? 'grant admin privileges to' : 'remove admin privileges from';
        if (!confirm(`Are you sure you want to ${action} "${user.username}"?`)) return;
        
        try {
            const response = await fetch(`/api/admin/users/${userId}/admin`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ is_admin: makeAdmin })
            });
            
            if (!response.ok) throw new Error('Failed to update admin status');
            
            alert('Admin status updated successfully');
            fetchUsers();
        } catch (error) {
            console.error('Error updating admin status:', error);
            alert('Error updating admin status');
        }
    };
    
    window.editPermissions = (userId) => {
        openPermissionsModal(userId);
    };
    
    // Event listeners for admin functionality
    if (addUserButton) {
        addUserButton.addEventListener('click', () => openUserModal());
    }
    
    if (userForm) {
        userForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const userId = document.getElementById('user-id').value;
            const username = document.getElementById('user-username').value;
            const password = document.getElementById('user-password').value;
            const isAdmin = document.getElementById('user-is-admin').checked;
            
            const isEdit = !!userId;
            const url = isEdit ? `/api/admin/users/${userId}` : '/api/admin/users';
            const method = isEdit ? 'PUT' : 'POST';
            
            const payload = { username, is_admin: isAdmin };
            if (password) payload.password = password;
            
            try {
                const response = await fetch(url, {
                    method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.detail || 'Failed to save user');
                }
                
                alert(`User ${isEdit ? 'updated' : 'created'} successfully`);
                userModal.style.display = 'none';
                fetchUsers();
            } catch (error) {
                console.error('Error saving user:', error);
                alert(`Error saving user: ${error.message}`);
            }
        });
    }
    
    if (permissionsForm) {
        permissionsForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const userId = document.getElementById('permissions-user-id').value;
            
            // Collect smartlock permissions
            const smartlockPermissions = [];
            allSmartlocks.forEach(smartlock => {
                const checkbox = document.getElementById(`smartlock-${smartlock.smartlockId}`);
                if (checkbox && checkbox.checked) {
                    smartlockPermissions.push({
                        smartlock_id: smartlock.smartlockId,
                        can_view: true
                    });
                }
            });
            
            // Collect auth permissions
            const authPermissions = {
                can_create_auth: document.getElementById('can-create-auth').checked,
                can_edit_auth: document.getElementById('can-edit-auth').checked,
                can_delete_auth: document.getElementById('can-delete-auth').checked
            };
            
            // Collect specific auth permissions
            const specificAuthAccess = [];
            const smartlockMap = new Map(allSmartlocks.map(smartlock => [smartlock.smartlockId, smartlock.name]));
            const keypadAuths = allAuths.filter(auth => auth.type === 13);
            const groupedAuths = keypadAuths.reduce((acc, auth) => {
                const key = `${auth.name}-${auth.code}`;
                if (!acc[key]) {
                    acc[key] = {
                        ...auth,
                        authIds: []
                    };
                }
                acc[key].authIds.push(auth.id);
                return acc;
            }, {});
            
            Object.values(groupedAuths).forEach(auth => {
                const editCheckbox = document.getElementById(`auth-edit-${auth.authIds[0]}`);
                const deleteCheckbox = document.getElementById(`auth-delete-${auth.authIds[0]}`);
                const notEditCheckbox = document.getElementById(`auth-not-edit-${auth.authIds[0]}`);
                
                if (editCheckbox || deleteCheckbox || notEditCheckbox) {
                    auth.authIds.forEach(authId => {
                        const canEdit = editCheckbox && editCheckbox.checked;
                        const canDelete = deleteCheckbox && deleteCheckbox.checked;
                        const canNotEdit = notEditCheckbox && notEditCheckbox.checked;
                        
                        // Only add entry if at least one permission is set
                        if (canEdit || canDelete || canNotEdit) {
                            specificAuthAccess.push({
                                auth_id: authId,
                                can_edit: canEdit,
                                can_delete: canDelete,
                                can_not_edit: canNotEdit
                            });
                        }
                    });
                }
            });
            
            const payload = {
                smartlock_permissions: smartlockPermissions,
                auth_permissions: authPermissions,
                specific_auth_access: specificAuthAccess
            };
            
            try {
                const response = await fetch(`/api/admin/users/${userId}/permissions`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                
                if (!response.ok) throw new Error('Failed to update permissions');
                
                alert('Permissions updated successfully');
                permissionsModal.style.display = 'none';
            } catch (error) {
                console.error('Error updating permissions:', error);
                alert('Error updating permissions');
            }
        });
    }
    
    // Modal close handlers for admin modals
    document.querySelectorAll('.modal .close-button').forEach(button => {
        button.onclick = (e) => {
            const modal = e.target.closest('.modal');
            if (modal) modal.style.display = 'none';
        };
    });
    
    window.onclick = (event) => {
        if (event.target === authModal) closeModal(authModal);
        if (event.target === userModal) userModal.style.display = 'none';
        if (event.target === permissionsModal) permissionsModal.style.display = 'none';
    };
    
    // Load admin data when admin page is accessed
    const originalSwitchToPage = switchToPage;
    window.switchToPage = (target) => {
        originalSwitchToPage(target);
        if (target === 'admin') {
            fetchUsers();
        }
    };

    // Initial Load
    refreshAllData();
    
    // Auto-refresh smartlock status every second
    let autoRefreshInterval = null;
    
    const startAutoRefresh = () => {
        if (autoRefreshInterval) {
            clearInterval(autoRefreshInterval);
        }
        
        autoRefreshInterval = setInterval(async () => {
            try {
                // Only refresh smartlocks data, not auths (to avoid disrupting user interactions)
                const fetchOptions = { cache: 'no-cache' };
                const smartlocksRes = await fetch('/api/smartlocks', fetchOptions);
                
                if (smartlocksRes.ok) {
                    const newSmartlocks = await smartlocksRes.json();
                    
                    // Only update if data actually changed to avoid unnecessary re-renders
                    if (JSON.stringify(allSmartlocks) !== JSON.stringify(newSmartlocks)) {
                        allSmartlocks = newSmartlocks;
                        renderSmartlocks();
                    }
                }
            } catch (error) {
                console.error('Auto-refresh error:', error);
                // Don't stop the interval on error, just log it
            }
        }, 1000); // Update every second
    };
    
    const stopAutoRefresh = () => {
        if (autoRefreshInterval) {
            clearInterval(autoRefreshInterval);
            autoRefreshInterval = null;
        }
    };
    
    // Start auto-refresh after initial load
    setTimeout(() => {
        startAutoRefresh();
    }, 2000); // Wait 2 seconds after initial load
    
    // Stop auto-refresh when page becomes hidden (browser tab not active)
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            stopAutoRefresh();
        } else {
            startAutoRefresh();
        }
    });
    
    // Stop auto-refresh when window loses focus
    window.addEventListener('blur', stopAutoRefresh);
    window.addEventListener('focus', startAutoRefresh);
    
    // Also load users immediately if user is admin (after authentication check)
    setTimeout(() => {
        const token = localStorage.getItem('authToken');
        if (token) {
            fetch('/api/verify-token', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data && data.is_admin) {
                    fetchUsers();
                }
            })
            .catch(error => {
                console.error('Error checking admin status for initial user load:', error);
            });
        }
    }, 1000); // Wait 1 second to ensure authentication check is complete
});
