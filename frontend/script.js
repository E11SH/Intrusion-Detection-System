// ===== Configuration =====
const API_BASE_URL = 'http://localhost:5000/api';
const REFRESH_INTERVAL = 3000; // 3 seconds
let refreshTimer = null;

// ===== DOM Elements =====
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const lastUpdate = document.getElementById('lastUpdate');
const totalAttacks = document.getElementById('totalAttacks');
const mostCommonType = document.getElementById('mostCommonType');
const topAttacker = document.getElementById('topAttacker');
const alertsTableBody = document.getElementById('alertsTableBody');
const themeToggle = document.getElementById('themeToggle');
const clearBtn = document.getElementById('clearBtn');
const testBtn = document.getElementById('testBtn');
const testArpBtn = document.getElementById('testArpBtn');
const viewArpBtn = document.getElementById('viewArpBtn');
const refreshBtn = document.getElementById('refreshBtn');

// ===== Theme Management =====
function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
}

// ===== API Functions =====
async function fetchStatus() {
    try {
        const response = await fetch(`${API_BASE_URL}/status`);
        if (!response.ok) throw new Error('Failed to fetch status');
        const data = await response.json();
        updateStatus(data.status);
        return true;
    } catch (error) {
        console.error('Error fetching status:', error);
        updateStatus('error');
        return false;
    }
}

async function fetchAlerts() {
    try {
        const response = await fetch(`${API_BASE_URL}/alerts/recent`);
        if (!response.ok) throw new Error('Failed to fetch alerts');
        const data = await response.json();
        updateAlertsTable(data.alerts);
        updateLastUpdate();
        return data.alerts;
    } catch (error) {
        console.error('Error fetching alerts:', error);
        return [];
    }
}

async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE_URL}/stats`);
        if (!response.ok) throw new Error('Failed to fetch stats');
        const data = await response.json();
        updateStats(data);
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

async function clearAllAlerts() {
    if (!confirm('Are you sure you want to clear all alerts?')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/clear`, {
            method: 'POST'
        });
        if (!response.ok) throw new Error('Failed to clear alerts');
        
        // Refresh data
        await fetchData();
        
        // Show success feedback
        showNotification('Alerts cleared successfully', 'success');
    } catch (error) {
        console.error('Error clearing alerts:', error);
        showNotification('Failed to clear alerts', 'error');
    }
}

async function createTestAlert() {
    try {
        const response = await fetch(`${API_BASE_URL}/test`, {
            method: 'POST'
        });
        if (!response.ok) throw new Error('Failed to create test alert');
        
        // Refresh data immediately
        await fetchData();
        
        showNotification('Test alert created!', 'success');
    } catch (error) {
        console.error('Error creating test alert:', error);
        showNotification('Failed to create test alert', 'error');
    }
}

async function testArpSpoofing() {
    try {
        const response = await fetch(`${API_BASE_URL}/test/arp`, {
            method: 'POST'
        });
        if (!response.ok) throw new Error('Failed to create test ARP alert');
        
        const data = await response.json();
        
        // Refresh data immediately
        await fetchData();
        
        if (data.status === 'no IPs in ARP cache yet') {
            showNotification('No IPs in ARP cache yet. Wait for network traffic.', 'info');
        } else {
            showNotification('Test ARP spoofing alert created!', 'success');
        }
    } catch (error) {
        console.error('Error creating test ARP alert:', error);
        showNotification('Failed to create test ARP alert', 'error');
    }
}

async function viewArpCache() {
    try {
        const response = await fetch(`${API_BASE_URL}/arp/list`);
        if (!response.ok) throw new Error('Failed to fetch ARP cache');
        
        const data = await response.json();
        
        if (data.total_entries === 0) {
            showNotification('ARP cache is empty. Wait for network traffic.', 'info');
            return;
        }
        
        // Create a modal-like display
        const arpList = Object.entries(data.arp_cache)
            .map(([ip, mac]) => `${ip} → ${mac}`)
            .join('\n');
        
        alert(`ARP Cache (${data.total_entries} entries):\n\n${arpList}`);
        
    } catch (error) {
        console.error('Error fetching ARP cache:', error);
        showNotification('Failed to fetch ARP cache', 'error');
    }
}

// ===== Update Functions =====
function updateStatus(status) {
    if (status === 'running') {
        statusDot.classList.add('active');
        statusDot.classList.remove('error');
        statusText.textContent = 'IDS Running';
    } else if (status === 'error') {
        statusDot.classList.add('error');
        statusDot.classList.remove('active');
        statusText.textContent = 'Connection Error';
    } else {
        statusDot.classList.remove('active', 'error');
        statusText.textContent = 'IDS Stopped';
    }
}

function updateAlertsTable(alerts) {
    if (!alerts || alerts.length === 0) {
        alertsTableBody.innerHTML = `
            <tr class="no-data">
                <td colspan="5">No alerts detected. System is monitoring...</td>
            </tr>
        `;
        return;
    }
    
    const rows = alerts.map(alert => {
        const timestamp = new Date(alert.timestamp);
        const formattedTime = timestamp.toLocaleString();
        
        return `
            <tr>
                <td>
                    <span class="severity-badge ${alert.severity}">
                        ${alert.severity}
                    </span>
                </td>
                <td>
                    <span class="type-badge">${alert.type}</span>
                </td>
                <td>
                    <span class="ip-address">${alert.source_ip}</span>
                </td>
                <td>${alert.details || '-'}</td>
                <td>
                    <span class="timestamp">${formattedTime}</span>
                </td>
            </tr>
        `;
    }).join('');
    
    alertsTableBody.innerHTML = rows;
}

function updateStats(stats) {
    // Update total attacks
    totalAttacks.textContent = stats.total_attacks || 0;
    
    // Update most common attack type
    if (stats.by_type && Object.keys(stats.by_type).length > 0) {
        const types = Object.entries(stats.by_type);
        const mostCommon = types.reduce((a, b) => a[1] > b[1] ? a : b);
        mostCommonType.textContent = `${mostCommon[0]} (${mostCommon[1]})`;
    } else {
        mostCommonType.textContent = '-';
    }
    
    // Update top attacker
    if (stats.most_common_attacker) {
        topAttacker.textContent = stats.most_common_attacker.ip;
    } else {
        topAttacker.textContent = '-';
    }
}

function updateLastUpdate() {
    const now = new Date();
    const timeStr = now.toLocaleTimeString();
    lastUpdate.textContent = timeStr;
}

// ===== Notification System =====
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 16px 24px;
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        box-shadow: var(--shadow-lg);
        z-index: 1000;
        animation: slideInRight 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// ===== Data Fetching =====
async function fetchData() {
    const statusOk = await fetchStatus();
    if (statusOk) {
        await Promise.all([
            fetchAlerts(),
            fetchStats()
        ]);
    }
}

function startAutoRefresh() {
    // Clear existing timer
    if (refreshTimer) {
        clearInterval(refreshTimer);
    }
    
    // Start new timer
    refreshTimer = setInterval(fetchData, REFRESH_INTERVAL);
}

function stopAutoRefresh() {
    if (refreshTimer) {
        clearInterval(refreshTimer);
        refreshTimer = null;
    }
}

// ===== Manual Refresh with Animation =====
async function manualRefresh() {
    const icon = refreshBtn.querySelector('svg');
    icon.style.animation = 'spin 0.6s ease';
    
    await fetchData();
    
    setTimeout(() => {
        icon.style.animation = '';
    }, 600);
}

// ===== Event Listeners =====
themeToggle.addEventListener('click', toggleTheme);
clearBtn.addEventListener('click', clearAllAlerts);
testBtn.addEventListener('click', createTestAlert);
testArpBtn.addEventListener('click', testArpSpoofing);
viewArpBtn.addEventListener('click', viewArpCache);
refreshBtn.addEventListener('click', manualRefresh);

// Handle visibility change (pause refresh when tab is hidden)
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        stopAutoRefresh();
    } else {
        fetchData();
        startAutoRefresh();
    }
});

// ===== Initialization =====
function init() {
    initTheme();
    fetchData();
    startAutoRefresh();
}

// ===== Add CSS Animation Styles =====
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    @keyframes spin {
        from {
            transform: rotate(0deg);
        }
        to {
            transform: rotate(360deg);
        }
    }
`;
document.head.appendChild(style);

// Start the application
init();
