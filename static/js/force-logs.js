/**
 * Force Logs Script
 * This script directly fetches and displays logs from the server
 */

(function() {
  console.log('Force Logs: Initializing...');
  
  // Global variables
  let pollingInterval = null;
  let lastLogCount = 0;
  
  // Function to get repository and issue information
  function getRepoInfo() {
    const repoNameMeta = document.querySelector('meta[name="repository-name"]');
    const issueNumberMeta = document.querySelector('meta[name="issue-number"]');
    
    if (!repoNameMeta || !issueNumberMeta) {
      console.error('Force Logs: Missing metadata tags!');
      return null;
    }
    
    return {
      repoName: repoNameMeta.getAttribute('content'),
      issueNumber: issueNumberMeta.getAttribute('content')
    };
  }
  
  // Function to add a log entry to the terminal
  function addLogEntry(message, timestamp, type = 'info') {
    const terminalContent = document.getElementById('terminalContent');
    if (!terminalContent) {
      console.error('Force Logs: Terminal content element not found!');
      return;
    }
    
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    
    const timestampSpan = document.createElement('span');
    timestampSpan.className = 'log-timestamp';
    timestampSpan.textContent = timestamp || new Date().toISOString().replace('T', ' ').substr(0, 19);
    
    const messageSpan = document.createElement('span');
    messageSpan.className = `log-message ${type}`;
    messageSpan.textContent = message;
    
    logEntry.appendChild(timestampSpan);
    logEntry.appendChild(messageSpan);
    
    terminalContent.appendChild(logEntry);
    terminalContent.scrollTop = terminalContent.scrollHeight;
  }
  
  // Function to fetch logs directly from the server
  function fetchLogs() {
    const repoInfo = getRepoInfo();
    if (!repoInfo) return;
    
    const { repoName, issueNumber } = repoInfo;
    
    // Create a Set to track displayed log messages to avoid duplicates if it doesn't exist
    if (!window.displayedLogMessages) {
      window.displayedLogMessages = new Set();
    }
    
    // Fetch analysis status which includes logs
    fetch(`/api/analysis-status/${repoName}/${issueNumber}`)
      .then(response => response.json())
      .then(data => {
        if (data.error) {
          console.error('Force Logs: Error from server:', data.error);
          return;
        }
        
        if (!data.analysis) {
          console.log('Force Logs: No analysis data available');
          return;
        }
        
        // Get logs from the analysis
        const logs = data.analysis.logs || [];
        
        // Process all logs, but only display new ones
        logs.forEach((log, index) => {
          // Create a unique key for this log based on timestamp and message
          const logKey = `${log.timestamp}-${log.message}`;
          
          // Skip if we've already displayed this log
          if (window.displayedLogMessages.has(logKey)) {
            return;
          }
          
          // Mark this log as displayed
          window.displayedLogMessages.add(logKey);
          
          // Add the log entry to the terminal
            const timestamp = new Date(log.timestamp).toISOString().replace('T', ' ').substr(0, 19);
            addLogEntry(log.message, timestamp, log.type || 'info');
          });
          
        // Update last log count for status tracking
          lastLogCount = logs.length;
        
        // Update status indicators based on analysis status
        updateStatusIndicators(data.analysis.analysis_status);
      })
      .catch(error => {
        console.error('Force Logs: Error fetching logs:', error);
      });
  }
  
  // Function to update status indicators
  function updateStatusIndicators(status) {
    const loadingSpinner = document.getElementById('loading-spinner');
    const successIndicator = document.getElementById('success-indicator');
    const errorIndicator = document.getElementById('error-indicator');
    
    if (!loadingSpinner || !successIndicator || !errorIndicator) {
      return;
    }
    
    // Hide all indicators first
    loadingSpinner.classList.add('hidden');
    successIndicator.classList.add('hidden');
    errorIndicator.classList.add('hidden');
    
    // Show the appropriate indicator based on status
    switch(status) {
      case 'completed':
        successIndicator.classList.remove('hidden');
        break;
      
      case 'failed':
      case 'error':
        errorIndicator.classList.remove('hidden');
        break;
      
      default:
        loadingSpinner.classList.remove('hidden');
        break;
    }
  }
  
  // Function to start polling for logs
  function startPolling() {
    if (pollingInterval) {
      clearInterval(pollingInterval);
    }
    
    // Reset log count
    lastLogCount = 0;
    
    // Add initial log entry
    addLogEntry('Force logs activated - polling for logs every 2 seconds...', null, 'info');
    
    // Fetch logs immediately
    fetchLogs();
    
    // Set up polling interval (every 2 seconds)
    pollingInterval = setInterval(fetchLogs, 2000);
    
    console.log('Force Logs: Started polling');
  }
  
  // Function to stop polling
  function stopPolling() {
    if (pollingInterval) {
      clearInterval(pollingInterval);
      pollingInterval = null;
      console.log('Force Logs: Stopped polling');
    }
  }
  
  // Function to add the force logs button
  function addForceLogsButton() {
    const terminalHeader = document.querySelector('.terminal-header > div:last-child');
    if (!terminalHeader) return;
    
    const forceLogsButton = document.createElement('button');
    forceLogsButton.className = 'mini-button';
    forceLogsButton.title = 'Force display logs';
    forceLogsButton.innerHTML = '<i class="fas fa-sync"></i> Force Logs';
    forceLogsButton.addEventListener('click', function() {
      // Toggle polling
      if (pollingInterval) {
        stopPolling();
        this.innerHTML = '<i class="fas fa-sync"></i> Force Logs';
        addLogEntry('Force logs deactivated', null, 'info');
      } else {
        startPolling();
        this.innerHTML = '<i class="fas fa-stop"></i> Stop Force Logs';
      }
    });
    
    terminalHeader.appendChild(forceLogsButton);
  }
  
  // Function to handle workspace tab activation
  function onWorkspaceTabActivated() {
    const workspaceTab = document.getElementById('workspace');
    if (workspaceTab && workspaceTab.classList.contains('active')) {
      // Start polling when workspace tab is activated
      if (!pollingInterval) {
        startPolling();
      }
    } else {
      // Stop polling when workspace tab is deactivated
      stopPolling();
    }
  }
  
  // Function to override tab switching functions
  function overrideTabSwitching() {
    if (typeof window.switchTab === 'function') {
      const originalSwitchTab = window.switchTab;
      window.switchTab = function(tabId) {
        const result = originalSwitchTab(tabId);
        
        // Check if workspace tab is active
        if (tabId === 'workspace') {
          setTimeout(onWorkspaceTabActivated, 100);
        }
        
        return result;
      };
    }
    
    if (typeof window.directTabSwitch === 'function') {
      const originalDirectTabSwitch = window.directTabSwitch;
      window.directTabSwitch = function(tabId) {
        const result = originalDirectTabSwitch(tabId);
        
        // Check if workspace tab is active
        if (tabId === 'workspace') {
          setTimeout(onWorkspaceTabActivated, 100);
        }
        
        return result;
      };
    }
  }
  
  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      addForceLogsButton();
      overrideTabSwitching();
      
      // Check if workspace tab is already active
      const workspaceTab = document.getElementById('workspace');
      if (workspaceTab && workspaceTab.classList.contains('active')) {
        // Start polling automatically
        startPolling();
      }
    });
  } else {
    // DOM is already ready
    addForceLogsButton();
    overrideTabSwitching();
    
    // Check if workspace tab is already active
    const workspaceTab = document.getElementById('workspace');
    if (workspaceTab && workspaceTab.classList.contains('active')) {
      // Start polling automatically
      startPolling();
    }
  }
})(); 