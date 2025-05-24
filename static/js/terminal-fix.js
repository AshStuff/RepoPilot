/**
 * Terminal Fix Script
 * This script fixes issues with terminal log display
 */

(function() {
  console.log('Terminal Fix: Initializing...');
  
  // Function to ensure the terminal is properly initialized
  function ensureTerminalInitialized() {
    const terminalContent = document.getElementById('terminalContent');
    if (!terminalContent) {
      console.error('Terminal Fix: Terminal content element not found!');
      return false;
    }
    
    // Add an initial log entry if the terminal is empty
    if (terminalContent.children.length === 0) {
      const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
      const logEntry = document.createElement('div');
      logEntry.className = 'log-entry';
      
      const timestampSpan = document.createElement('span');
      timestampSpan.className = 'log-timestamp';
      timestampSpan.textContent = timestamp;
      
      const messageSpan = document.createElement('span');
      messageSpan.className = 'log-message info';
      messageSpan.textContent = 'Terminal initialized by terminal-fix.js';
      
      logEntry.appendChild(timestampSpan);
      logEntry.appendChild(messageSpan);
      
      terminalContent.appendChild(logEntry);
      console.log('Terminal Fix: Added initial log entry');
    }
    
    return true;
  }
  
  // Function to manually fetch and display logs
  function fetchAndDisplayLogs() {
    const repoNameMeta = document.querySelector('meta[name="repository-name"]');
    const issueNumberMeta = document.querySelector('meta[name="issue-number"]');
    
    if (!repoNameMeta || !issueNumberMeta) {
      console.error('Terminal Fix: Missing repository name or issue number metadata!');
      return;
    }
    
    const repoName = repoNameMeta.getAttribute('content');
    const issueNumber = issueNumberMeta.getAttribute('content');
    
    console.log(`Terminal Fix: Fetching logs for ${repoName}/${issueNumber}`);
    
    // Fetch the analysis status first
    fetch(`/api/analysis-status/${repoName}/${issueNumber}`)
      .then(response => response.json())
      .then(data => {
        console.log('Terminal Fix: Analysis status response:', data);
        
        // If we have an analysis with logs, display them
        if (data.analysis && data.analysis.logs && data.analysis.logs.length > 0) {
          displayLogs(data.analysis.logs);
        } else {
          console.log('Terminal Fix: No logs found in analysis');
          
          // Add a message to the terminal
          const terminalContent = document.getElementById('terminalContent');
          if (terminalContent) {
            const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
            const logEntry = document.createElement('div');
            logEntry.className = 'log-entry';
            
            const timestampSpan = document.createElement('span');
            timestampSpan.className = 'log-timestamp';
            timestampSpan.textContent = timestamp;
            
            const messageSpan = document.createElement('span');
            messageSpan.className = 'log-message warning';
            messageSpan.textContent = 'No logs found. Try clicking the "Restart" button to trigger a new analysis.';
            
            logEntry.appendChild(timestampSpan);
            logEntry.appendChild(messageSpan);
            
            terminalContent.appendChild(logEntry);
          }
        }
      })
      .catch(error => {
        console.error('Terminal Fix: Error fetching analysis status:', error);
      });
  }
  
  // Function to display logs in the terminal
  function displayLogs(logs) {
    const terminalContent = document.getElementById('terminalContent');
    if (!terminalContent) return;
    
    // Create a Set to track displayed log messages to avoid duplicates
    if (!window.displayedLogMessages) {
      window.displayedLogMessages = new Set();
    }
    
    // Add each log entry that hasn't been displayed yet
    logs.forEach(log => {
      // Create a unique key for this log based on timestamp and message
      const logKey = `${log.timestamp}-${log.message}`;
      
      // Skip if we've already displayed this log
      if (window.displayedLogMessages.has(logKey)) {
        return;
      }
      
      // Mark this log as displayed
      window.displayedLogMessages.add(logKey);
      
      const logEntry = document.createElement('div');
      logEntry.className = 'log-entry';
      
      const timestampSpan = document.createElement('span');
      timestampSpan.className = 'log-timestamp';
      
      // Format the timestamp from ISO to readable format
      const timestamp = new Date(log.timestamp);
      timestampSpan.textContent = timestamp.toISOString().replace('T', ' ').substr(0, 19);
      
      const messageSpan = document.createElement('span');
      messageSpan.className = `log-message ${log.type || ''}`;
      messageSpan.textContent = log.message;
      
      logEntry.appendChild(timestampSpan);
      logEntry.appendChild(messageSpan);
      
      terminalContent.appendChild(logEntry);
    });
    
    // Scroll to bottom
    terminalContent.scrollTop = terminalContent.scrollHeight;
    console.log('Terminal Fix: Displayed', logs.length, 'log entries');
  }
  
  // Function to fix terminal updates
  function fixTerminalUpdates() {
    if (typeof setupTerminalLogUpdates === 'function') {
      console.log('Terminal Fix: Calling setupTerminalLogUpdates() again');
      setupTerminalLogUpdates();
    } else {
      console.error('Terminal Fix: setupTerminalLogUpdates function not found');
    }
  }
  
  // Function to run when workspace tab is activated
  function onWorkspaceTabActivated() {
    console.log('Terminal Fix: Workspace tab activated');
    
    // Ensure terminal is initialized
    if (ensureTerminalInitialized()) {
      // Fix terminal updates
      fixTerminalUpdates();
      
      // Fetch and display logs
      fetchAndDisplayLogs();
    }
  }
  
  // Function to override the tab switching function
  function overrideTabSwitching() {
    if (typeof window.switchTab === 'function') {
      console.log('Terminal Fix: Overriding switchTab function');
      
      const originalSwitchTab = window.switchTab;
      window.switchTab = function(tabId) {
        const result = originalSwitchTab(tabId);
        
        // If switching to workspace tab, run our fix
        if (tabId === 'workspace') {
          setTimeout(onWorkspaceTabActivated, 100);
        }
        
        return result;
      };
    }
    
    if (typeof window.directTabSwitch === 'function') {
      console.log('Terminal Fix: Overriding directTabSwitch function');
      
      const originalDirectTabSwitch = window.directTabSwitch;
      window.directTabSwitch = function(tabId) {
        const result = originalDirectTabSwitch(tabId);
        
        // If switching to workspace tab, run our fix
        if (tabId === 'workspace') {
          setTimeout(onWorkspaceTabActivated, 100);
        }
        
        return result;
      };
    }
  }
  
  // Function to clear all logs and reset tracking
  function clearAllLogs() {
    // Clear the terminal content
    const terminalContent = document.getElementById('terminalContent');
    if (terminalContent) {
      terminalContent.innerHTML = '';
    }
    
    // Reset the log tracking
    window.displayedLogMessages = new Set();
    
    // Add a message indicating logs were cleared
    const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    
    const timestampSpan = document.createElement('span');
    timestampSpan.className = 'log-timestamp';
    timestampSpan.textContent = timestamp;
    
    const messageSpan = document.createElement('span');
    messageSpan.className = 'log-message info';
    messageSpan.textContent = 'Logs cleared';
    
    logEntry.appendChild(timestampSpan);
    logEntry.appendChild(messageSpan);
    
    terminalContent.appendChild(logEntry);
    console.log('Terminal Fix: Cleared all logs');
  }
  
  // Function to add a clear logs button
  function addClearLogsButton() {
    const terminalHeader = document.querySelector('.terminal-header > div:last-child');
    if (!terminalHeader) return;
    
    const clearLogsButton = document.createElement('button');
    clearLogsButton.className = 'mini-button';
    clearLogsButton.title = 'Clear logs';
    clearLogsButton.innerHTML = '<i class="fas fa-trash"></i> Clear Logs';
    clearLogsButton.addEventListener('click', clearAllLogs);
    
    terminalHeader.appendChild(clearLogsButton);
  }
  
  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      overrideTabSwitching();
      addClearLogsButton();
      
      // Check if we're already on the workspace tab
      const workspaceTab = document.getElementById('workspace');
      if (workspaceTab && workspaceTab.classList.contains('active')) {
        onWorkspaceTabActivated();
      }
    });
  } else {
    // DOM is already ready
    overrideTabSwitching();
    addClearLogsButton();
    
    // Check if we're already on the workspace tab
    const workspaceTab = document.getElementById('workspace');
    if (workspaceTab && workspaceTab.classList.contains('active')) {
      onWorkspaceTabActivated();
    }
  }
})(); 