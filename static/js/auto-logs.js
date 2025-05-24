/**
 * Auto Logs
 * This script automatically loads and displays issue analyzer logs
 */

(function() {
  console.log('Auto Logs: Initializing...');
  
  // Function to display logs from the analysis data
  function displayLogs(analysisData) {
    const terminalContent = document.getElementById('terminalContent');
    if (!terminalContent) {
      console.error('Auto Logs: Terminal content element not found!');
      return;
    }
    
    // Create a Set to track displayed log messages to avoid duplicates
    if (!window.displayedLogMessages) {
      window.displayedLogMessages = new Set();
    }
    
    // Get logs from the analysis
    const logs = analysisData.logs || [];
    
    if (logs.length === 0) {
      // Only add a "no logs" message if the terminal is empty
      if (terminalContent.children.length === 0) {
      const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
      const logEntry = document.createElement('div');
      logEntry.className = 'log-entry';
      
      const timestampSpan = document.createElement('span');
      timestampSpan.className = 'log-timestamp';
      timestampSpan.textContent = timestamp;
      
      const messageSpan = document.createElement('span');
      messageSpan.className = 'log-message warning';
      messageSpan.textContent = 'No logs found in the analysis. Try restarting the analysis.';
      
      logEntry.appendChild(timestampSpan);
      logEntry.appendChild(messageSpan);
      
      terminalContent.appendChild(logEntry);
      }
      return;
    }
    
    // Display each log that hasn't been displayed yet
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
      
      // Format the timestamp
      try {
        const timestamp = new Date(log.timestamp);
        timestampSpan.textContent = timestamp.toISOString().replace('T', ' ').substr(0, 19);
      } catch (e) {
        timestampSpan.textContent = log.timestamp || 'Unknown';
      }
      
      const messageSpan = document.createElement('span');
      messageSpan.className = `log-message ${log.type || ''}`;
      messageSpan.textContent = log.message || 'No message';
      
      logEntry.appendChild(timestampSpan);
      logEntry.appendChild(messageSpan);
      
      terminalContent.appendChild(logEntry);
    });
    
    // Scroll to bottom
    terminalContent.scrollTop = terminalContent.scrollHeight;
  }
  
  // Function to load logs automatically
  function loadLogs() {
    // Get repository and issue information
    const repoNameMeta = document.querySelector('meta[name="repository-name"]');
    const issueNumberMeta = document.querySelector('meta[name="issue-number"]');
    
    if (!repoNameMeta || !issueNumberMeta) {
      console.error('Auto Logs: Missing metadata tags!');
      return;
    }
    
    const repoName = repoNameMeta.getAttribute('content');
    const issueNumber = issueNumberMeta.getAttribute('content');
    
    console.log(`Auto Logs: Loading logs for ${repoName}/${issueNumber}`);
    
    // Fetch logs from the analysis status endpoint
    fetch(`/api/analysis-status/${repoName}/${issueNumber}`)
      .then(response => {
        if (!response.ok) {
          throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }
        return response.json();
      })
      .then(data => {
        console.log('Auto Logs: Response received', data);
        
        if (data.error) {
          console.error('Auto Logs: Error from server:', data.error);
          return;
        }
        
        if (!data.analysis) {
          console.error('Auto Logs: No analysis data available');
          return;
        }
        
        // Display logs from the analysis
        displayLogs(data.analysis);
        
        // Set up polling for log updates
        setupLogPolling(repoName, issueNumber, data.analysis.logs ? data.analysis.logs.length : 0);
      })
      .catch(error => {
        console.error('Auto Logs: Error fetching logs:', error);
      });
  }
  
  // Set up polling for log updates
  function setupLogPolling(repoName, issueNumber, initialLogCount) {
    let lastLogCount = initialLogCount || 0;
    
    // Poll every 3 seconds
    const pollingInterval = setInterval(() => {
      // Only poll if the workspace tab is active
      const workspaceTab = document.getElementById('workspace');
      if (!workspaceTab || !workspaceTab.classList.contains('active')) {
        return;
      }
      
      fetch(`/api/analysis-status/${repoName}/${issueNumber}`)
        .then(response => response.json())
        .then(data => {
          if (data.error || !data.analysis) {
            return;
          }
          
          const logs = data.analysis.logs || [];
          
          // If we have new logs, update the display
          if (logs.length > lastLogCount) {
            console.log(`Auto Logs: Found ${logs.length - lastLogCount} new logs`);
            displayLogs(data.analysis);
            lastLogCount = logs.length;
          }
        })
        .catch(error => {
          console.error('Auto Logs: Error polling for logs:', error);
        });
    }, 3000);
    
    // Store the interval ID for cleanup
    window.autoLogsPollingInterval = pollingInterval;
  }
  
  // Function to handle workspace tab activation
  function onWorkspaceTabActivated() {
    console.log('Auto Logs: Workspace tab activated');
    loadLogs();
  }
  
  // Function to override tab switching functions
  function overrideTabSwitching() {
    if (typeof window.switchTab === 'function') {
      const originalSwitchTab = window.switchTab;
      window.switchTab = function(tabId) {
        const result = originalSwitchTab(tabId);
        
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
      overrideTabSwitching();
      
      // Check if we're already on the workspace tab
      const workspaceTab = document.getElementById('workspace');
      if (workspaceTab && workspaceTab.classList.contains('active')) {
        setTimeout(onWorkspaceTabActivated, 500);
      }
    });
  } else {
    // DOM is already ready
    overrideTabSwitching();
    
    // Check if we're already on the workspace tab
    const workspaceTab = document.getElementById('workspace');
    if (workspaceTab && workspaceTab.classList.contains('active')) {
      setTimeout(onWorkspaceTabActivated, 500);
    }
  }
})(); 