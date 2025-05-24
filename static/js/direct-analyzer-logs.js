/**
 * Direct Analyzer Logs
 * This script directly fetches and displays issue analyzer logs from the database
 */

(function() {
  console.log('Direct Analyzer Logs: Initializing...');
  
  // Create a direct fetch button that will be added to the page
  function createDirectFetchButton() {
    const button = document.createElement('button');
    button.id = 'directFetchLogsBtn';
    button.className = 'mini-button';
    button.style.backgroundColor = '#ff5500';
    button.style.color = 'white';
    button.style.fontWeight = 'bold';
    button.style.padding = '8px 16px';
    button.style.fontSize = '14px';
    button.style.margin = '10px';
    button.style.cursor = 'pointer';
    button.innerHTML = '⚡ FETCH ANALYZER LOGS ⚡';
    button.title = 'Directly fetch analyzer logs from database';
    
    return button;
  }
  
  // Add the button to the page
  function addDirectFetchButton() {
    // First try adding it to the terminal header
    const terminalHeader = document.querySelector('.terminal-header');
    if (terminalHeader) {
      const button = createDirectFetchButton();
      terminalHeader.appendChild(button);
      button.addEventListener('click', fetchAnalyzerLogs);
      return;
    }
    
    // If terminal header doesn't exist, add it to the workspace tab content
    const workspaceTab = document.getElementById('workspace');
    if (workspaceTab) {
      const button = createDirectFetchButton();
      workspaceTab.prepend(button);
      button.addEventListener('click', fetchAnalyzerLogs);
      return;
    }
    
    // If neither exists, add it to the body
    const button = createDirectFetchButton();
    document.body.prepend(button);
    button.addEventListener('click', fetchAnalyzerLogs);
  }
  
  // Function to display a log message
  function displayMessage(message, type = 'info') {
    const terminalContent = document.getElementById('terminalContent');
    if (!terminalContent) {
      console.error('Direct Analyzer Logs: Terminal content element not found!');
      alert('Terminal content element not found! ' + message);
      return;
    }
    
    const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    
    const timestampSpan = document.createElement('span');
    timestampSpan.className = 'log-timestamp';
    timestampSpan.textContent = timestamp;
    
    const messageSpan = document.createElement('span');
    messageSpan.className = `log-message ${type}`;
    messageSpan.textContent = `[DIRECT] ${message}`;
    
    logEntry.appendChild(timestampSpan);
    logEntry.appendChild(messageSpan);
    
    terminalContent.appendChild(logEntry);
    terminalContent.scrollTop = terminalContent.scrollHeight;
  }
  
  // Function to fetch analyzer logs
  function fetchAnalyzerLogs() {
    // Get repository and issue information
    const repoNameMeta = document.querySelector('meta[name="repository-name"]');
    const issueNumberMeta = document.querySelector('meta[name="issue-number"]');
    
    if (!repoNameMeta || !issueNumberMeta) {
      console.error('Direct Analyzer Logs: Missing metadata tags!');
      alert('Missing repository name or issue number metadata!');
      return;
    }
    
    const repoName = repoNameMeta.getAttribute('content');
    const issueNumber = issueNumberMeta.getAttribute('content');
    
    console.log(`Direct Analyzer Logs: Fetching logs for ${repoName}/${issueNumber}`);
    displayMessage(`Fetching analyzer logs for ${repoName}/${issueNumber}...`);
    
    // Create a Set to track displayed log messages to avoid duplicates if it doesn't exist
    if (!window.displayedLogMessages) {
      window.displayedLogMessages = new Set();
    }
    
    // Fetch logs from the analysis status endpoint
    fetch(`/api/analysis-status/${repoName}/${issueNumber}`)
      .then(response => {
        if (!response.ok) {
          throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }
        return response.json();
      })
      .then(data => {
        console.log('Direct Analyzer Logs: Response received', data);
        
        if (data.error) {
          displayMessage(`Error: ${data.error}`, 'error');
          return;
        }
        
        if (!data.analysis) {
          displayMessage('No analysis data available. Try clicking the "Restart" button to trigger a new analysis.', 'warning');
          return;
        }
        
        // Display analysis status
        displayMessage(`Analysis status: ${data.analysis.analysis_status}`, 'info');
        
        // Get logs from the analysis
        const logs = data.analysis.logs || [];
        
        if (logs.length === 0) {
          displayMessage('No logs found in the analysis. Try restarting the analysis.', 'warning');
          return;
        }
        
        // Display log count
        displayMessage(`Found ${logs.length} logs. Displaying new logs...`, 'success');
        
        const terminalContent = document.getElementById('terminalContent');
        if (!terminalContent) {
          console.error('Direct Analyzer Logs: Terminal content element not found!');
          return;
        }
        
        // Count new logs
        let newLogCount = 0;
        
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
          newLogCount++;
          
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
        
        // Final message
        displayMessage(`Successfully displayed ${newLogCount} new logs!`, 'success');
      })
      .catch(error => {
        console.error('Direct Analyzer Logs: Error fetching logs:', error);
        displayMessage(`Error fetching logs: ${error.message}`, 'error');
      });
  }
  
  // Function to create a floating button
  function createFloatingButton() {
    const button = document.createElement('button');
    button.id = 'floatingFetchLogsBtn';
    button.style.position = 'fixed';
    button.style.bottom = '20px';
    button.style.right = '20px';
    button.style.zIndex = '9999';
    button.style.backgroundColor = '#ff5500';
    button.style.color = 'white';
    button.style.fontWeight = 'bold';
    button.style.padding = '10px 20px';
    button.style.fontSize = '16px';
    button.style.border = 'none';
    button.style.borderRadius = '5px';
    button.style.boxShadow = '0 2px 5px rgba(0,0,0,0.3)';
    button.style.cursor = 'pointer';
    button.innerHTML = '⚡ FETCH ANALYZER LOGS ⚡';
    button.title = 'Directly fetch analyzer logs from database';
    
    button.addEventListener('mouseenter', function() {
      this.style.backgroundColor = '#ff7700';
    });
    
    button.addEventListener('mouseleave', function() {
      this.style.backgroundColor = '#ff5500';
    });
    
    button.addEventListener('click', fetchAnalyzerLogs);
    
    return button;
  }
  
  // Add a floating button to the page
  function addFloatingButton() {
    const button = createFloatingButton();
    document.body.appendChild(button);
  }
  
  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      addDirectFetchButton();
      addFloatingButton();
      
      // Check if we're on the workspace tab and fetch logs automatically
      const workspaceTab = document.getElementById('workspace');
      if (workspaceTab && workspaceTab.classList.contains('active')) {
        // Wait a bit to make sure everything is loaded
        setTimeout(fetchAnalyzerLogs, 1000);
      }
    });
  } else {
    // DOM is already ready
    addDirectFetchButton();
    addFloatingButton();
    
    // Check if we're on the workspace tab and fetch logs automatically
    const workspaceTab = document.getElementById('workspace');
    if (workspaceTab && workspaceTab.classList.contains('active')) {
      // Wait a bit to make sure everything is loaded
      setTimeout(fetchAnalyzerLogs, 1000);
    }
  }
  
  // Override tab switching functions to fetch logs when workspace tab is activated
  if (typeof window.switchTab === 'function') {
    const originalSwitchTab = window.switchTab;
    window.switchTab = function(tabId) {
      const result = originalSwitchTab(tabId);
      
      if (tabId === 'workspace') {
        setTimeout(fetchAnalyzerLogs, 500);
      }
      
      return result;
    };
  }
  
  if (typeof window.directTabSwitch === 'function') {
    const originalDirectTabSwitch = window.directTabSwitch;
    window.directTabSwitch = function(tabId) {
      const result = originalDirectTabSwitch(tabId);
      
      if (tabId === 'workspace') {
        setTimeout(fetchAnalyzerLogs, 500);
      }
      
      return result;
    };
  }
})(); 