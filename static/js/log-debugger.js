/**
 * Log Debugger Script
 * This script helps debug issues with log display in the workspace tab
 */

(function() {
  console.log('Log Debugger: Initializing...');
  
  // Function to check if repository name and issue number are available
  function checkMetadata() {
    const repoNameMeta = document.querySelector('meta[name="repository-name"]');
    const issueNumberMeta = document.querySelector('meta[name="issue-number"]');
    
    console.log('Log Debugger: Checking metadata...');
    
    if (!repoNameMeta || !issueNumberMeta) {
      console.error('Log Debugger: Missing metadata tags!');
      addDebugMessage('ERROR: Missing repository name or issue number metadata tags!');
      return false;
    }
    
    const repoName = repoNameMeta.getAttribute('content');
    const issueNumber = issueNumberMeta.getAttribute('content');
    
    console.log(`Log Debugger: Found metadata - Repo: ${repoName}, Issue: ${issueNumber}`);
    addDebugMessage(`Repository: ${repoName}, Issue: ${issueNumber}`);
    
    return { repoName, issueNumber };
  }
  
  // Function to add debug message to terminal
  function addDebugMessage(message, type = 'debug') {
    const terminalContent = document.getElementById('terminalContent');
    if (!terminalContent) {
      console.error('Log Debugger: Terminal content element not found!');
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
    messageSpan.textContent = `[DEBUGGER] ${message}`;
    
    logEntry.appendChild(timestampSpan);
    logEntry.appendChild(messageSpan);
    
    terminalContent.appendChild(logEntry);
    terminalContent.scrollTop = terminalContent.scrollHeight;
  }
  
  // Function to test direct API call
  function testDirectApiCall() {
    const metadata = checkMetadata();
    if (!metadata) return;
    
    const { repoName, issueNumber } = metadata;
    addDebugMessage(`Testing direct API call to /api/analysis-status/${repoName}/${issueNumber}...`);
    
    fetch(`/api/analysis-status/${repoName}/${issueNumber}`)
      .then(response => response.json())
      .then(data => {
        console.log('Log Debugger: Analysis status response:', data);
        addDebugMessage(`Analysis status: ${JSON.stringify(data)}`, 'info');
        
        // If we have an analysis, try to get logs
        if (data.analysis) {
          testLogsApi(repoName, issueNumber);
        }
      })
      .catch(error => {
        console.error('Log Debugger: Error fetching analysis status:', error);
        addDebugMessage(`Error fetching analysis status: ${error.message}`, 'error');
      });
  }
  
  // Function to test logs API
  function testLogsApi(repoName, issueNumber) {
    addDebugMessage(`Testing SSE connection to /api/terminal-logs/${repoName}/${issueNumber}...`);
    
    // Create a new EventSource connection
    const debugEventSource = new EventSource(`/api/terminal-logs/${repoName}/${issueNumber}`);
    
    // Connection opened
    debugEventSource.onopen = function() {
      console.log('Log Debugger: SSE connection established');
      addDebugMessage('SSE connection established', 'success');
    };
    
    // Listen for messages
    debugEventSource.onmessage = function(event) {
      try {
        const data = JSON.parse(event.data);
        console.log('Log Debugger: Received SSE data:', data);
        
        if (data.connected) {
          addDebugMessage(`Connected to log stream: ${data.stream_id}`, 'success');
        }
        
        if (data.logs && data.logs.length > 0) {
          addDebugMessage(`Received ${data.logs.length} new log entries`, 'success');
          
          // Display the first log message as an example
          if (data.logs[0]) {
            const firstLog = data.logs[0];
            addDebugMessage(`Example log: ${firstLog.message.substring(0, 50)}...`, 'info');
          }
        }
        
        if (data.heartbeat) {
          addDebugMessage(`Heartbeat received (${data.count || 'n/a'})`, 'info');
        }
        
        if (data.error) {
          addDebugMessage(`Error: ${data.error}`, 'error');
        }
      } catch (e) {
        console.error('Log Debugger: Error parsing SSE data:', e);
        addDebugMessage(`Error parsing SSE data: ${e.message}`, 'error');
      }
    };
    
    // Handle errors
    debugEventSource.onerror = function(error) {
      console.error('Log Debugger: SSE Error:', error);
      addDebugMessage('SSE connection error', 'error');
      
      // Close the connection
      debugEventSource.close();
    };
    
    // Store the event source for cleanup
    window.debugEventSource = debugEventSource;
    
    // Close the connection after 30 seconds to prevent resource leaks
    setTimeout(() => {
      if (window.debugEventSource) {
        window.debugEventSource.close();
        addDebugMessage('Debug SSE connection closed after timeout', 'info');
      }
    }, 30000);
  }
  
  // Function to run all tests
  function runDebugTests() {
    addDebugMessage('Starting log debugger tests...', 'info');
    
    // Check if terminal functions are available
    if (typeof setupTerminalLogUpdates === 'function') {
      addDebugMessage('Terminal functions are available', 'success');
    } else {
      addDebugMessage('Terminal functions are NOT available', 'error');
    }
    
    // Check metadata
    const metadata = checkMetadata();
    if (metadata) {
      // Test direct API call
      testDirectApiCall();
    }
  }
  
  // Add a debug button to the terminal header
  function addDebugButton() {
    const terminalHeader = document.querySelector('.terminal-header > div:last-child');
    if (!terminalHeader) return;
    
    const debugButton = document.createElement('button');
    debugButton.className = 'mini-button';
    debugButton.title = 'Run log debugger';
    debugButton.innerHTML = '<i class="fas fa-bug"></i> Debug Logs';
    debugButton.addEventListener('click', runDebugTests);
    
    terminalHeader.appendChild(debugButton);
  }
  
  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', addDebugButton);
  } else {
    // DOM is already ready
    addDebugButton();
  }
})(); 