/**
 * One-time Fix Script
 * This script runs once when the page loads to ensure logs are displayed
 */

(function() {
  console.log('One-time Fix: Running...');
  
  // Function to run after a short delay to ensure DOM is fully loaded
  function runFix() {
    console.log('One-time Fix: Starting fix...');
    
    // Get repository and issue information
    const repoNameMeta = document.querySelector('meta[name="repository-name"]');
    const issueNumberMeta = document.querySelector('meta[name="issue-number"]');
    
    if (!repoNameMeta || !issueNumberMeta) {
      console.error('One-time Fix: Missing repository name or issue number metadata!');
      return;
    }
    
    const repoName = repoNameMeta.getAttribute('content');
    const issueNumber = issueNumberMeta.getAttribute('content');
    
    console.log(`One-time Fix: Found metadata - Repo: ${repoName}, Issue: ${issueNumber}`);
    
    // Function to add a log entry
    function addFixLogEntry(message) {
      const terminalContent = document.getElementById('terminalContent');
      if (!terminalContent) {
        console.error('One-time Fix: Terminal content element not found!');
        return;
      }
      
      const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
      const logEntry = document.createElement('div');
      logEntry.className = 'log-entry';
      
      const timestampSpan = document.createElement('span');
      timestampSpan.className = 'log-timestamp';
      timestampSpan.textContent = timestamp;
      
      const messageSpan = document.createElement('span');
      messageSpan.className = 'log-message info';
      messageSpan.textContent = `[ONE-TIME FIX] ${message}`;
      
      logEntry.appendChild(timestampSpan);
      logEntry.appendChild(messageSpan);
      
      terminalContent.appendChild(logEntry);
      terminalContent.scrollTop = terminalContent.scrollHeight;
    }
    
    // Make sure the terminal content exists and has at least one entry
    const terminalContent = document.getElementById('terminalContent');
    if (terminalContent && terminalContent.children.length === 0) {
      addFixLogEntry('Initializing terminal...');
    }
    
    // Fetch logs directly from the analysis status endpoint
    fetch(`/api/analysis-status/${repoName}/${issueNumber}`)
      .then(response => response.json())
      .then(data => {
        console.log('One-time Fix: Analysis status response:', data);
        
        if (data.error) {
          console.error('One-time Fix: Error from server:', data.error);
          addFixLogEntry(`Error: ${data.error}`);
          return;
        }
        
        if (!data.analysis) {
          console.log('One-time Fix: No analysis data available');
          addFixLogEntry('No analysis data available. Try clicking the "Restart" button.');
          return;
        }
        
        // Check if we have logs
        const logs = data.analysis.logs || [];
        if (logs.length > 0) {
          console.log(`One-time Fix: Found ${logs.length} logs`);
          addFixLogEntry(`Found ${logs.length} logs. Displaying...`);
          
          // Clear terminal content
          terminalContent.innerHTML = '';
          
          // Add each log entry
          logs.forEach(log => {
            const logEntry = document.createElement('div');
            logEntry.className = 'log-entry';
            
            const timestampSpan = document.createElement('span');
            timestampSpan.className = 'log-timestamp';
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
          
          // Add final message
          addFixLogEntry('Logs displayed successfully!');
        } else {
          console.log('One-time Fix: No logs found');
          addFixLogEntry('No logs found. Try clicking the "Restart" button to trigger a new analysis.');
        }
      })
      .catch(error => {
        console.error('One-time Fix: Error fetching analysis status:', error);
        addFixLogEntry(`Error fetching logs: ${error.message}`);
      });
  }
  
  // Run the fix after a short delay
  setTimeout(runFix, 500);
})(); 