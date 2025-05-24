/**
 * Terminal Functions for Issue Details Page
 */

// Function to initialize real-time updates
function setupRealtimeUpdates() {
  const repoName = document.querySelector('meta[name="repository-name"]').getAttribute('content');
  const issueNumber = document.querySelector('meta[name="issue-number"]').getAttribute('content');
  
  if (!repoName || !issueNumber) {
    console.error('Missing repository name or issue number');
    return;
  }
  
  const eventSource = new EventSource(`/api/issue-updates/${repoName}/${issueNumber}`);

  eventSource.onmessage = function(event) {
    const data = JSON.parse(event.data);
    updateIssueContent(data);
  };

  eventSource.onerror = function(error) {
    console.error('SSE Error:', error);
    eventSource.close();
    // Try to reconnect after 5 seconds
    setTimeout(setupRealtimeUpdates, 5000);
  };
}

// Setup real-time terminal logs
function setupTerminalLogUpdates() {
  const repoName = document.querySelector('meta[name="repository-name"]').getAttribute('content');
  const issueNumber = document.querySelector('meta[name="issue-number"]').getAttribute('content');
  
  if (!repoName || !issueNumber) {
    console.error('Missing repository name or issue number');
    return;
  }
  
  function connectEventSource() {
    // Close any existing connection
    if (window.terminalEventSource) {
      window.terminalEventSource.close();
    }
    
    // Create new connection with cache busting parameter
    const timestamp = new Date().getTime();
    const terminalEventSource = new EventSource(`/api/terminal-logs/${repoName}/${issueNumber}?t=${timestamp}`);
    
    // Track the current analysis status
    let currentAnalysisStatus = 'pending';
    
    // Connection opened
    terminalEventSource.onopen = function() {
      console.log('Terminal SSE connection established');
    };
    
    terminalEventSource.onmessage = function(event) {
      try {
        const data = JSON.parse(event.data);
        
        // Handle new logs
        if (data.logs && data.logs.length > 0) {
          // Clear terminal content if this is the first batch of logs
          const terminalContent = document.getElementById('terminalContent');
          if (terminalContent && terminalContent.dataset.justInitialized === 'true') {
            terminalContent.innerHTML = '';
            terminalContent.dataset.justInitialized = 'false';
          }
          
          // Add each log entry
          data.logs.forEach(log => {
            addLogEntryFromServer(log);
          });
        }
        
        // Handle heartbeat to keep connection alive
        if (data.heartbeat) {
          console.log('Terminal SSE heartbeat received');
        }
        
        // Handle errors
        if (data.error) {
          console.error('Terminal log error:', data.error);
          addLogEntry('Error receiving logs: ' + data.error, 'error');
        }
        
        // Only update the status indicator when the overall status changes
        if (data.status && data.status !== currentAnalysisStatus) {
          if (data.status === 'completed' || data.status === 'failed' || 
            (currentAnalysisStatus === 'completed' || currentAnalysisStatus === 'failed')) {
            updateAnalysisStatusUI(data.status);
          }
          
          // Update the current status
          currentAnalysisStatus = data.status;
        }
      } catch (e) {
        console.error('Error parsing SSE data:', e);
      }
    };
    
    terminalEventSource.onerror = function(error) {
      console.error('Terminal SSE Error:', error);
      
      // Close the connection
      terminalEventSource.close();
      
      // Try to reconnect after 3 seconds
      setTimeout(connectEventSource, 3000);
    };
    
    // Store the event source for cleanup
    window.terminalEventSource = terminalEventSource;
  }
  
  // Initial connection
  connectEventSource();
  
  // As a fallback, also fetch logs directly from the analysis status endpoint
  setTimeout(function() {
    fetch(`/api/analysis-status/${repoName}/${issueNumber}`)
      .then(response => response.json())
      .then(data => {
        if (data.error || !data.analysis || !data.analysis.logs) {
          return;
        }
        
        const terminalContent = document.getElementById('terminalContent');
        if (terminalContent && terminalContent.children.length <= 1) {
          // If terminal is empty or has only one entry, display logs from analysis
          terminalContent.innerHTML = '';
          
          data.analysis.logs.forEach(log => {
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
        }
      })
      .catch(error => {
        console.error('Error fetching analysis status:', error);
      });
  }, 1000);
}

// Function to add a log entry from server data
function addLogEntryFromServer(log) {
  const terminalContent = document.getElementById('terminalContent');
  if (!terminalContent) return;
  
  // Create log entry from server data
  const logEntry = document.createElement('div');
  logEntry.className = 'log-entry';
  
  // Create timestamp span
  const timestampSpan = document.createElement('span');
  timestampSpan.className = 'log-timestamp';
  
  // Format the timestamp from ISO to readable format
  const timestamp = new Date(log.timestamp);
  timestampSpan.textContent = timestamp.toISOString().replace('T', ' ').substr(0, 19);
  
  // Create message span with proper formatting
  const messageSpan = document.createElement('span');
  
  // Basic class with type
  let messageClass = `log-message ${log.type || ''}`;
  
  // Check for separator lines (lots of = characters)
  if (log.message.includes('===================')) {
    messageClass += ' separator';
  }
  
  // Check for section headers
  if (log.message.includes('SYSTEM INFORMATION') || 
    log.message.includes('STARTING CONTAINER') || 
    log.message.includes('CONTAINER CREATED') ||
    log.message.includes('CONTAINER CREATION FAILED')) {
    messageClass += ' section-header';
  }
  
  messageSpan.className = messageClass;
  
  // Apply markdown formatting for long messages
  if (log.message.length > 100 && (log.type === 'info' || log.type === 'success')) {
    messageSpan.innerHTML = marked.parse(log.message);
    messageSpan.classList.add('markdown-formatted');
  } else {
    messageSpan.textContent = log.message;
  }
  
  // Assemble the log entry
  logEntry.appendChild(timestampSpan);
  logEntry.appendChild(messageSpan);
  
  // Add to terminal and scroll to bottom
  terminalContent.appendChild(logEntry);
  terminalContent.scrollTop = terminalContent.scrollHeight;
}

// Function to add a log entry with custom message
function addLogEntry(message, type = '') {
  const terminalContent = document.getElementById('terminalContent');
  if (!terminalContent) return;
  
  const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
  const logEntry = document.createElement('div');
  logEntry.className = 'log-entry';
  
  // Create timestamp span
  const timestampSpan = document.createElement('span');
  timestampSpan.className = 'log-timestamp';
  timestampSpan.textContent = timestamp;
  
  // Create message span with proper formatting
  const messageSpan = document.createElement('span');
  
  // Basic class with type
  let messageClass = `log-message ${type}`;
  
  // Check for separator lines (lots of = characters)
  if (message.includes('===================')) {
    messageClass += ' separator';
  }
  
  // Check for section headers
  if (message.includes('SYSTEM INFORMATION') || 
    message.includes('STARTING CONTAINER') || 
    message.includes('CONTAINER CREATED') ||
    message.includes('CONTAINER CREATION FAILED')) {
    messageClass += ' section-header';
  }
  
  messageSpan.className = messageClass;
  
  // Apply markdown formatting for long messages
  if (message.length > 100 && (type === 'info' || type === 'success')) {
    messageSpan.innerHTML = marked.parse(message);
    messageSpan.classList.add('markdown-formatted');
  } else {
    messageSpan.textContent = message;
  }
  
  // Assemble the log entry
  logEntry.appendChild(timestampSpan);
  logEntry.appendChild(messageSpan);
  
  // Add to terminal and scroll to bottom
  terminalContent.appendChild(logEntry);
  terminalContent.scrollTop = terminalContent.scrollHeight;
}

// Function to update the analysis status indicators
function updateAnalysisStatusUI(status) {
  const loadingSpinner = document.getElementById('loading-spinner');
  const successIndicator = document.getElementById('success-indicator');
  const errorIndicator = document.getElementById('error-indicator');
  
  // Make sure all elements exist before proceeding
  if (!loadingSpinner || !successIndicator || !errorIndicator) {
    console.error('Status indicator elements not found');
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
      addLogEntry('Analysis completed successfully', 'success');
      break;
    
    case 'failed':
    case 'error':
      errorIndicator.classList.remove('hidden');
      addLogEntry('Analysis failed or encountered errors', 'error');
      break;
    
    case 'not_started':
      loadingSpinner.classList.remove('hidden');
      addLogEntry('Starting new analysis...', 'info');
      break;
    
    case 'not_found':
      errorIndicator.classList.remove('hidden');
      addLogEntry('Repository or issue not found', 'error');
      break;
    
    case 'pending':
    case 'in_progress':
    default:
      loadingSpinner.classList.remove('hidden');
      break;
  }
}

// Update the analysis UI function
function updateAnalysisUI(analysis) {
  console.log('Analysis update:', analysis);
  
  if (!analysis) {
    addLogEntry('Waiting for analysis to start...', 'info');
    // Show loading spinner
    updateAnalysisStatusUI('pending');
    return;
  }
  
  // Only update status indicators when the overall analysis status changes
  if (analysis.analysis_status === 'completed' || analysis.analysis_status === 'failed') {
    updateAnalysisStatusUI(analysis.analysis_status);
  } else {
    // For all other statuses, show the spinner
    updateAnalysisStatusUI('in_progress');
  }
  
  if (analysis.analysis_status === 'completed') {
    // Add detailed log entries for all analysis results
    
    // Log branch/tag information if available
    if (analysis.analysis_results && analysis.analysis_results.system_info) {
      const sysInfo = analysis.analysis_results.system_info;
      const isTag = sysInfo.is_tag;
      
      if (isTag && sysInfo.tag) {
        addLogEntry(`🏷️ Tag detected: ${sysInfo.tag}`, 'info');
      } else if (sysInfo.branch) {
        addLogEntry(`🔖 Branch detected: ${sysInfo.branch}`, 'info');
      }
    }
    
    // Log container information
    if (analysis.analysis_results && analysis.analysis_results.container) {
      const container = analysis.analysis_results.container;
      addLogEntry('Container created successfully:', 'success');
      addLogEntry(`Container ID: ${container.container_id || container.id}`, 'info');
      addLogEntry(`Container Name: ${container.container_name || container.name}`, 'info');
      addLogEntry(`Container Status: ${container.status}`, 'info');
      
      // Show branch or tag based on is_tag flag
      if (container.is_tag && container.tag) {
        addLogEntry(`Tag: ${container.tag}`, 'info');
      } else if (container.branch) {
        addLogEntry(`Branch: ${container.branch}`, 'info');
      }
    }
    
    addLogEntry('Analysis complete', 'success');
  } else if (analysis.analysis_status === 'failed') {
    addLogEntry('Analysis failed: ' + analysis.error_message, 'error');
  } else if (analysis.analysis_status === 'pending' || analysis.analysis_status === 'in_progress') {
    addLogEntry('Analysis in progress...', 'info');
  }
}

// Function to update issue content
function updateIssueContent(data) {
  const issue = data.issue;
  const comments = data.comments;

  // Update issue title
  const titleElement = document.querySelector('.issue-main-title h2');
  if (titleElement) {
    titleElement.textContent = issue.title;
  }

  // Update issue status
  const statusIcon = document.querySelector('.issue-status i');
  const statusText = document.querySelector('.issue-status');
  if (statusIcon && statusText) {
    statusIcon.className = `fas ${issue.state === 'open' ? 'fa-exclamation-circle' : 'fa-check-circle'}`;
    statusText.className = `issue-status ${issue.state}`;
    const statusSpan = statusText.querySelector('span');
    if (statusSpan) {
      statusSpan.textContent = issue.state.charAt(0).toUpperCase() + issue.state.slice(1);
    }
  }

  // Update issue body
  const issueBody = document.querySelector('.issue-body');
  if (issueBody && typeof marked === 'function') {
    issueBody.innerHTML = marked(issue.body || '');
  }

  // Update labels
  const labelsContainer = document.querySelector('.issue-labels');
  if (labelsContainer && issue.labels) {
    labelsContainer.innerHTML = issue.labels.map(label => `
      <span class="issue-label" style="background-color: #${label.color}20; color: #${label.color};">
        ${label.name}
      </span>
    `).join('');
  }

  // Update comments
  const commentsSection = document.querySelector('.comments-section');
  if (commentsSection) {
    const commentsTitle = commentsSection.querySelector('h3');
    if (commentsTitle) {
      commentsTitle.textContent = `Comments (${comments.length})`;
    }

    const commentsContainer = document.createElement('div');
    comments.forEach(comment => {
      const commentElement = document.createElement('div');
      commentElement.className = 'comment';
      commentElement.innerHTML = `
        <div class="comment-header">
          <span class="comment-author">${comment.user.login}</span>
          <span class="comment-time">commented ${formatDate(new Date(comment.created_at))}</span>
        </div>
        <div class="comment-body markdown-content">
          ${marked(comment.body || '')}
        </div>
      `;
      commentsContainer.appendChild(commentElement);
    });

    // Replace old comments with new ones
    const oldComments = commentsSection.querySelectorAll('.comment');
    oldComments.forEach(comment => comment.remove());
    commentsSection.appendChild(commentsContainer);
  }
}

// Date formatting helper
function formatDate(date) {
  const now = new Date();
  const diff = now - date;
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 60) return 'just now';
  if (minutes < 60) return `${minutes} minute${minutes !== 1 ? 's' : ''} ago`;
  if (hours < 24) return `${hours} hour${hours !== 1 ? 's' : ''} ago`;
  if (days === 1) return 'yesterday';
  if (days < 7) return `${days} days ago`;

  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  });
}

// Function to get the current analysis status
function getAnalysisStatus() {
  const repoName = document.querySelector('meta[name="repository-name"]').getAttribute('content');
  const issueNumber = document.querySelector('meta[name="issue-number"]').getAttribute('content');
  
  if (!repoName || !issueNumber) {
    console.error('Missing repository name or issue number');
    return;
  }
  
  // Show loading indicator
  const loadingSpinner = document.getElementById('loading-spinner');
  if (loadingSpinner) {
    loadingSpinner.classList.remove('hidden');
  }
  
  // Hide success/error indicators
  const successIndicator = document.getElementById('success-indicator');
  const errorIndicator = document.getElementById('error-indicator');
  if (successIndicator) successIndicator.classList.add('hidden');
  if (errorIndicator) errorIndicator.classList.add('hidden');
  
  // Add status message to terminal
  addLogEntry('Fetching analysis status...', 'info');
  
  // Fetch the current analysis status from the server
  fetch(`/api/analysis-status/${repoName}/${issueNumber}`)
    .then(response => {
      console.log('Analysis status response:', response.status);
      // Handle HTTP errors
      if (!response.ok && response.status !== 200) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      console.log('Analysis status data:', data);
      
      // Check if we got an error response with status 200
      if (data.error) {
        console.warn('Analysis status API returned an error:', data.error);
        
        // If we have an error_message, display it in the terminal
        if (data.error_message) {
          addLogEntry(`API Error: ${data.error_message}`, 'error');
        }
        
        // Update UI based on the error status
        updateAnalysisStatusUI(data.analysis_status || 'error');
        
        // If repository not found, provide instructions
        if (data.error.includes('Repository not found')) {
          addLogEntry('Repository not found. Please go back to dashboard and connect this repository.', 'error');
        }
        
        return;
      }
      
      // Update the UI based on the current status
      if (data && data.analysis_status) {
        updateAnalysisStatusUI(data.analysis_status);
        
        // If analysis is completed, display the results
        if (data.analysis_status === 'completed' && data.analysis_results) {
          updateAnalysisUI(data);
        }
        // If analysis hasn't started yet, trigger it
        else if (data.analysis_status === 'not_started' || data.analysis_status === 'not_found') {
          console.log('Analysis not started, triggering analysis');
          addLogEntry('Analysis not started. Triggering new analysis...', 'info');
          
          // Trigger new analysis
          triggerNewAnalysis();
        }
      } else {
        addLogEntry('Received invalid response from server. Trying to start analysis...', 'warning');
        triggerNewAnalysis();
      }
    })
    .catch(error => {
      console.error('Error getting analysis status:', error);
      // Update UI to show error state
      updateAnalysisStatusUI('error');
      // Add error log
      addLogEntry(`Error fetching analysis status: ${error.message}`, 'error');
      addLogEntry('Attempting to start a new analysis...', 'info');
      
      // Try to trigger a new analysis as fallback
      triggerNewAnalysis();
    });
}

// Function to trigger a new analysis
function triggerNewAnalysis() {
  const repoName = document.querySelector('meta[name="repository-name"]').getAttribute('content');
  const issueNumber = document.querySelector('meta[name="issue-number"]').getAttribute('content');
  
  if (!repoName || !issueNumber) {
    console.error('Missing repository name or issue number');
    return;
  }
  
  fetch(`/api/analyze-issue/${repoName}/${issueNumber}`)
    .then(response => {
      console.log('Trigger analysis response:', response.status);
      if (!response.ok) {
        throw new Error(`Failed to trigger analysis: ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      console.log('Analysis triggered:', data);
      updateAnalysisUI(data);
      addLogEntry('New analysis started successfully', 'success');
    })
    .catch(error => {
      console.error('Error triggering analysis:', error);
      addLogEntry(`Error triggering analysis: ${error.message}`, 'error');
      // Show a more user-friendly message with retry button
      const terminalContent = document.getElementById('terminalContent');
      if (terminalContent) {
        const retryDiv = document.createElement('div');
        retryDiv.className = 'retry-container';
        retryDiv.innerHTML = `
          <div class="log-entry">
            <span class="log-timestamp">${new Date().toISOString().replace('T', ' ').substr(0, 19)}</span>
            <span class="log-message error">Failed to start analysis. GitHub API rate limit may be exceeded.</span>
          </div>
          <div class="log-entry" style="margin-top: 10px;">
            <button onclick="clearAnalysis()" class="retry-button">Retry Analysis</button>
          </div>
        `;
        terminalContent.appendChild(retryDiv);
        terminalContent.scrollTop = terminalContent.scrollHeight;
      }
    });
}

// Function to clean up orphaned Docker containers
function cleanupOrphanedContainers() {
  const repoName = document.querySelector('meta[name="repository-name"]').getAttribute('content');
  const issueNumber = document.querySelector('meta[name="issue-number"]').getAttribute('content');
  
  if (!repoName || !issueNumber) {
    console.error('Missing repository name or issue number');
    return;
  }
  
  // Show confirmation dialog
  if (confirm('Are you sure you want to clean up orphaned Docker containers for this issue?')) {
    // Add log entry
    addLogEntry('Cleaning up orphaned Docker containers...', 'info');
    
    // Make API request to clean up containers
    fetch(`/api/cleanup-containers/${repoName}/${issueNumber}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        addLogEntry(`${data.message}`, 'success');
      } else {
        addLogEntry(`Failed to clean up containers: ${data.error}`, 'error');
      }
    })
    .catch(error => {
      console.error('Error cleaning up containers:', error);
      addLogEntry(`Error cleaning up containers: ${error.message}`, 'error');
    });
  }
}

// Function to clear analysis and restart
function clearAnalysis() {
  const repoName = document.querySelector('meta[name="repository-name"]').getAttribute('content');
  const issueNumber = document.querySelector('meta[name="issue-number"]').getAttribute('content');
  
  if (!repoName || !issueNumber) {
    console.error('Missing repository name or issue number');
    return;
  }
  
  // Close any existing event source before restart
  if (window.terminalEventSource) {
    window.terminalEventSource.close();
    window.terminalEventSource = null;
  }
  
  // Clear the terminal first
  const terminalContent = document.getElementById('terminalContent');
  if (terminalContent) {
    terminalContent.innerHTML = '';
  }
  
  addLogEntry('Clearing previous analysis...', 'info');
  addLogEntry('Clearing MongoDB cache...', 'info');
  
  // Reset status indicators to show loading
  updateAnalysisStatusUI('pending');
  
  // First clear the MongoDB cache for this specific issue
  fetch(`/api/clear-issue-cache/${repoName}/${issueNumber}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    }
  })
  .then(response => {
    if (!response.ok) {
      throw new Error('Failed to clear MongoDB cache');
    }
    return response.json();
  })
  .then(data => {
    if (data.success) {
      addLogEntry('MongoDB cache cleared successfully', 'success');
    } else {
      addLogEntry('Warning: Failed to clear MongoDB cache: ' + data.message, 'warning');
    }
    
    // Now call the API to clear the analysis and delete Docker resources
    return fetch(`/api/clear-analysis-with-docker/${repoName}/${issueNumber}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    });
  })
  .then(response => {
    if (!response.ok) {
      throw new Error('Failed to clear analysis');
    }
    return response.json();
  })
  .then(data => {
    addLogEntry(data.message, 'success');
    
    // Log Docker resource cleanup information if applicable
    if (data.container_deleted) {
      addLogEntry('Docker container deleted successfully', 'success');
    }
    if (data.image_deleted) {
      addLogEntry('Docker image deleted successfully', 'success');
    }
    
    addLogEntry('Starting fresh analysis...', 'info');
    
    // Trigger new analysis
    return fetch(`/api/analyze-issue/${repoName}/${issueNumber}?restart=true`);
  })
  .then(response => {
    if (!response.ok) {
      throw new Error('Failed to trigger analysis');
    }
    return response.json();
  })
  .then(data => {
    console.log('Fresh analysis triggered:', data);
    updateAnalysisUI(data);
    
    // Reconnect to the terminal log updates with a slight delay
    setTimeout(() => {
      setupTerminalLogUpdates();
    }, 1000);
  })
  .catch(error => {
    console.error('Error:', error);
    addLogEntry('Error: ' + error.message, 'error');
  });
}

// Function to clear logs without restarting analysis
function clearLogs() {
  const terminalContent = document.getElementById('terminalContent');
  if (terminalContent) {
    terminalContent.innerHTML = '';
    addLogEntry('Logs cleared', 'info');
    
    // Update the analysis status to show current state
    getAnalysisStatus();
  }
}

// Function to initialize terminal
function initTerminal() {
  // Ensure terminal element exists
  const terminalContent = document.getElementById('terminalContent');
  if (!terminalContent) return;
  
  // Set initialization flag
  terminalContent.dataset.justInitialized = 'true';
  
  // Add initial welcome message
  addLogEntry('Terminal initialized. Ready to display analysis logs.', 'info');
}

// Initialize functions on page load
document.addEventListener('DOMContentLoaded', function() {
  // Initialize terminal
  initTerminal();
  
  // Set up event listeners for window unload
  window.addEventListener('beforeunload', function() {
    if (window.terminalEventSource) {
      window.terminalEventSource.close();
    }
  });
}); 