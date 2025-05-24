// Debounce setup for search
let debounceTimer;

if (typeof window.displayedLogMessages === 'undefined') {
    window.displayedLogMessages = new Set();
}

function fetchAnalysisStatus(repoName, issueNumber) {
    console.log(`Fetching analysis status for ${repoName}/${issueNumber} at ${new Date().toLocaleTimeString()}`); // Log when fetch is called
    fetch(`/api/analysis-status/${repoName}/${issueNumber}`)
        .then(response => {
            if (!response.ok) {
                console.error(`Error fetching status: ${response.status} ${response.statusText}`);
                return response.text().then(text => { throw new Error(`Server error: ${text || 'Unknown error'}`); });
            }
            return response.json();
        })
        .then(data => {
            console.log('Received analysis data:', data); // Log received data
            const statusElement = document.getElementById('analysisStatus');
            const logsContainer = document.getElementById('analysisLogs');
            const llmSummaryContainer = document.getElementById('llmSummaryContainer');
            const llmSolutionsContainer = document.getElementById('llmSolutionsContainer');
            const llmCodeAnalysisContainer = document.getElementById('llmCodeAnalysisContainer');


            if (statusElement) {
                statusElement.textContent = data.analysis_status || 'Status not available';
            }

            if (logsContainer && data.logs) {
                let newLogsAdded = false;
                data.logs.forEach(log => {
                    // To ensure even identical consecutive log messages are displayed if they are new,
                    // we might need a more sophisticated check than just string content if logs can be truly identical but separate entries.
                    // However, for typical logging with timestamps or varying content, Set is usually fine.
                    if (!window.displayedLogMessages.has(log)) {
                        const logEntry = document.createElement('p');
                        logEntry.className = 'log-entry'; // Add class for potential styling
                        logEntry.textContent = log;
                        logsContainer.appendChild(logEntry);
                        window.displayedLogMessages.add(log);
                        newLogsAdded = true;
                    }
                });
                if (newLogsAdded) {
                    console.log('New logs appended to the UI.'); // Log when new logs are added
                    logsContainer.scrollTop = logsContainer.scrollHeight; // Scroll to bottom
                } else {
                    // console.log('No new logs to display.'); // Optional: log if no new logs
                }
            }

            if (data.analysis_status === 'completed' || data.analysis_status === 'error' || data.analysis_status === 'output_processed') {
                // If analysis is done, no need to poll as frequently or at all.
                // For now, we'll let it continue polling but could clear the interval here.
                // clearInterval(pollingInterval); // Example: stop polling
                console.log(`Analysis status is ${data.analysis_status}, polling continues but could be stopped or slowed.`);
            }
        })
        .catch(error => {
            console.error('Error in fetchAnalysisStatus:', error);
            const statusElement = document.getElementById('analysisStatus');
            if (statusElement) {
                // statusElement.textContent = 'Error fetching status.'; // Avoid stopping interval here.
            }
            // Don't clear the interval on a single failed fetch, allow it to retry.
        });
}

// Ensure this script part runs after the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize displayedLogMessages for the current page context
    // This is already at the top, but ensure it's initialized before first use.
    if (typeof window.displayedLogMessages === 'undefined') {
        window.displayedLogMessages = new Set();
    }

    const issueDetailsContainer = document.getElementById('issueDetailsContainer');
    const clearLogsButton = document.getElementById('clearLogsButton');
    const analyzeButton = document.getElementById('analyzeIssueButton'); // Assuming this ID for the analyze button
    let pollingInterval; // Define pollingInterval here

    if (issueDetailsContainer) {
        const repoName = issueDetailsContainer.dataset.repoName;
        const issueNumber = issueDetailsContainer.dataset.issueNumber;

        if (repoName && issueNumber) {
            // Initial fetch
            fetchAnalysisStatus(repoName, issueNumber);
            // Poll for updates
            pollingInterval = setInterval(() => fetchAnalysisStatus(repoName, issueNumber), 3000); // Poll every 3 seconds
            console.log(`Polling started for ${repoName}/${issueNumber} every 3 seconds.`);
        } else {
            console.error("Could not extract repoName or issueNumber for polling.");
        }
    }
}); 