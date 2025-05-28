class WebSocketHandler {
    constructor(url) {
        this.url = url;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000; // Start with 1 second
        this.lastHeartbeat = Date.now();
        this.heartbeatTimeout = 35000; // 35 seconds (slightly longer than server's 30s)
        this.connect();
        this.startHeartbeatCheck();
    }

    connect() {
        this.ws = new WebSocket(this.url);

        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.reconnectAttempts = 0;
            this.reconnectDelay = 1000;
            this.lastHeartbeat = Date.now();
        };

        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            if (data.type === 'heartbeat') {
                this.lastHeartbeat = Date.now();
                return;
            }

            if (data.type === 'log') {
                // Handle log message
                const logElement = document.getElementById('log-container');
                if (logElement) {
                    const logEntry = document.createElement('div');
                    logEntry.className = `log-entry log-${data.log_type}`;
                    logEntry.textContent = `${data.content}`;
                    logElement.appendChild(logEntry);
                    logElement.scrollTop = logElement.scrollHeight;
                }
            }
        };

        this.ws.onclose = () => {
            console.log('WebSocket closed');
            this.reconnect();
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    reconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.log('Max reconnection attempts reached');
            return;
        }

        this.reconnectAttempts++;
        this.reconnectDelay *= 2; // Exponential backoff

        console.log(`Attempting to reconnect in ${this.reconnectDelay}ms (attempt ${this.reconnectAttempts})`);
        setTimeout(() => this.connect(), this.reconnectDelay);
    }

    startHeartbeatCheck() {
        setInterval(() => {
            const timeSinceLastHeartbeat = Date.now() - this.lastHeartbeat;
            if (timeSinceLastHeartbeat > this.heartbeatTimeout) {
                console.log('Heartbeat timeout, reconnecting...');
                this.ws.close();
            }
        }, 1000); // Check every second
    }
}

// Initialize WebSocket connection when the page loads
document.addEventListener('DOMContentLoaded', () => {
    const wsUrl = `ws://${window.location.host}/ws`;
    window.wsHandler = new WebSocketHandler(wsUrl);
}); 