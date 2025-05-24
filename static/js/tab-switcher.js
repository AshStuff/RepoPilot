/**
 * Simple Tab Switcher
 * A standalone utility to handle tab switching
 */

(function() {
  // Function to switch tabs
  function switchTab(tabId) {
    console.log('Tab switcher: switching to', tabId);
    
    // Hide all tab content
    document.querySelectorAll('.tab-content').forEach(function(tab) {
      tab.style.display = 'none';
      tab.classList.remove('active');
    });
    
    // Deactivate all tab buttons
    document.querySelectorAll('.tab-button').forEach(function(btn) {
      btn.classList.remove('active');
    });
    
    // Show the selected tab
    const selectedTab = document.getElementById(tabId);
    if (selectedTab) {
      selectedTab.style.display = 'block';
      selectedTab.classList.add('active');
      
      // Activate the corresponding button
      const button = document.querySelector(`.tab-button[data-tab="${tabId}"]`);
      if (button) {
        button.classList.add('active');
      }
      
      // Special handling for workspace tab
      if (tabId === 'workspace') {
        if (typeof setupTerminalLogUpdates === 'function') {
          setupTerminalLogUpdates();
        }
        if (typeof getAnalysisStatus === 'function') {
          getAnalysisStatus();
        }
      }
      
      console.log('Tab switched successfully to', tabId);
      return true;
    } else {
      console.error('Tab content not found:', tabId);
      return false;
    }
  }
  
  // Function to initialize tabs
  function initTabs() {
    console.log('Initializing tab switcher');
    
    // Add click handlers to all tab buttons
    document.querySelectorAll('.tab-button').forEach(function(button) {
      button.addEventListener('click', function(e) {
        e.preventDefault();
        const tabId = this.getAttribute('data-tab');
        if (tabId) {
          switchTab(tabId);
        }
      });
    });
    
    // Make sure the active tab is visible
    const activeButton = document.querySelector('.tab-button.active');
    if (activeButton) {
      const activeTabId = activeButton.getAttribute('data-tab');
      switchTab(activeTabId);
    } else {
      // Default to the first tab if none is active
      const firstButton = document.querySelector('.tab-button');
      if (firstButton) {
        const firstTabId = firstButton.getAttribute('data-tab');
        switchTab(firstTabId);
      }
    }
    
    console.log('Tab switcher initialized');
  }
  
  // Initialize on DOM ready
  document.addEventListener('DOMContentLoaded', initTabs);
  
  // Expose the switchTab function globally
  window.switchTab = switchTab;
})(); 