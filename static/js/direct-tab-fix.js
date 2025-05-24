/**
 * Direct Tab Fix
 * This script forcibly adds direct click event handlers to tab buttons.
 */

// Run immediately when loaded
(function() {
  console.log('Direct Tab Fix: Running...');

  // Function to directly switch tabs
  function directTabSwitch(tabId) {
    console.log('Direct Tab Fix: Switching to tab', tabId);
    
    // Get all tab content elements
    const tabContents = document.querySelectorAll('.tab-content');
    
    // Get all tab buttons
    const tabButtons = document.querySelectorAll('.tab-button');
    
    // Hide all tabs first
    tabContents.forEach(tab => {
      tab.style.display = 'none';
      tab.classList.remove('active');
    });
    
    // Deactivate all buttons
    tabButtons.forEach(btn => {
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
      if (tabId === 'workspace' && typeof getAnalysisStatus === 'function') {
        getAnalysisStatus();
      }
      
      return true;
    }
    
    console.error('Direct Tab Fix: Tab not found:', tabId);
    return false;
  }
  
  // Function to apply direct click handlers
  function applyDirectClicks() {
    console.log('Direct Tab Fix: Applying direct click handlers');
    
    // Get all tab buttons
    const tabButtons = document.querySelectorAll('.tab-button');
    console.log('Direct Tab Fix: Found', tabButtons.length, 'tab buttons');
    
    // Apply direct click handlers to each button
    tabButtons.forEach(button => {
      // Get the tab ID
      const tabId = button.getAttribute('data-tab');
      
      // Remove any existing click handlers by cloning the button
      const newButton = button.cloneNode(true);
      button.parentNode.replaceChild(newButton, button);
      
      // Add direct click handler
      newButton.addEventListener('click', function(event) {
        event.preventDefault();
        event.stopPropagation();
        
        console.log('Direct Tab Fix: Button clicked for tab', tabId);
        directTabSwitch(tabId);
      });
      
      // Add inline onclick attribute as a backup
      newButton.setAttribute('onclick', `directTabSwitch('${tabId}'); return false;`);
    });
    
    // Also add the global function
    window.directTabSwitch = directTabSwitch;
    
    // Set the active tab on initial load
    const activeButton = document.querySelector('.tab-button.active');
    if (activeButton) {
      const activeTabId = activeButton.getAttribute('data-tab');
      directTabSwitch(activeTabId);
    } else {
      // Default to first tab if none is active
      const firstButton = document.querySelector('.tab-button');
      if (firstButton) {
        const firstTabId = firstButton.getAttribute('data-tab');
        directTabSwitch(firstTabId);
      }
    }
  }
  
  // Apply the fix when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyDirectClicks);
  } else {
    // DOM is already ready
    applyDirectClicks();
  }
  
  // Also reapply after a short delay to handle any race conditions
  setTimeout(applyDirectClicks, 500);
})(); 