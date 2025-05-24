/**
 * Tab Fixer - Fixes tab switching issues in the issue details page
 */

// Function to ensure tab content elements exist
function fixTabs() {
  console.log("Tab Fixer running...");
  
  // Find all tab buttons
  const tabButtons = document.querySelectorAll('.tab-button');
  console.log("Found tab buttons:", tabButtons.length);
  
  // Find all tab contents
  const tabContents = document.querySelectorAll('.tab-content');
  console.log("Found tab contents:", tabContents.length);
  
  // Apply direct click handlers to each tab button
  tabButtons.forEach(button => {
    // Remove existing click handlers
    const newButton = button.cloneNode(true);
    button.parentNode.replaceChild(newButton, button);
    
    // Add new click handler
    newButton.addEventListener('click', function(event) {
      event.preventDefault();
      const tabId = this.getAttribute('data-tab');
      console.log("Tab clicked:", tabId);
      
      // Hide all tab contents
      tabContents.forEach(content => {
        content.style.display = 'none';
        content.classList.remove('active');
      });
      
      // Deactivate all tab buttons
      tabButtons.forEach(btn => {
        btn.classList.remove('active');
      });
      
      // Show the selected tab content
      const targetTab = document.getElementById(tabId);
      if (targetTab) {
        targetTab.style.display = 'block';
        targetTab.classList.add('active');
        this.classList.add('active');
        console.log("Activated tab:", tabId);
      } else {
        console.error("Tab content not found:", tabId);
      }
    });
  });
  
  // Ensure the active tab is properly displayed
  const activeButton = document.querySelector('.tab-button.active');
  if (activeButton) {
    const activeTabId = activeButton.getAttribute('data-tab');
    const activeTab = document.getElementById(activeTabId);
    
    if (activeTab) {
      tabContents.forEach(content => {
        content.style.display = 'none';
        content.classList.remove('active');
      });
      
      activeTab.style.display = 'block';
      activeTab.classList.add('active');
      console.log("Initial active tab set to:", activeTabId);
    }
  }
}

// Run the tab fixer when the page loads
document.addEventListener('DOMContentLoaded', fixTabs);

// Also provide a global function that can be called manually
window.fixTabSwitching = fixTabs; 