#!/usr/bin/env python3
"""
Test script for clear_issue_analysis.py
This is a simple test to verify that the script works correctly.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the function to test
from clear_issue_analysis import clear_analysis_for_issue

class TestClearIssueAnalysis(unittest.TestCase):
    """Test cases for clear_issue_analysis.py"""
    
    @patch('clear_issue_analysis.ConnectedRepository')
    @patch('clear_issue_analysis.IssueAnalysis')
    def test_clear_analysis_for_issue(self, mock_issue_analysis, mock_repository):
        """Test that clear_analysis_for_issue works correctly"""
        # Setup mock repository
        mock_repo = MagicMock()
        mock_repository.objects.return_value.first.return_value = mock_repo
        
        # Setup mock analysis
        mock_analysis = MagicMock()
        mock_analysis.id = "test_id"
        mock_analysis.logs = ["log1", "log2"]
        mock_issue_analysis.objects.return_value.first.return_value = mock_analysis
        
        # Call the function
        result = clear_analysis_for_issue("test/repo", 42)
        
        # Verify the function worked correctly
        self.assertTrue(result)
        mock_repository.objects.assert_called_once()
        mock_issue_analysis.objects.assert_called_once()
        mock_analysis.delete.assert_called_once()
        
    @patch('clear_issue_analysis.ConnectedRepository')
    @patch('clear_issue_analysis.IssueAnalysis')
    def test_clear_analysis_no_repo(self, mock_issue_analysis, mock_repository):
        """Test that clear_analysis_for_issue handles missing repository"""
        # Setup mock repository
        mock_repository.objects.return_value.first.return_value = None
        
        # Call the function
        result = clear_analysis_for_issue("test/repo", 42)
        
        # Verify the function returned False
        self.assertFalse(result)
        mock_repository.objects.assert_called_once()
        mock_issue_analysis.objects.assert_not_called()
        
    @patch('clear_issue_analysis.ConnectedRepository')
    @patch('clear_issue_analysis.IssueAnalysis')
    def test_clear_analysis_no_analysis(self, mock_issue_analysis, mock_repository):
        """Test that clear_analysis_for_issue handles missing analysis"""
        # Setup mock repository
        mock_repo = MagicMock()
        mock_repository.objects.return_value.first.return_value = mock_repo
        
        # Setup mock analysis
        mock_issue_analysis.objects.return_value.first.return_value = None
        
        # Call the function
        result = clear_analysis_for_issue("test/repo", 42)
        
        # Verify the function returned False
        self.assertFalse(result)
        mock_repository.objects.assert_called_once()
        mock_issue_analysis.objects.assert_called_once()

if __name__ == "__main__":
    unittest.main() 