#!/usr/bin/env python
from models import IssueAnalysis, init_app
from flask import Flask
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app and MongoDB connection
app = Flask(__name__)
app.config['MONGODB_SETTINGS'] = {
    'host': 'mongodb://localhost:27017/repopilot'
}
init_app(app)

def clear_analyses(issue_number=None):
    """
    Clear analysis records from MongoDB.
    
    Args:
        issue_number: Optional issue number to clear only specific analyses.
                      If None, all analyses will be cleared.
    """
    with app.app_context():
        if issue_number:
            # Clear analyses for a specific issue number
            count = IssueAnalysis.objects(issue_number=issue_number).delete()
            logger.info(f"Deleted {count} analysis records for issue #{issue_number}")
        else:
            # Clear all analyses
            count = IssueAnalysis.objects.delete()
            logger.info(f"Deleted all {count} analysis records")

if __name__ == "__main__":
    import sys
    
    # Check if an issue number was provided
    if len(sys.argv) > 1:
        try:
            issue_num = int(sys.argv[1])
            clear_analyses(issue_num)
        except ValueError:
            logger.error(f"Invalid issue number: {sys.argv[1]}")
            sys.exit(1)
    else:
        # Clear all analyses if no issue number was provided
        clear_analyses() 