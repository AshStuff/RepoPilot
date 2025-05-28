#!/usr/bin/env python
from models import CiPrAnalysis, init_app # Import CiPrAnalysis
from flask import Flask
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app and MongoDB connection
app = Flask(__name__)
app.config['MONGODB_SETTINGS'] = {
    'host': 'mongodb://localhost:27017/repopilot' # Ensure this matches your DB URI
}
init_app(app)

def clear_ci_pr_analyses(pr_number=None):
    """
    Clear CI PR analysis records from MongoDB.
    
    Args:
        pr_number: Optional PR number to clear only specific CI PR analyses.
                   If None, all CI PR analyses will be cleared.
    """
    with app.app_context():
        if pr_number:
            # Clear CI PR analyses for a specific PR number
            # Assuming you might want to clear by repository as well if PR numbers are not globally unique
            # For now, just by pr_number. If you have multiple repos, you might need repo_name too.
            count = CiPrAnalysis.objects(pr_number=pr_number).delete()
            logger.info(f"Deleted {count} CI PR analysis records for PR #{pr_number}")
        else:
            # Clear all CI PR analyses
            count = CiPrAnalysis.objects.delete()
            logger.info(f"Deleted all {count} CI PR analysis records")

if __name__ == "__main__":
    import sys
    
    # Check if a PR number was provided
    if len(sys.argv) > 1:
        try:
            pr_num_arg = int(sys.argv[1])
            clear_ci_pr_analyses(pr_num_arg)
        except ValueError:
            logger.error(f"Invalid PR number: {sys.argv[1]}")
            sys.exit(1)
    else:
        # Clear all CI PR analyses if no PR number was provided
        clear_ci_pr_analyses() 