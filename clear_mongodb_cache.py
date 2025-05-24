#!/usr/bin/env python3
"""
Script to clear MongoDB cache and existing analysis data.
This script can be used to manually clean up the database when needed.
"""

import os
import sys
import logging
from dotenv import load_dotenv
from mongoengine import connect, disconnect
from models import IssueAnalysis, ConnectedRepository, User

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def clear_all_analyses():
    """Clear all issue analyses from the database."""
    try:
        count = IssueAnalysis.objects.count()
        if count > 0:
            logger.info(f"Deleting {count} issue analyses...")
            IssueAnalysis.objects.delete()
            logger.info(f"Successfully deleted {count} issue analyses.")
        else:
            logger.info("No issue analyses found in the database.")
        return count
    except Exception as e:
        logger.error(f"Error deleting issue analyses: {str(e)}")
        return 0

def clear_analysis_for_issue(repo_name, issue_number):
    """Clear analysis for a specific issue."""
    try:
        # Find the repository
        repository = ConnectedRepository.objects(name=repo_name).first()
        if not repository:
            logger.error(f"Repository not found: {repo_name}")
            return False
            
        # Find and delete the analysis
        analysis = IssueAnalysis.objects(
            repository=repository,
            issue_number=issue_number
        ).first()
        
        if analysis:
            analysis_id = str(analysis.id)
            analysis.delete()
            logger.info(f"Deleted analysis (ID: {analysis_id}) for issue #{issue_number} in {repo_name}")
            return True
        else:
            logger.info(f"No analysis found for issue #{issue_number} in {repo_name}")
            return False
    except Exception as e:
        logger.error(f"Error clearing analysis for issue #{issue_number} in {repo_name}: {str(e)}")
        return False

def drop_collection():
    """Drop the issue_analysis collection to clear all cache."""
    try:
        from mongoengine.connection import get_db
        db = get_db()
        if 'issue_analysis' in db.list_collection_names():
            logger.info("Dropping issue_analysis collection to clear cache...")
            db.issue_analysis.drop()
            logger.info("Successfully dropped issue_analysis collection.")
            return True
        else:
            logger.info("issue_analysis collection not found in database.")
            return False
    except Exception as e:
        logger.error(f"Error dropping collection: {str(e)}")
        return False

def main():
    # Load environment variables
    load_dotenv()
    
    # Connect to MongoDB
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/repopilot')
    logger.info(f"Connecting to MongoDB: {mongo_uri}")
    connect(host=mongo_uri)
    
    # Parse command line arguments
    if len(sys.argv) == 1:
        # No arguments, clear all analyses
        logger.info("Clearing all analyses and dropping collection...")
        count = clear_all_analyses()
        drop_collection()
        logger.info(f"Operation completed. Deleted {count} analyses.")
    elif len(sys.argv) == 3:
        # Arguments: repo_name issue_number
        repo_name = sys.argv[1]
        try:
            issue_number = int(sys.argv[2])
            logger.info(f"Clearing analysis for issue #{issue_number} in {repo_name}...")
            success = clear_analysis_for_issue(repo_name, issue_number)
            if success:
                logger.info("Successfully cleared analysis.")
            else:
                logger.warning("No analysis was cleared.")
        except ValueError:
            logger.error("Issue number must be an integer.")
            print("Usage: python clear_mongodb_cache.py [repo_name issue_number]")
    else:
        print("Usage: python clear_mongodb_cache.py [repo_name issue_number]")
        print("Examples:")
        print("  python clear_mongodb_cache.py                # Clear all analyses")
        print("  python clear_mongodb_cache.py owner/repo 42  # Clear analysis for issue #42 in owner/repo")
    
    # Disconnect from MongoDB
    disconnect()

if __name__ == "__main__":
    main() 