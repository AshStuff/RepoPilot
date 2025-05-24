#!/usr/bin/env python3
import os
import sys
import logging
import argparse

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

# Import models
from models import ConnectedRepository, IssueAnalysis, User, init_app

# Create a minimal app config for MongoDB connection
class MinimalAppConfig:
    def __init__(self):
        self.config = {
            'MONGODB_SETTINGS': {
                'host': 'mongodb://localhost:27017/repopilot'
            }
        }

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Delete repository and related data from MongoDB')
    parser.add_argument('--repo', help='Repository name to delete (can be partial name)', default='junkrepo')
    parser.add_argument('--list', action='store_true', help='List all repositories in the database')
    parser.add_argument('--force', action='store_true', help='Skip confirmation prompt')
    args = parser.parse_args()

    # Initialize MongoDB connection
    logger.info("Connecting to MongoDB...")
    app_config = MinimalAppConfig()
    init_app(app_config)
    
    # If --list flag is provided, list all repositories and exit
    if args.list:
        list_repositories()
        return
    
    repo_name = args.repo
    # Find all repositories matching the name pattern
    logger.info(f"Finding repositories with '{repo_name}' in the name...")
    junkrepos = ConnectedRepository.objects(name__contains=repo_name)
    
    if not junkrepos:
        logger.info(f"No repositories found containing '{repo_name}'")
        return
    
    repo_count = len(junkrepos)
    logger.info(f"Found {repo_count} repositories containing '{repo_name}':")
    for repo in junkrepos:
        logger.info(f"  - {repo.name} (ID: {repo.id})")
    
    # Get all issue analyses for these repositories
    all_analyses = []
    for repo in junkrepos:
        analyses = IssueAnalysis.objects(repository=repo)
        all_analyses.extend(analyses)
        logger.info(f"Repository: {repo.name} has {len(analyses)} issue analyses")
    
    analyses_count = len(all_analyses)
    logger.info(f"Total analyses to delete: {analyses_count}")
    
    # Confirm deletion unless --force is used
    if not args.force:
        confirm = input(f"Are you sure you want to delete {repo_count} repositories and {analyses_count} analyses? (y/n): ")
        if confirm.lower() != 'y':
            logger.info("Deletion cancelled")
            return
    
    # Delete all analyses first (to maintain referential integrity)
    logger.info("Deleting issue analyses...")
    for analysis in all_analyses:
        analysis.delete()
    logger.info(f"Deleted {analyses_count} issue analyses")
    
    # Delete repositories
    logger.info("Deleting repositories...")
    for repo in junkrepos:
        repo_name = repo.name
        repo.delete()
        logger.info(f"Deleted repository: {repo_name}")
    
    logger.info("Successfully deleted all requested repository data")

def list_repositories():
    """List all repositories in the database"""
    repos = ConnectedRepository.objects.all()
    if not repos:
        logger.info("No repositories found in the database")
        return
    
    logger.info(f"Found {len(repos)} repositories:")
    for repo in repos:
        # Count analyses for this repo
        analysis_count = IssueAnalysis.objects(repository=repo).count()
        logger.info(f"  - {repo.name} (ID: {repo.id}) - {analysis_count} analyses")

if __name__ == "__main__":
    main() 