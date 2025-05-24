#!/usr/bin/env python3
"""
Script to clear ALL issue analyses from MongoDB and associated Docker resources,
or a specific issue if --issue-number is provided.
"""

import os
import sys
import logging
from dotenv import load_dotenv
from mongoengine import connect, disconnect
from models import IssueAnalysis, ConnectedRepository
import mongoengine
import json
import subprocess
import argparse # Added argparse

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def clear_docker_resources_for_issue(issue_number: int):
    """Clear Docker containers and images related to a specific issue number."""
    logger.info(f"Attempting to clear Docker resources for issue #{issue_number}...")
    
    container_name_pattern = f"repopilot-issue-{issue_number}"
    image_name_pattern = f"repopilot-issue-{issue_number}"

    try:
        # Clear containers
        result_containers = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name={container_name_pattern}", "--format", "{{.ID}} {{.Names}}"],
            capture_output=True, text=True, check=False
        )
        containers = [c for c in result_containers.stdout.strip().split('\n') if c]
        if containers:
            logger.info(f"Found {len(containers)} Docker containers for issue #{issue_number}.")
            for container_line in containers:
                container_id = container_line.split()[0]
                container_name = ' '.join(container_line.split()[1:])
                logger.info(f"Removing container: {container_name} ({container_id})")
                subprocess.run(["docker", "rm", "-f", container_id], check=True)
        else:
            logger.info(f"No Docker containers found for issue #{issue_number} with pattern '{container_name_pattern}'.")

        # Clear images
        result_images = subprocess.run(
            ["docker", "images", "--filter", f"reference={image_name_pattern}", "--format", "{{.ID}} {{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, check=False
        )
        images = [i for i in result_images.stdout.strip().split('\n') if i]
        if images:
            logger.info(f"Found {len(images)} Docker images for issue #{issue_number}.")
            for image_line in images:
                image_id = image_line.split()[0]
                image_name = ' '.join(image_line.split()[1:])
                logger.info(f"Removing image: {image_name} ({image_id})")
                subprocess.run(["docker", "rmi", "-f", image_id], check=True)
        else:
            logger.info(f"No Docker images found for issue #{issue_number} with pattern '{image_name_pattern}'.")
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing Docker command during cleanup for issue #{issue_number}: {e}")
    except Exception as e:
        logger.error(f"Generic error during Docker resource cleanup for issue #{issue_number}: {e}")

def clear_all_docker_resources():
    """Clear all Docker containers and images potentially related to any issue analysis."""
    logger.info("Attempting to clear all repopilot-related Docker resources...")
            
    # Clear containers with 'repopilot-' in their name
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=repopilot-", "--format", "{{.ID}} {{.Names}}"],
            capture_output=True, text=True, check=False # Don't fail if no matches
        )
        containers = [c for c in result.stdout.strip().split('\n') if c]
        if containers:
            logger.info(f"Found {len(containers)} potentially related Docker containers.")
            for container_line in containers:
                container_id = container_line.split()[0]
                container_name = ' '.join(container_line.split()[1:])
                logger.info(f"Removing container: {container_name} ({container_id})")
                subprocess.run(["docker", "rm", "-f", container_id], check=True)
        else:
            logger.info("No Docker containers with 'repopilot-' prefix found.")

        # Clear images with 'repopilot-issue-' or 'repopilot-debug-' in their reference
        result = subprocess.run(
            ["docker", "images", "--filter", "reference=repopilot-issue-*", "--filter", "reference=repopilot-debug-*", "--format", "{{.ID}} {{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, check=False # Don't fail if no matches
        )
        images = [i for i in result.stdout.strip().split('\n') if i]
        if images:
            logger.info(f"Found {len(images)} potentially related Docker images.")
            for image_line in images:
                image_id = image_line.split()[0]
                image_name = ' '.join(image_line.split()[1:])
                logger.info(f"Removing image: {image_name} ({image_id})")
                subprocess.run(["docker", "rmi", "-f", image_id], check=True)
        else:
            logger.info("No Docker images with 'repopilot-issue-*' or 'repopilot-debug-*' prefix found.")
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing Docker command during cleanup: {e}")
    except Exception as e:
        logger.error(f"Generic error during Docker resource cleanup: {e}")

def clear_specific_issue_analysis(issue_number: int):
    """Clear analysis data for a specific issue from MongoDB."""
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/repopilot')
    logger.info(f"Connecting to MongoDB: {mongo_uri}")
    connect(host=mongo_uri)

    analysis = IssueAnalysis.objects(issue_number=issue_number).first()
    
    if not analysis:
        logger.info(f"No analysis found in the database for issue #{issue_number}.")
        disconnect()
        return

    logger.info(f"Found analysis for issue #{issue_number} (ID: {analysis.id}). Deleting...")
    analysis.delete()
    logger.info(f"Successfully deleted analysis for issue #{issue_number}.")
    disconnect()

def clear_all_issue_analyses():
    """Clear ALL analysis data from MongoDB."""
    # Connect to MongoDB
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/repopilot')
    logger.info(f"Connecting to MongoDB: {mongo_uri}")
    connect(host=mongo_uri)
    
    analyses = list(IssueAnalysis.objects())
    
    if not analyses:
        logger.info("No analyses found in the database.")
        disconnect()
        return
    
    count = len(analyses)
    logger.info(f"Found {count} analyses to delete.")
    
    # IssueAnalysis.objects().delete() # More efficient way to delete all
    # logger.info(f"Successfully deleted {count} analyses using bulk delete.")

    # Or if you need to log each one:
    for analysis_obj in analyses: # Renamed variable to avoid conflict
        logger.info(f"Deleting analysis ID: {analysis_obj.id}, Repo: {analysis_obj.repository.name if analysis_obj.repository else 'N/A'}, Issue: {analysis_obj.issue_number}, Status: {analysis_obj.analysis_status}")
        analysis_obj.delete()
    logger.info(f"Successfully deleted {count} analyses by iterating.")
    disconnect()

if __name__ == "__main__":
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="Clear issue analyses from MongoDB and Docker.")
    parser.add_argument("--issue-number", type=int, help="Specific issue number to clear.")
    args = parser.parse_args()

    if args.issue_number:
        logger.info(f"Starting process to clear analysis and Docker resources for issue #{args.issue_number}...")
        clear_docker_resources_for_issue(args.issue_number)
        clear_specific_issue_analysis(args.issue_number)
        logger.info(f"Analysis and Docker resources for issue #{args.issue_number} have been cleared.")
    else:
        logger.info("Starting process to clear ALL issue analyses and Docker resources...")
        clear_all_docker_resources()
        clear_all_issue_analyses()
        logger.info("All issue analyses and potentially related Docker resources have been cleared.") 