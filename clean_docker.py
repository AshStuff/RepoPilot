#!/usr/bin/env python3
import subprocess
import json
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_docker_sudo():
    """Check if Docker requires sudo."""
    try:
        subprocess.run(["docker", "info"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return False
    except (subprocess.SubprocessError, FileNotFoundError):
        try:
            subprocess.run(["sudo", "-n", "docker", "info"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info("Using sudo for Docker commands")
            return True
        except:
            logger.error("Cannot access Docker even with sudo. Please check Docker installation.")
            return True

def get_docker_containers(use_sudo):
    """Get a list of all Docker containers."""
    try:
        docker_cmd = ["sudo", "docker"] if use_sudo else ["docker"]
        cmd = docker_cmd + ["ps", "-a", "--format", "{{json .}}"]
        
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Parse JSON output
        containers = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    container_data = json.loads(line)
                    containers.append(container_data)
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse JSON: {line}")
        
        return containers
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get Docker containers: {e.stderr}")
        return []

def get_docker_images(use_sudo):
    """Get a list of all Docker images."""
    try:
        # Get list of images in JSON format
        docker_cmd = ["sudo", "docker"] if use_sudo else ["docker"]
        cmd = docker_cmd + ["image", "ls", "--format", "{{json .}}"]
        
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Parse JSON output
        images = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    image_data = json.loads(line)
                    images.append(image_data)
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse JSON: {line}")
        
        return images
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get Docker images: {e.stderr}")
        return []

def stop_and_remove_container(container_id, use_sudo):
    """Stop and remove a Docker container."""
    try:
        docker_cmd = ["sudo", "docker"] if use_sudo else ["docker"]
        
        # First stop the container
        stop_cmd = docker_cmd + ["stop", container_id]
        subprocess.run(stop_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Then remove it
        rm_cmd = docker_cmd + ["rm", "-f", container_id]
        subprocess.run(rm_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        logger.info(f"Stopped and removed container: {container_id}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to stop/remove container {container_id}: {e.stderr}")
        return False

def delete_docker_image(image_id, use_sudo):
    """Delete a Docker image by ID."""
    try:
        docker_cmd = ["sudo", "docker"] if use_sudo else ["docker"]
        cmd = docker_cmd + ["rmi", "-f", image_id]
        
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.info(f"Deleted image: {image_id}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to delete image {image_id}: {e.stderr}")
        return False

def main():
    """Main function to delete all Docker images except repopilot/base."""
    logger.info("Starting Docker cleanup...")
    
    # Check if Docker requires sudo
    use_sudo = check_docker_sudo()
    
    # Step 1: Stop and remove all containers
    logger.info("Stopping and removing all Docker containers...")
    containers = get_docker_containers(use_sudo)
    
    container_count = 0
    for container in containers:
        container_id = container.get('ID', '')
        if container_id:
            if stop_and_remove_container(container_id, use_sudo):
                container_count += 1
    
    logger.info(f"Removed {container_count} containers")
    
    # Step 2: Delete all Docker images except repopilot/base and ubuntu:20.04 (dependency for base image)
    logger.info("Deleting Docker images (except repopilot/base and ubuntu:20.04)...")
    images = get_docker_images(use_sudo)
    
    if not images:
        logger.info("No Docker images found.")
        return
    
    # Count deleted and kept images
    deleted_count = 0
    kept_count = 0
    
    # Process each image
    for image in images:
        repository = image.get('Repository', '')
        tag = image.get('Tag', '')
        image_id = image.get('ID', '')
        
        # Skip the repopilot/base image and ubuntu:20.04 (dependency for base image)
        if repository == 'repopilot/base' or (repository == 'ubuntu' and tag == '20.04'):
            logger.info(f"Keeping image: {repository}:{tag}")
            kept_count += 1
            continue
        
        # Delete all other images
        if delete_docker_image(image_id, use_sudo):
            deleted_count += 1
    
    logger.info(f"Docker cleanup complete: {deleted_count} images deleted, {kept_count} images kept.")

if __name__ == "__main__":
    main() 