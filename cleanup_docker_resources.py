#!/usr/bin/env python3
import asyncio
import os
import subprocess
import json
import logging
import shutil
import sys

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

# Import MongoDB models
try:
    from models import IssueAnalysis, init_app
    from config import Config
    
    # Create a minimal app config for MongoDB connection
    class MinimalAppConfig:
        def __init__(self):
            self.config = {
                'MONGODB_SETTINGS': {
                    'host': 'mongodb://localhost:27017/repopilot'
                }
            }
    
    # Initialize MongoDB connection
    mongo_available = True
except ImportError as e:
    logger.warning(f"MongoDB models could not be imported: {e}")
    mongo_available = False

class DockerCleaner:
    def __init__(self, use_sudo=None):
        self.containers_dir = os.path.join(os.path.expanduser('~'), '.repopilot', 'containers')
        self.dockerfiles_dir = os.path.abspath('docker_files')
        
        # Determine if sudo is needed
        if use_sudo is None:
            try:
                subprocess.run(["docker", "info"], check=True, capture_output=True)
                self.use_sudo = False
                logger.info("Docker access available without sudo")
            except (subprocess.SubprocessError, FileNotFoundError):
                try:
                    subprocess.run(["sudo", "-n", "docker", "info"], check=True, capture_output=True)
                    self.use_sudo = True
                    logger.info("Docker access available with passwordless sudo")
                except:
                    self.use_sudo = True
                    logger.info("Docker access requires sudo with password")
        else:
            self.use_sudo = use_sudo
    
    def _run_docker_command(self, args, **kwargs):
        """Run a docker command with or without sudo as needed"""
        cmd = ["sudo", "docker"] if self.use_sudo else ["docker"]
        cmd.extend(args)
        return subprocess.run(cmd, **kwargs)
    
    async def cleanup_all_containers(self):
        """Clean up all RepoPilot containers and images"""
        logger.info("Starting cleanup of RepoPilot Docker resources...")
        
        # Delete containers from configuration directory
        containers_removed = 0
        if os.path.exists(self.containers_dir):
            logger.info(f"Scanning {self.containers_dir} for container configs...")
            
            # List all container configs
            for filename in os.listdir(self.containers_dir):
                if filename.endswith('.json'):
                    config_path = os.path.join(self.containers_dir, filename)
                    try:
                        with open(config_path, 'r') as f:
                            container_config = json.load(f)
                        
                        container_name = container_config.get('container_name')
                        custom_image_name = container_config.get('custom_image_name')
                        
                        if container_name:
                            # Remove container
                            logger.info(f"Removing container: {container_name}")
                            try:
                                self._run_docker_command(["stop", container_name], check=False)
                                self._run_docker_command(["rm", "-f", container_name], check=False)
                                containers_removed += 1
                            except Exception as e:
                                logger.warning(f"Failed to remove container {container_name}: {str(e)}")
                        
                        if custom_image_name:
                            # Remove custom image
                            logger.info(f"Removing image: {custom_image_name}")
                            try:
                                self._run_docker_command(["rmi", "-f", custom_image_name], check=False)
                            except Exception as e:
                                logger.warning(f"Failed to remove image {custom_image_name}: {str(e)}")
                        
                        # Remove config file
                        os.remove(config_path)
                        
                    except Exception as e:
                        logger.warning(f"Error processing {filename}: {str(e)}")
            
            # Clean up workspace directories
            for dirname in os.listdir(self.containers_dir):
                if os.path.isdir(os.path.join(self.containers_dir, dirname)):
                    logger.info(f"Removing workspace directory: {dirname}")
                    try:
                        shutil.rmtree(os.path.join(self.containers_dir, dirname))
                    except Exception as e:
                        logger.warning(f"Failed to remove directory {dirname}: {str(e)}")
        
        # Clean up Dockerfile directories
        if os.path.exists(self.dockerfiles_dir):
            logger.info(f"Cleaning up Dockerfile directories in {self.dockerfiles_dir}...")
            for dirname in os.listdir(self.dockerfiles_dir):
                if os.path.isdir(os.path.join(self.dockerfiles_dir, dirname)):
                    logger.info(f"Removing Dockerfile directory: {dirname}")
                    try:
                        shutil.rmtree(os.path.join(self.dockerfiles_dir, dirname))
                    except Exception as e:
                        logger.warning(f"Failed to remove directory {dirname}: {str(e)}")
        
        # Find and remove any remaining RepoPilot containers
        try:
            logger.info("Searching for any remaining RepoPilot containers...")
            process = self._run_docker_command(
                ["ps", "-a", "--filter", "name=repopilot", "--format", "{{.Names}}"],
                capture_output=True,
                text=True
            )
            
            for container_name in process.stdout.strip().split('\n'):
                if container_name:
                    logger.info(f"Removing container: {container_name}")
                    try:
                        self._run_docker_command(["stop", container_name], check=False)
                        self._run_docker_command(["rm", "-f", container_name], check=False)
                        containers_removed += 1
                    except Exception as e:
                        logger.warning(f"Failed to remove container {container_name}: {str(e)}")
        except Exception as e:
            logger.warning(f"Error finding remaining containers: {str(e)}")
        
        # Find and remove any remaining RepoPilot images
        try:
            logger.info("Searching for any remaining RepoPilot images...")
            process = self._run_docker_command(
                ["images", "--filter", "reference=repopilot*", "--format", "{{.Repository}}:{{.Tag}}"],
                capture_output=True,
                text=True
            )
            
            for image_name in process.stdout.strip().split('\n'):
                if image_name and image_name != "<none>:<none>":
                    logger.info(f"Removing image: {image_name}")
                    try:
                        self._run_docker_command(["rmi", "-f", image_name], check=False)
                    except Exception as e:
                        logger.warning(f"Failed to remove image {image_name}: {str(e)}")
        except Exception as e:
            logger.warning(f"Error finding remaining images: {str(e)}")
        
        logger.info(f"Cleanup complete. Removed {containers_removed} containers.")
        
        return {
            "containers_removed": containers_removed,
            "configs_dir_cleaned": os.path.exists(self.containers_dir),
            "dockerfiles_dir_cleaned": os.path.exists(self.dockerfiles_dir)
        }

def clear_mongodb_cache():
    """Clear the MongoDB cache of issue analyses"""
    if not mongo_available:
        logger.warning("MongoDB models not available, skipping database cleanup")
        return 0
    
    try:
        # Initialize MongoDB connection
        app_config = MinimalAppConfig()
        init_app(app_config)
        
        # Get count before deletion
        count_before = IssueAnalysis.objects.count()
        
        # Delete all issue analyses
        IssueAnalysis.objects.delete()
        
        logger.info(f"Successfully deleted {count_before} issue analyses from MongoDB")
        return count_before
    except Exception as e:
        logger.error(f"Error clearing MongoDB cache: {str(e)}")
        return 0

async def main():
    # Clean up Docker resources
    cleaner = DockerCleaner()
    docker_result = await cleaner.cleanup_all_containers()
    logger.info(f"Docker cleanup summary: {docker_result}")
    
    # Clean up MongoDB cache
    analyses_deleted = clear_mongodb_cache()
    logger.info(f"Database cleanup summary: {analyses_deleted} issue analyses deleted")

if __name__ == "__main__":
    asyncio.run(main()) 