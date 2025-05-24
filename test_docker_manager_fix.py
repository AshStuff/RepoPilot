import asyncio
import os
import logging
from agents.docker_manager import DockerManager

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_docker_manager():
    """Test the DockerManager with branch and tag support"""
    
    # Use a public repository for testing
    repo_url = "https://github.com/pallets/flask"
    repo_name = "pallets/flask"
    issue_number = 9999
    branch = "main"  # Or specify a tag/branch to test with
    
    # Create the DockerManager instance
    manager = DockerManager(simulation_mode=True)  # Use simulation mode for safety
    
    try:
        # Create a container with the specified branch
        logger.info(f"Creating container for {repo_name} with branch/tag: {branch}")
        container = await manager.create_container(
            repo_url=repo_url, 
            repo_name=repo_name, 
            issue_number=issue_number,
            branch=branch
        )
        
        logger.info(f"Container created successfully: {container['container_name']}")
        logger.info(f"Container ID: {container['container_id']}")
        logger.info(f"Container status: {container['status']}")
        
        # In simulation mode, no actual commands will be executed
        # But we can still verify the container configuration
        logger.info(f"Container configuration: {container}")
        
        # Clean up (this is important for non-simulation mode)
        if not manager.simulation_mode:
            logger.info(f"Deleting container {container['container_id']}")
            manager.delete_container(container['container_id'])
        
    except Exception as e:
        logger.error(f"Error in test: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(test_docker_manager()) 