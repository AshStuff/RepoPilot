import asyncio
import os
import sys
import logging
from agents.docker_manager import DockerManager

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_docker_manager_with_branch():
    """Test the DockerManager with a specific branch or tag"""
    
    # Use a public repository for testing
    repo_url = "https://github.com/pallets/flask"
    repo_name = "pallets/flask"
    issue_number = 9999
    
    # Use the specified branch or default to 'main'
    branch = sys.argv[1] if len(sys.argv) > 1 else "main"
    
    # Check if simulation mode is requested
    simulation_mode = "--sim" in sys.argv or "-s" in sys.argv
    
    # Create the DockerManager instance
    manager = DockerManager(simulation_mode=simulation_mode)
    
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
        if simulation_mode:
            logger.info(f"Container configuration: {container}")
        else:
            # Execute commands to verify the branch/tag
            logger.info("Verifying branch/tag in container...")
            
            # Check the current branch
            branch_cmd = "git branch --show-current"
            branch_output = manager.execute_command(container['container_id'], branch_cmd)
            logger.info(f"Current branch: {branch_output.strip() if branch_output else 'Not available'}")
            
            # If we're in detached HEAD state, check the tag
            if not branch_output or not branch_output.strip():
                tag_cmd = "git describe --tags 2>/dev/null || echo 'No tag'"
                tag_output = manager.execute_command(container['container_id'], tag_cmd)
                logger.info(f"Current tag: {tag_output.strip() if tag_output else 'Not available'}")
        
        # Clean up unless --keep flag is provided
        if "--keep" not in sys.argv and "-k" not in sys.argv:
            logger.info(f"Deleting container {container['container_id']}")
            manager.delete_container(container['container_id'])
            logger.info("Container deleted.")
        else:
            logger.info(f"Container kept alive: {container['container_name']}")
            if not simulation_mode:
                logger.info("To delete it manually run:")
                logger.info(f"docker rm -f {container['container_name']}")
        
    except Exception as e:
        logger.error(f"Error in test: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(test_docker_manager_with_branch()) 