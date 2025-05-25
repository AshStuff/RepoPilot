import asyncio
import os
import sys
import logging
from agents.docker_manager import DockerManager

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Determine if running in simulation mode (no longer used by DockerManager)
# simulation_mode = "--sim" in sys.argv or "-s" in sys.argv

# Initialize DockerManager
# logger.info(f"Initializing DockerManager (Simulation: {simulation_mode})")
# manager = DockerManager(simulation_mode=simulation_mode)
manager = DockerManager()

async def test_docker_manager_with_branch():
    """Test the DockerManager with a specific branch or tag"""
    
    # Use a public repository for testing
    repo_url = "https://github.com/pallets/flask"
    repo_name = "pallets/flask"
    issue_number = 9999
    
    # Use the specified branch or default to 'main'
    branch = sys.argv[1] if len(sys.argv) > 1 else "main"
    
    # Check if simulation mode is requested
    # simulation_mode = "--sim" in sys.argv or "-s" in sys.argv
    
    # Create the DockerManager instance
    # logger.info(f"Creating DockerManager (Simulation: {simulation_mode})")
    # manager = DockerManager(simulation_mode=simulation_mode)
    
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
        # if simulation_mode:
        #     logger.info(f"Container configuration: {container}")
        # else:
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
            # if not simulation_mode:
            #     logger.info("To delete it manually run:")
            #     logger.info(f"docker rm -f {container['container_name']}")
        
    except Exception as e:
        logger.error(f"Error in test: {str(e)}")
        raise

async def test_repo(repo_url, repo_name, branch_or_tag, issue_number, issue_body):
    # ... existing code ...
    if cloned_repo_path:
        logger.info(f"Cleaning up cloned repo: {cloned_repo_path}")
        manager.cleanup_cloned_repo(cloned_repo_path)
    # if simulation_mode: # No longer relevant
    #     logger.info("[SIMULATION] Skipping Docker image cleanup as it was not created.")
    # else:
    if image_id and not image_id.startswith("simulated"):
        try:
    # ... existing code ...

# Run tests
async def main():
    # Test 1: Main branch of a common repository
    # await test_repo("https://github.com/psf/requests.git", "requests", "main", 1, "Test issue for requests main branch")

    # Test 2: Specific tag (e.g., a version) of a repository
    # await test_repo("https://github.com/pallets/flask.git", "flask", "2.0.0", 2, "Test issue for flask tag 2.0.0")

    # Test 3: Non-existent branch (should fall back to default or error)
    # await test_repo("https://github.com/aio-libs/aiohttp.git", "aiohttp", "non-existent-branch-123", 3, "Test for non-existent branch")
    
    # Test 4: Specific commit hash (Git clone can handle this directly if branch arg allows commit-ish)
    # Note: clone_repo.sh might need adjustment if specific commit hashes are primary use case vs branches/tags
    # await test_repo("https://github.com/numpy/numpy.git", "numpy", "a0250068c67c79059f4ac59900977b3919f63bd6", 4, "Test for numpy specific commit")

    # Test 5: Repository with a dash in its name
    await test_repo("https://github.com/aio-libs/aiohttp-socks.git", "aiohttp-socks", "main", 5, "Test for aiohttp-socks main branch")

if __name__ == "__main__":
    # if simulation_mode:
    #     logger.info("Running tests in SIMULATION mode.")
    # else:
    #     logger.info("Running tests in LIVE Docker mode.")
    asyncio.run(main()) 