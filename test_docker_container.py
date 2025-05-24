import asyncio
import sys
from agents.docker_manager import DockerManager

async def main():
    # Initialize DockerManager with auto sudo detection
    docker_manager = DockerManager()
    
    # GitHub repository to test - using a smaller repo
    repo_url = "https://github.com/miguelgrinberg/microblog"
    repo_name = "miguelgrinberg/microblog"
    issue_number = 1  # Just a sample issue number
    
    print(f"Creating container for {repo_name} issue #{issue_number}...")
    
    try:
        # Create the container
        container = await docker_manager.create_container(
            repo_url=repo_url,
            repo_name=repo_name,
            issue_number=issue_number
        )
        
        print("Container created successfully:")
        print(f"Container ID: {container['container_id']}")
        print(f"Container Name: {container['container_name']}")
        print(f"Container Status: {container['status']}")
        
        # Execute a command in the container to verify the repository was cloned
        print("\nListing repository files:")
        result = docker_manager.execute_command(
            container_id=container['container_id'],
            command="ls -la"
        )
        print(result)
        
        # Check the Python version in the container
        print("\nChecking Python version:")
        result = docker_manager.execute_command(
            container_id=container['container_id'],
            command="python3 --version"
        )
        print(result)
        
        # Get container logs
        print("\nContainer logs:")
        logs = docker_manager.get_container_logs(container['container_id'])
        print(logs)
        
        # Clean up - delete the container
        print("\nDeleting container...")
        docker_manager.delete_container(container['container_id'])
        print("Container deleted.")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 