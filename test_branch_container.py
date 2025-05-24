import asyncio
import sys
from agents.docker_manager import DockerManager

async def main():
    """Test script to verify branch/tag handling in container creation"""
    # Parse command line arguments
    repo_url = sys.argv[1] if len(sys.argv) > 1 else "https://github.com/pallets/flask"
    repo_name = sys.argv[2] if len(sys.argv) > 2 else "pallets/flask"
    branch_or_tag = sys.argv[3] if len(sys.argv) > 3 else "main"
    
    # Initialize DockerManager
    docker_manager = DockerManager()
    
    print(f"Creating container for {repo_name}")
    print(f"Branch/Tag: {branch_or_tag}")
    print("-" * 50)
    
    try:
        # Create the container with specified branch/tag
        container = await docker_manager.create_container(
            repo_url=repo_url,
            repo_name=repo_name,
            issue_number=999,  # Dummy issue number for testing
            branch=branch_or_tag,
            access_token=None  # No access token for public repos
        )
        
        print("Container created successfully:")
        print(f"Container ID: {container.get('container_id')}")
        print(f"Container Name: {container.get('container_name')}")
        print(f"Status: {container.get('status')}")
        
        # Verify the branch/tag was set correctly
        verify_cmd = "cd /workspace/$(ls /workspace) && git branch --show-current"
        branch_result = docker_manager.execute_command(
            container_id=container['container_id'],
            command=verify_cmd
        )
        
        print("\nCurrent branch:")
        print(branch_result.strip() if branch_result else "Unknown")
        
        # If branch is empty or "HEAD", it might be a tag
        if not branch_result or branch_result.strip() == "HEAD" or branch_result.strip() == "":
            print("\nChecking for tag:")
            tag_cmd = "cd /workspace/$(ls /workspace) && git describe --tags"
            tag_result = docker_manager.execute_command(
                container_id=container['container_id'],
                command=tag_cmd
            )
            print(tag_result.strip() if tag_result else "No tag detected")
        
        # List all available branches
        list_cmd = "cd /workspace/$(ls /workspace) && git branch -a"
        list_result = docker_manager.execute_command(
            container_id=container['container_id'],
            command=list_cmd
        )
        
        print("\nAvailable branches:")
        print(list_result)
        
        # Clean up the container unless --keep flag is provided
        if "--keep" not in sys.argv:
            print("\nCleaning up container...")
            docker_manager.delete_container(container['container_id'])
            print("Container deleted.")
        else:
            print(f"\nContainer kept alive: {container['container_name']}")
            print("To delete it manually run:")
            print(f"docker rm -f {container['container_name']}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 