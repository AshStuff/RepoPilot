import asyncio
import sys
from agents.docker_manager import DockerManager
import argparse
import os

async def main():
    parser = argparse.ArgumentParser(description='Debug Docker container creation for RepoPilot')
    parser.add_argument('--repo', type=str, default='miguelgrinberg/microblog', 
                      help='GitHub repository (owner/repo format)')
    parser.add_argument('--issue', type=int, default=1, 
                      help='Issue number (for naming)')
    parser.add_argument('--cmd', type=str, default='ls -la',
                      help='Command to execute in the container')
    parser.add_argument('--keep', action='store_true', 
                      help='Keep container after execution (don\'t delete)')
    parser.add_argument('--force-sudo', action='store_true', 
                      help='Force using sudo for Docker commands')
    args = parser.parse_args()
    
    # Format repo URL
    repo_name = args.repo
    repo_url = f"https://github.com/{repo_name}"
    issue_number = args.issue
    
    # Initialize DockerManager with auto sudo detection
    docker_manager = DockerManager(use_sudo=True if args.force_sudo else None)
    container = None
    
    try:
        print(f"Building and creating container for {repo_name} issue #{issue_number}...")
        
        # Create the container
        container = await docker_manager.create_container(
            repo_url=repo_url,
            repo_name=repo_name,
            issue_number=issue_number
        )
        
        print("\nContainer created successfully:")
        print(f"Container ID: {container['container_id']}")
        print(f"Container Name: {container['container_name']}")
        print(f"Container Status: {container['status']}")
        
        # Get logs to see what happened during container creation
        print("\nContainer logs:")
        logs = docker_manager.get_container_logs(container['container_id'])
        print(logs or "No logs available")
        
        # Execute command
        print(f"\nExecuting command: {args.cmd}")
        result = docker_manager.execute_command(
            container_id=container['container_id'],
            command=args.cmd
        )
        print(result or "Command execution failed or no output")
        
        # Keep container if requested
        if not args.keep:
            print("\nDeleting container...")
            docker_manager.delete_container(container['container_id'])
            print("Container deleted.")
        else:
            print(f"\nContainer kept alive: {container['container_name']}")
            print("To delete it later, run:")
            cmd_prefix = "sudo " if docker_manager.use_sudo else ""
            print(f"  {cmd_prefix}docker rm -f {container['container_name']}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        
        # Clean up if container was created but keep flag not set
        if container and not args.keep:
            try:
                print("\nCleaning up container...")
                docker_manager.delete_container(container['container_id'])
                print("Container deleted.")
            except:
                pass
        
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 