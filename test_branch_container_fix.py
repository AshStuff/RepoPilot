import asyncio
import sys
import os
import json
import subprocess
from typing import Dict, Any, Optional

# Simplified DockerManager for testing
class SimpleDockerManager:
    def __init__(self):
        self.base_image = "repopilot/base:latest"
        self.temp_dir = "/tmp/repopilot_test"
        os.makedirs(self.temp_dir, exist_ok=True)
    
    async def create_container_with_branch(self, repo_url: str, repo_name: str, branch: str) -> Dict[str, Any]:
        """Create a container with the specified branch"""
        print(f"Creating container for {repo_name} with branch/tag: {branch}")
        
        # Create a unique ID for this container
        container_id = f"test-{branch.replace('/', '-')}"
        container_name = f"repopilot-test-{branch.replace('/', '-')}"
        
        # Create a Dockerfile directory
        dockerfile_dir = os.path.join(self.temp_dir, container_id)
        os.makedirs(dockerfile_dir, exist_ok=True)
        
        # Create a clone script
        clone_script = os.path.join(dockerfile_dir, "clone.sh")
        with open(clone_script, "w") as f:
            f.write(f"""#!/bin/bash
set -e
mkdir -p /workspace
cd /workspace
echo "Cloning {repo_url} with branch/tag {branch}..."
git clone --depth 1 {repo_url} repo || true
cd repo
git fetch --all
git checkout {branch} || git checkout -b {branch} || echo "Failed to checkout {branch}"
echo "Current branch: $(git branch --show-current)"
""")
        
        # Make the script executable
        os.chmod(clone_script, 0o755)
        
        # Create a simple Dockerfile
        dockerfile_path = os.path.join(dockerfile_dir, "Dockerfile")
        with open(dockerfile_path, "w") as f:
            f.write(f"""FROM {self.base_image}
COPY clone.sh /tmp/clone.sh
RUN apt-get update && apt-get install -y git
RUN chmod +x /tmp/clone.sh
RUN /tmp/clone.sh
WORKDIR /workspace/repo
CMD ["bash"]
""")
        
        # Build the Docker image
        image_name = f"repopilot-test-{branch.replace('/', '-')}"
        build_cmd = ["docker", "build", "-t", image_name, "-f", dockerfile_path, dockerfile_dir]
        
        try:
            print("Building Docker image...")
            proc = subprocess.run(build_cmd, check=True, capture_output=True, text=True)
            
            # Run the container
            run_cmd = ["docker", "run", "--name", container_name, "-d", image_name]
            proc = subprocess.run(run_cmd, check=True, capture_output=True, text=True)
            container_id = proc.stdout.strip()
            
            return {
                "container_id": container_id,
                "container_name": container_name,
                "image_name": image_name,
                "status": "running"
            }
            
        except subprocess.CalledProcessError as e:
            print(f"Error: {e.stderr}")
            return {"error": e.stderr}
    
    def execute_command(self, container_id: str, command: str) -> str:
        """Execute a command in the container"""
        cmd = ["docker", "exec", container_id, "bash", "-c", command]
        try:
            proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return proc.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error executing command: {e.stderr}")
            return f"Error: {e.stderr}"
    
    def delete_container(self, container_name: str) -> bool:
        """Delete a container"""
        try:
            # Stop the container if it's running
            subprocess.run(["docker", "stop", container_name], check=False)
            
            # Remove the container
            subprocess.run(["docker", "rm", "-f", container_name], check=True)
            
            # Remove the image
            image_name = f"repopilot-test-{container_name.replace('repopilot-test-', '')}"
            subprocess.run(["docker", "rmi", "-f", image_name], check=False)
            
            return True
        except Exception as e:
            print(f"Error deleting container: {str(e)}")
            return False

async def main():
    """Test script for branch/tag handling"""
    # Parse command line args
    repo_url = sys.argv[1] if len(sys.argv) > 1 else "https://github.com/pallets/flask"
    repo_name = sys.argv[2] if len(sys.argv) > 2 else "pallets/flask"
    branch = sys.argv[3] if len(sys.argv) > 3 else "main"
    
    # Create the manager and container
    manager = SimpleDockerManager()
    
    try:
        # Create container with the specified branch
        container = await manager.create_container_with_branch(repo_url, repo_name, branch)
        
        if "error" in container:
            print(f"Failed to create container: {container['error']}")
            sys.exit(1)
        
        print(f"Container created: {container['container_name']}")
        
        # Check the current branch
        branch_cmd = "git branch --show-current"
        branch_output = manager.execute_command(container['container_name'], branch_cmd)
        print(f"Current branch: {branch_output.strip()}")
        
        # If we're in detached HEAD state, the branch might be empty
        if not branch_output.strip():
            tag_cmd = "git describe --tags"
            tag_output = manager.execute_command(container['container_name'], tag_cmd)
            print(f"Current tag: {tag_output.strip()}")
        
        # List all branches
        all_branches_cmd = "git branch -a"
        all_branches = manager.execute_command(container['container_name'], all_branches_cmd)
        print(f"Available branches:\n{all_branches}")
        
        # Clean up unless --keep flag is provided
        if "--keep" not in sys.argv:
            print("Cleaning up container...")
            manager.delete_container(container['container_name'])
            print("Container deleted.")
        else:
            print(f"Container kept alive: {container['container_name']}")
            print("To delete it manually run:")
            print(f"docker rm -f {container['container_name']}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 