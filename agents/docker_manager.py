import os
import subprocess
import logging
import uuid
import json
from typing import Dict, Optional, Any
import shlex
import tempfile
import time
import docker
import tarfile
import io
import shutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DockerManager:
    def __init__(self, simulation_mode=False, use_sudo=None):
        self.base_image = "repopilot/base:latest"
        self.containers_dir = os.path.join(os.path.expanduser('~'), '.repopilot', 'containers')
        self.dockerfiles_dir = os.path.abspath('docker_files')
        self.clone_dir = os.path.abspath('cloned_repos')
        os.makedirs(self.containers_dir, exist_ok=True)
        os.makedirs(self.dockerfiles_dir, exist_ok=True)
        os.makedirs(self.clone_dir, exist_ok=True)
        self.simulation_mode = simulation_mode
        self.client = None
        
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
                except (subprocess.SubprocessError, FileNotFoundError):
                    self.use_sudo = True
                    logger.info("Docker access might require sudo with password or setup.")
        else:
            self.use_sudo = use_sudo
        
        if not simulation_mode:
            try:
                self.client = docker.from_env()
                if not self.client.ping():
                    logger.warning("Docker client initialized but failed to ping Docker server. Docker might not be running correctly.")
                    self.simulation_mode = True
                else:
                    logger.info("Docker client initialized and server ping successful.")
            except docker.errors.DockerException as e:
                logger.warning(f"Failed to initialize Docker client: {e}. Switching to simulation mode.")
                self.simulation_mode = True
            except Exception as e_gen:
                logger.warning(f"An unexpected error occurred during Docker client initialization: {e_gen}. Switching to simulation mode.")
                self.simulation_mode = True
        
        if self.simulation_mode:
            logger.info("DockerManager is in SIMULATION MODE.")
            self.client = None
    
    def _run_docker_command(self, args, **kwargs):
        """Run a docker command with or without sudo as needed"""
        cmd = ["sudo", "docker"] if self.use_sudo else ["docker"]
        cmd.extend(args)
        return subprocess.run(cmd, **kwargs)
        
    async def create_container(self, repo_url: str, repo_name: str, issue_number: int, 
                              branch: str = 'main', access_token: Optional[str] = None,
                              issue_body_for_txt_file: Optional[str] = None) -> Dict[str, Any]:
        """Create a Docker container for analyzing a repository issue"""
        try:
            container_id = str(uuid.uuid4())
            container_name = f"repopilot-{repo_name.replace('/', '-')}-{issue_number}-{container_id[:8]}"
            
            container_config = {
                'container_id': container_id,
                'container_name': container_name,
                'repo_url': repo_url,
                'repo_name': repo_name,
                'issue_number': issue_number,
                'branch': branch,
                'status': 'creating'
            }
            
            self._save_container_config(container_id, container_config)
            
            if self.simulation_mode:
                logger.info(f"[SIMULATION] Creating container {container_name} for issue #{issue_number} in {repo_name} with branch {branch}")
                
                sim_workspace = os.path.join(self.containers_dir, container_id, 'workspace')
                os.makedirs(sim_workspace, exist_ok=True)
                
                repo_dir = os.path.join(sim_workspace, repo_name.split('/')[-1])
                os.makedirs(repo_dir, exist_ok=True)
                
                with open(os.path.join(repo_dir, 'README.md'), 'w') as f:
                    f.write(f"""# Simulated Clone of {repo_name}

This is a simulated repository clone for issue #{issue_number}.
Repository URL: {repo_url}
Branch: {branch}
                    """)
                
                time.sleep(1)
                
                container_config['status'] = 'running'
                container_config['container_short_id'] = 'sim-' + container_id[:12]
                container_config['simulation'] = True
                container_config['workspace_path'] = sim_workspace
                self._save_container_config(container_id, container_config)
                
                logger.info(f"[SIMULATION] Container {container_name} created successfully")
                return container_config
                
            else:
                import pdb; pdb.set_trace()
                dockerfile_path = self._create_custom_dockerfile(container_id, repo_url, repo_name, branch, access_token, issue_body_content=issue_body_for_txt_file)
                
                custom_image_name = f"repopilot-issue-{container_id[:8]}"
                logger.info(f"Building custom Docker image for issue #{issue_number} in {repo_name} with branch {branch}")
                
                build_cmd = [
                    "build",
                    "-t", custom_image_name,
                    "-f", dockerfile_path,
                    "--build-arg", f"REPO_URL={repo_url}",
                    "--build-arg", f"BRANCH={branch}"
                ]
                
                if access_token:
                    build_cmd.extend(["--build-arg", f"ACCESS_TOKEN={access_token}"])
                    
                build_cmd.append(os.path.dirname(dockerfile_path))
                
                process = self._run_docker_command(build_cmd, capture_output=True, text=True, check=True)
                
                logger.info(f"Creating container {container_name} for issue #{issue_number} in {repo_name} on branch {branch}")
                
                run_cmd = [
                    "run", "-d",
                    "--name", container_name,
                    "-e", f"REPO_URL={repo_url}",
                    "-e", f"ISSUE_NUMBER={issue_number}",
                    "-e", f"BRANCH={branch}",
                    custom_image_name,
                    "/bin/bash", "-c", "tail -f /dev/null"
                ]
                
                process = self._run_docker_command(run_cmd, capture_output=True, text=True, check=True)
                container_short_id = process.stdout.strip()
                
                container_config['status'] = 'running'
                container_config['container_short_id'] = container_short_id
                container_config['custom_image_name'] = custom_image_name
                self._save_container_config(container_id, container_config)
                
                logger.info(f"Container {container_name} ({container_short_id}) created successfully")
                
                return container_config
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create container: {e.stderr}")
            if container_id:
                container_config['status'] = 'failed'
                container_config['error'] = e.stderr
                self._save_container_config(container_id, container_config)
            raise RuntimeError(f"Failed to create Docker container: {e.stderr}")
            
        except Exception as e:
            logger.error(f"Error creating container: {str(e)}")
            if container_id:
                container_config['status'] = 'failed'
                container_config['error'] = str(e)
                self._save_container_config(container_id, container_config)
            raise
    
    def _create_custom_dockerfile(self, container_id: str, repo_url: str, repo_name: str, branch: str = 'main', 
                                  access_token: Optional[str] = None, 
                                  issue_body_content: Optional[str] = None) -> str:
        """Create a custom Dockerfile in the workspace under docker_files/<container_id>/"""
        
        build_context_dir = os.path.join(self.dockerfiles_dir, container_id)
        os.makedirs(build_context_dir, exist_ok=True)
        
        dockerfile_path = os.path.join(build_context_dir, 'Dockerfile')
        clone_script_path = os.path.join(build_context_dir, 'clone_repo.sh')
        issue_txt_path_in_context = os.path.join(build_context_dir, 'issue.txt')

        agent_script_source_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'container_agent.py'))
        agent_reqs_source_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'container_agent_requirements.txt'))
        
        agent_script_dest_path = os.path.join(build_context_dir, 'container_agent.py')
        agent_reqs_dest_path = os.path.join(build_context_dir, 'container_agent_requirements.txt')

        if os.path.exists(agent_script_source_path):
            subprocess.run(['cp', agent_script_source_path, agent_script_dest_path], check=True)
            logger.info(f"Copied container_agent.py to build context: {agent_script_dest_path}")
            os.chmod(agent_script_dest_path, 0o755)
            logger.info(f"Made container_agent.py executable in build context: {agent_script_dest_path}")
        else:
            logger.warning(f"container_agent.py not found at {agent_script_source_path}")

        if os.path.exists(agent_reqs_source_path):
            subprocess.run(['cp', agent_reqs_source_path, agent_reqs_dest_path], check=True)
            logger.info(f"Copied container_agent_requirements.txt to build context: {agent_reqs_dest_path}")
        else:
            logger.warning(f"container_agent_requirements.txt not found at {agent_reqs_source_path}")

        repo_basename = os.path.basename(repo_url)
        if repo_basename.endswith('.git'):
            repo_basename = repo_basename[:-4]
        
        clone_script_content = """#!/bin/bash
# Print each command for debugging
set -ex

WORKSPACE_DIR="/workspace"
REPO_URL="{0}"
BRANCH="{1}"
REPO_NAME="{2}"
ACCESS_TOKEN="{3}"

echo "====== DEBUG INFO ======"
echo "Repository URL: $REPO_URL"
echo "Branch/Tag: $BRANCH"
echo "Repository name: $REPO_NAME"
echo "Workspace directory: $WORKSPACE_DIR"
echo "Current directory: $(pwd)"
echo "=======================\n"

# Create workspace directory
mkdir -p "$WORKSPACE_DIR"
cd "$WORKSPACE_DIR"

# Construct the correct GitHub URL with branch/tag
if [ "$BRANCH" != "main" ] && [ "$BRANCH" != "master" ]; then
    # Format the repo URL to include the branch/tag
    if [[ "$BRANCH" =~ ^v[0-9] ]]; then
        # For version tags, use the archive download URL
        CLONE_URL="$REPO_URL/archive/refs/tags/$BRANCH.zip"
        
        # Try to download the archive
        if curl -L -o "$WORKSPACE_DIR/$BRANCH.zip" "$CLONE_URL"; then
            echo "Downloaded version archive, extracting..."
            unzip -q "$WORKSPACE_DIR/$BRANCH.zip" -d "$WORKSPACE_DIR"
            
            # Find the extracted directory and rename to expected repo name
            EXTRACTED_DIR=$(find "$WORKSPACE_DIR" -maxdepth 1 -type d -name "$REPO_NAME-*")
            if [ -n "$EXTRACTED_DIR" ]; then
                # Handle cases where there might be multiple matches if repo_name is a substring
                # Prefer the shortest match or the one that looks most like REPO_NAME-BRANCH or REPO_NAME-TAG
                PREFERRED_EXTRACTED_DIR=$(echo "$EXTRACTED_DIR" | awk -v repo="$REPO_NAME" -v branch="$BRANCH" '
                    BEGIN {{ best_match = ""; min_len = 9999 }}
                    {{ 
                        current_len = length($0);
                        if ( ($0 ~ repo "-" branch "$") || ($0 ~ repo "-" substr(branch,2) "$") ) {{ best_match = $0; break; }}
                        if (current_len < min_len) {{ min_len = current_len; best_match = $0; }}
                    }}
                    END {{ print best_match }}')
                mv "$PREFERRED_EXTRACTED_DIR" "$WORKSPACE_DIR/$REPO_NAME"
                echo "Extracted archive to $WORKSPACE_DIR/$REPO_NAME"
                cd "$WORKSPACE_DIR/$REPO_NAME"
                echo "Successfully checked out tag $BRANCH"
                exit 0
            fi
        fi
    fi
fi

# If we get here, either the archive download failed or it's a regular branch
# Fall back to standard git clone

# Add authentication if token is provided
if [ -n "$ACCESS_TOKEN" ]; then
    AUTH_URL=$(echo "$REPO_URL" | sed "s|https://|https://oauth2:$ACCESS_TOKEN@|")
    
    # Try direct clone with branch specified
    if git clone --depth 1 --branch "$BRANCH" "$AUTH_URL" "$WORKSPACE_DIR/$REPO_NAME" 2>/dev/null; then
        echo "Successfully cloned repo with branch $BRANCH using authentication"
        cd "$WORKSPACE_DIR/$REPO_NAME"
        exit 0
    else
        # Try standard clone then checkout
        if git clone --depth 1 "$AUTH_URL" "$WORKSPACE_DIR/$REPO_NAME"; then
            cd "$WORKSPACE_DIR/$REPO_NAME"
            
            # Try to checkout the branch or tag
            if git checkout "$BRANCH" 2>/dev/null || git checkout "tags/$BRANCH" 2>/dev/null; then
                echo "Successfully checked out $BRANCH after cloning"
                exit 0
            else
                echo "Failed to checkout branch/tag $BRANCH, using default branch"
            fi
        else
            echo "Failed to clone repository"
            exit 1
        fi
    fi
else
    # No authentication, try direct public clone with branch
    if git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$WORKSPACE_DIR/$REPO_NAME" 2>/dev/null; then
        echo "Successfully cloned repo with branch $BRANCH"
        cd "$WORKSPACE_DIR/$REPO_NAME"
        exit 0
    else
        # Try standard clone then checkout
        if git clone --depth 1 "$REPO_URL" "$WORKSPACE_DIR/$REPO_NAME"; then
            cd "$WORKSPACE_DIR/$REPO_NAME"
            
            # Try to checkout the branch or tag
            if git checkout "$BRANCH" 2>/dev/null || git checkout "tags/$BRANCH" 2>/dev/null; then
                echo "Successfully checked out $BRANCH after cloning"
                exit 0
            else
                echo "Failed to checkout branch/tag $BRANCH, using default branch"
            fi
        else
            echo "Failed to clone repository"
            exit 1
        fi
    fi
fi

# Verify clone success
cd "$WORKSPACE_DIR/$REPO_NAME" || exit 1
echo "Now in $(pwd)"

# Check for requirements.txt and install if present
if [ -f "requirements.txt" ]; then
    echo "Installing Python dependencies from requirements.txt..."
    pip3 install --user -r requirements.txt
    echo "Successfully installed dependencies from requirements.txt"
fi

# Check for pyproject.toml and install if present
if [ -f "pyproject.toml" ]; then
    echo "Installing Python package from pyproject.toml..."
    pip3 install --user -e .
    echo "Successfully installed package from pyproject.toml"
fi

# Check for package.json and install if present
if [ -f "package.json" ]; then
    echo "Installing Node.js dependencies..."
    # Check if npm is installed
    if command -v npm &> /dev/null; then
        npm install
        echo "Successfully installed Node.js dependencies"
    else
        echo "Node.js/npm is not installed, skipping npm dependencies."
    fi
fi

echo "Repository $REPO_NAME has been cloned successfully with branch/tag: $BRANCH"
""".format(
                repo_url,
                branch,
                repo_basename,
                access_token if access_token else ''
            )
        
        with open(clone_script_path, 'w') as f:
            f.write(clone_script_content)
        os.chmod(clone_script_path, 0o755)
        
        if issue_body_content is not None:
            with open(issue_txt_path_in_context, 'w') as f_issue:
                f_issue.write(issue_body_content)
            logger.info(f"Created issue.txt in build context: {issue_txt_path_in_context}")
            issue_txt_copy_instruction = "COPY issue.txt /app/issue.txt"
        else:
            issue_txt_copy_instruction = "# issue_body_content not provided, issue.txt not created"

        dockerfile_content = f"""FROM {self.base_image}

# Arguments that can be passed during build
ARG REPO_URL
ARG BRANCH
ARG ACCESS_TOKEN

# Set environment variables
ENV REPO_URL=$REPO_URL
ENV BRANCH=$BRANCH
ENV ACCESS_TOKEN=$ACCESS_TOKEN
ENV DEBIAN_FRONTEND=noninteractive

# Copy the clone script (from build context) into the image
# Permissions should be preserved from the host if host script is executable.
COPY clone_repo.sh /app/clone_repo.sh
# RUN chmod +x /app/clone_repo.sh # Removed as per user request, host chmod should suffice

# --- BEGIN ADDITION FOR issue.txt ---
# Copy issue.txt into the image if it was created
{issue_txt_copy_instruction}
# --- END ADDITION FOR issue.txt ---

# Copy the container agent script and its requirements
COPY container_agent.py /app/container_agent.py
COPY container_agent_requirements.txt /app/container_agent_requirements.txt

# Install dependencies for the container agent
RUN pip install --no-cache-dir -r /app/container_agent_requirements.txt

# Run the clone script
RUN /app/clone_repo.sh

# Execute the container agent script and save its output and errors
RUN python3 /app/container_agent.py > /app/analysis_output.json 2> /app/analysis_error.log || true

# Set working directory to the cloned repo
WORKDIR /workspace/{repo_basename}

# Default command (can be overridden)
CMD [\"/bin/bash\"]
"""
        
        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile_content)
            
        logger.info(f"Dockerfile and clone script created in: {build_context_dir}")
        
        return dockerfile_path
    
    def stop_container(self, container_id: str) -> bool:
        """Stop a running container"""
        try:
            container_config = self._get_container_config(container_id)
            if not container_config:
                logger.error(f"Container config not found for ID: {container_id}")
                return False
                
            container_name = container_config.get('container_name')
            if not container_name:
                logger.error(f"Container name not found in config for ID: {container_id}")
                return False
                
            logger.info(f"Stopping container {container_name}")
            self._run_docker_command(["stop", container_name], check=True)
            
            container_config['status'] = 'stopped'
            self._save_container_config(container_id, container_config)
            
            logger.info(f"Container {container_name} stopped successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stop container: {e.stderr}")
            return False
            
        except Exception as e:
            logger.error(f"Error stopping container: {str(e)}")
            return False
    
    def start_container(self, container_id: str) -> bool:
        """Start a stopped container"""
        try:
            container_config = self._get_container_config(container_id)
            if not container_config:
                logger.error(f"Container config not found for ID: {container_id}")
                return False
                
            container_name = container_config.get('container_name')
            if not container_name:
                logger.error(f"Container name not found in config for ID: {container_id}")
                return False
                
            logger.info(f"Starting container {container_name}")
            self._run_docker_command(["start", container_name], check=True)
            
            container_config['status'] = 'running'
            self._save_container_config(container_id, container_config)
            
            logger.info(f"Container {container_name} started successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start container: {e.stderr}")
            return False
            
        except Exception as e:
            logger.error(f"Error starting container: {str(e)}")
            return False
    
    def delete_container(self, container_id: str) -> bool:
        """Delete a container"""
        try:
            container_config = self._get_container_config(container_id)
            if not container_config:
                logger.error(f"Container config not found for ID: {container_id}")
                return False
                
            container_name = container_config.get('container_name')
            if not container_name:
                logger.error(f"Container name not found in config for ID: {container_id}")
                return False
            
            custom_image_name = container_config.get('custom_image_name')
                
            if container_config.get('status') == 'running':
                try:
                    self._run_docker_command(["stop", container_name], check=True)
                except:
                    pass
                
            logger.info(f"Removing container {container_name}")
            self._run_docker_command(["rm", "-f", container_name], check=True)
            
            if custom_image_name:
                try:
                    logger.info(f"Removing custom image {custom_image_name}")
                    self._run_docker_command(["rmi", "-f", custom_image_name], check=True)
                except:
                    pass
            
            config_path = self._get_container_config_path(container_id)
            if os.path.exists(config_path):
                os.remove(config_path)
            
            dockerfile_dir = os.path.join(self.dockerfiles_dir, container_id)
            if os.path.exists(dockerfile_dir):
                shutil.rmtree(dockerfile_dir)
            
            logger.info(f"Container {container_name} removed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove container: {e.stderr}")
            return False
            
        except Exception as e:
            logger.error(f"Error removing container: {str(e)}")
            return False
    
    def execute_command(self, container_id: str, command: str) -> Optional[str]:
        """Execute a command in a container"""
        try:
            container_config = self._get_container_config(container_id)
            if not container_config:
                logger.error(f"Container config not found for ID: {container_id}")
                return None
                
            if container_config.get('simulation', False):
                logger.info(f"[SIMULATION] Executing command in container {container_config['container_name']}: {command}")
                
                return f"[SIMULATION] Would execute: {command}\nSimulated output."
            
            container_name = container_config.get('container_name')
            if not container_name:
                logger.error(f"Container name not found in config for ID: {container_id}")
                return None
                
            if container_config.get('status') != 'running':
                logger.error(f"Container {container_name} is not running")
                return None
                
            logger.info(f"Executing command in container {container_name}: {command}")
            process = self._run_docker_command(
                ["exec", container_name, "/bin/bash", "-c", command],
                capture_output=True, 
                text=True
            )
            
            if process.returncode != 0:
                logger.error(f"Command execution failed: {process.stderr}")
                return None
                
            return process.stdout
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to execute command: {e.stderr}")
            return None
            
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            return None
    
    def get_container_logs(self, container_id: str) -> Optional[str]:
        """Get logs from a container"""
        try:
            container_config = self._get_container_config(container_id)
            if not container_config:
                logger.error(f"Container config not found for ID: {container_id}")
                return None
                
            if container_config.get('simulation', False):
                logger.info(f"[SIMULATION] Getting logs from container {container_config['container_name']}")
                return "[SIMULATION] Container logs would appear here."
            
            container_name = container_config.get('container_name')
            if not container_name:
                logger.error(f"Container name not found in config for ID: {container_id}")
                return None
                
            logger.info(f"Getting logs from container {container_name}")
            process = self._run_docker_command(
                ["logs", container_name],
                capture_output=True, 
                text=True
            )
            
            if process.returncode != 0:
                logger.error(f"Failed to get logs: {process.stderr}")
                return None
                
            return process.stdout
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get logs: {e.stderr}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting logs: {str(e)}")
            return None
    
    def get_container_status(self, container_id: str) -> Optional[Dict[str, Any]]:
        """Get container status"""
        try:
            container_config = self._get_container_config(container_id)
            if not container_config:
                logger.error(f"Container config not found for ID: {container_id}")
                return None
                
            container_name = container_config.get('container_name')
            if not container_name:
                logger.error(f"Container name not found in config for ID: {container_id}")
                return None
                
            # Check if container exists
            try:
                process = self._run_docker_command(
                    ["inspect", "--format", "{{.State.Status}}", container_name],
                    capture_output=True, 
                    text=True,
                    check=True
                )
                docker_status = process.stdout.strip()
                
                # Update container status based on Docker status
                if docker_status != container_config.get('status'):
                    container_config['status'] = docker_status
                    self._save_container_config(container_id, container_config)
                
            except subprocess.CalledProcessError:
                container_config['status'] = 'not_found'
                self._save_container_config(container_id, container_config)
                
            return container_config
            
        except Exception as e:
            logger.error(f"Error getting container status: {str(e)}")
            return None
    
    def debug_build_image(self, repo_url: str, repo_name: str) -> Dict[str, Any]:
        """Debug helper to build a Docker image without creating a container"""
        try:
            # Generate a unique ID for this debug build
            debug_id = str(uuid.uuid4())[:8]
            
            # Create a custom Dockerfile for debugging
            dockerfile_path = self._create_custom_dockerfile(debug_id, repo_url, repo_name)
            
            # Build custom image for debugging
            custom_image_name = f"repopilot-debug-{debug_id}"
            logger.info(f"Building debug Docker image for {repo_name}")
            
            build_cmd = [
                "build",
                "-t", custom_image_name,
                "-f", dockerfile_path,
                "--build-arg", f"REPO_URL={repo_url}"
            ]
            
            build_cmd.append(os.path.dirname(dockerfile_path))
            
            # Build the custom image
            process = self._run_docker_command(build_cmd, capture_output=True, text=True, check=True)
            
            logger.info(f"Debug image built successfully: {custom_image_name}")
            
            return {
                'debug_id': debug_id,
                'image_name': custom_image_name,
                'dockerfile_path': dockerfile_path
            }
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to build debug image: {e.stderr}")
            raise RuntimeError(f"Failed to build debug Docker image: {e.stderr}")
            
        except Exception as e:
            logger.error(f"Error building debug image: {str(e)}")
            raise
    
    def _get_container_config_path(self, container_id: str) -> str:
        """Get the path to the container config file"""
        return os.path.join(self.containers_dir, f"{container_id}.json")
    
    def _save_container_config(self, container_id: str, config: Dict[str, Any]) -> None:
        """Save container configuration to a file"""
        config_path = self._get_container_config_path(container_id)
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    def _get_container_config(self, container_id: str) -> Optional[Dict[str, Any]]:
        """Get container configuration from file"""
        config_path = self._get_container_config_path(container_id)
        if not os.path.exists(config_path):
            logger.debug(f"Container config file not found: {config_path}")
            return None
            
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Error reading or parsing container config {config_path}: {e}")
            return None 

    def _copy_file_from_image_to_host(self, image_id, container_path, host_path):
        """
        Copies a file from a given path inside an image to a specified host path.
        It does this by creating a temporary container from the image,
        copying the file out, and then removing the temporary container.
        """
        if self.simulation_mode or not self.client:
            logger.info(f"[SIMULATION] Would copy {container_path} from image {image_id} to {host_path}")
            # os.makedirs(os.path.dirname(host_path), exist_ok=True)
            # with open(host_path, 'w') as f_dummy:
            #     f_dummy.write(f"Simulated content for {os.path.basename(host_path)}")
            return True # Simulate success

        temp_container = None
        try:
            logger.debug(f"Creating temporary container from image {image_id} to copy {container_path}")
            temp_container = self.client.containers.create(image_id) # command is irrelevant
            
            os.makedirs(os.path.dirname(host_path), exist_ok=True)

            logger.debug(f"Attempting to get archive for {container_path} from container {temp_container.id}")
            stream, stat = temp_container.get_archive(container_path)
            
            tar_bytes = b"".join(stream)
            
            # Check if tar_bytes is empty, which happens if path not found in get_archive
            if not tar_bytes:
                logger.warning(f"No data returned from get_archive for {container_path} in image {image_id}. File likely does not exist at this path in the image.")
                return False

            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r') as tar:
                tar_filename = os.path.basename(container_path)
                try:
                    member_info = tar.getmember(tar_filename)
                    extracted_file_obj = tar.extractfile(member_info)
                    if extracted_file_obj:
                        with open(host_path, 'wb') as f_out:
                            f_out.write(extracted_file_obj.read())
                        logger.info(f"Successfully copied {container_path} from image {image_id} to {host_path}")
                        return True
                    else:
                        logger.error(f"Failed to extract file object for {tar_filename} from tar archive (image: {image_id}).")
                        return False
                except KeyError:
                    all_members = tar.getmembers()
                    if len(all_members) == 1 and all_members[0].isfile():
                        logger.info(f"Found single file '{all_members[0].name}' in archive, extracting as {tar_filename} to {host_path}.")
                        extracted_file_obj = tar.extractfile(all_members[0])
                        if extracted_file_obj:
                            with open(host_path, 'wb') as f_out:
                                f_out.write(extracted_file_obj.read())
                            logger.info(f"Successfully extracted single member '{all_members[0].name}' as {tar_filename} to {host_path}")
                            return True
                    logger.error(f"File '{tar_filename}' (from {container_path}) not found in tar archive from image {image_id}. Members: {[m.name for m in all_members]}")
                    return False
        except docker.errors.NotFound as e_nf: # Specific error if get_archive path not found
            logger.warning(f"Path {container_path} not found in temp container {temp_container.id if temp_container else 'UnknownTempID'} (from image {image_id}) via get_archive: {e_nf}")
            return False
        except tarfile.ReadError as e_tar:
            logger.error(f"Tarfile read error for {container_path} from image {image_id}: {e_tar}. Tar data might be empty/corrupt.")
            return False
        except Exception as e: # General errors
            logger.error(f"General error copying {container_path} from image {image_id} to {host_path}: {str(e)}", exc_info=True)
            return False
        finally:
            if temp_container:
                try:
                    logger.debug(f"Removing temporary container {temp_container.id}")
                    temp_container.remove(force=True) # force=True to ensure removal
                except docker.errors.NotFound:
                    logger.debug(f"Temporary container {temp_container.id} already removed or not found during cleanup.")
                except Exception as e_remove:
                    logger.error(f"Error removing temporary container {temp_container.id}: {e_remove}")
        return False # Should have returned True earlier on success

    def clone_repo_and_create_image(self, repo_url, repo_name, issue_number, issue_body, branch_name=None):
        build_context_id = str(uuid.uuid4())
        
        build_context_path = os.path.join(self.dockerfiles_dir, build_context_id)
        os.makedirs(build_context_path, exist_ok=True)

        build_logs_list = []

        if self.simulation_mode or not self.client:
            logger.info(f"[SIMULATION] Would build image for {repo_name} issue #{issue_number} context {build_context_id}")
            sim_output_path = os.path.join(build_context_path, "analysis_output.json")
            sim_error_path = os.path.join(build_context_path, "analysis_error.log")
            try:
                with open(sim_output_path, 'w') as f_out:
                    json.dump({"issue_summary": "Simulated summary", "code_analysis_summary": "Simulated code analysis", "proposed_solutions": ["Simulated solution 1"]}, f_out)
                with open(sim_error_path, 'w') as f_err:
                    f_err.write("Simulated error log content if any.")
                logger.info(f"[SIMULATION] Created dummy output files in {build_context_path}")
            except IOError as e_io_sim:
                logger.error(f"[SIMULATION] Error creating dummy files: {e_io_sim}")

            return f"simulated_image_id_{build_context_id[:8]}", build_context_id, ["Simulated build log line 1"], None

        try:
            dockerfile_path = self._create_custom_dockerfile(
                container_id=build_context_id,
                repo_url=repo_url,
                repo_name=repo_name,
                branch=branch_name if branch_name else 'main',
                access_token=None, 
                issue_body_content=issue_body
            )

            logger.info(f"Building Docker image with context: {build_context_path}, Dockerfile: {os.path.basename(dockerfile_path)}")
            image_tag = f"repopilot-issue-{build_context_id[:8]}"
            image = None 
            
            response = self.client.api.build(
                path=build_context_path,
                dockerfile=os.path.basename(dockerfile_path),
                tag=image_tag,
                rm=True,
                forcerm=True,
                pull=True,
                decode=True
            )
            
            for chunk in response:
                if 'stream' in chunk:
                    log_line = chunk['stream'].strip()
                    if log_line:
                        logger.info(f"Build log: {log_line}")
                        build_logs_list.append(log_line)
                elif 'errorDetail' in chunk:
                    error_message = chunk['errorDetail']['message']
                    logger.error(f"Docker Image Build Error: {error_message}")
                    build_logs_list.append(f"ERROR: {error_message}")
                    raise docker.errors.BuildError(error_message, build_logs_list)

            try:
                image = self.client.images.get(image_tag)
                logger.info(f"Successfully built image: {image.id} with tags: {image.tags}")
            except docker.errors.ImageNotFound:
                logger.error(f"Build failed for image {image_tag}. Check build logs above.")
                full_build_log = "\\n".join(build_logs_list)
                raise docker.errors.BuildError(f"Image {image_tag} not found after build. Logs: {full_build_log}", build_logs_list)

            output_json_host_path = os.path.join(self.dockerfiles_dir, build_context_id, "analysis_output.json")
            error_log_host_path = os.path.join(self.dockerfiles_dir, build_context_id, "analysis_error.log")

            logger.info(f"Attempting to copy analysis files from image {image.id} to host for build context {build_context_id}")
            copy_output_success = self._copy_file_from_image_to_host(image.id, "/app/analysis_output.json", output_json_host_path)
            copy_error_success = self._copy_file_from_image_to_host(image.id, "/app/analysis_error.log", error_log_host_path)
            
            if not copy_output_success:
                 build_logs_list.append("Warning: Failed to copy analysis_output.json from image to host.")
            if not copy_error_success:
                 build_logs_list.append("Warning: Failed to copy analysis_error.log from image to host.")
            
            return image.id, build_context_id, build_logs_list, None # repo_dir is None

        except docker.errors.BuildError as e_build: # Corrected variable name
            logger.error(f"Docker BuildError for {repo_name} issue #{issue_number}: {e_build.msg}") # Use e_build.msg
            error_log_details = "\n".join(e_build.build_log) if e_build.build_log else str(e_build.msg)
            build_logs_list.append(f"Build Failed: {error_log_details}")
            # Attempt to cleanup build context even on build failure
            # self.cleanup_dockerfile_context(build_context_id) # Temporarily disabled for easier debugging of build errors
            logger.warning(f"Dockerfile context for build_id {build_context_id} has been preserved for debugging due to BuildError.")
            return None, build_context_id, build_logs_list, None
        except docker.errors.APIError as e_api:
            logger.error(f"Docker APIError for {repo_name} issue #{issue_number}: {e_api}", exc_info=True)
            build_logs_list.append(f"Docker API Error: {str(e_api)}")
            self.cleanup_dockerfile_context(build_context_id)
            return None, build_context_id, build_logs_list, None
        except Exception as e_gen: # Corrected variable name and added content
            logger.error(f"General error in clone_repo_and_create_image for {repo_name} issue #{issue_number}: {str(e_gen)}", exc_info=True)
            build_logs_list.append(f"General Error: {str(e_gen)}")
            self.cleanup_dockerfile_context(build_context_id) # Attempt cleanup
            return None, build_context_id, build_logs_list, None
        # Removed finally block that was empty. Cleanup of build context directory can be done in except blocks or after this method returns.

    def cleanup_dockerfile_context(self, build_context_id: str):
        """Clean up a Dockerfile build context directory."""
        context_path = os.path.join(self.dockerfiles_dir, build_context_id)
        if os.path.exists(context_path):
            try:
                shutil.rmtree(context_path)
                logger.info(f"Successfully cleaned up Dockerfile context: {context_path}")
            except OSError as e:
                logger.error(f"Error cleaning up Dockerfile context {context_path}: {e.strerror}")
        else:
            logger.debug(f"Dockerfile context cleanup skipped: path not found for {build_context_id}")

    def cleanup_cloned_repo(self, repo_path: Optional[str]):
        """Clean up a cloned repository directory if it exists and is provided."""
        if repo_path and os.path.exists(repo_path):
            try:
                shutil.rmtree(repo_path)
                logger.info(f"Successfully cleaned up cloned repository: {repo_path}")
            except OSError as e:
                logger.error(f"Error cleaning up cloned repository {repo_path}: {e.strerror}")
        else:
            logger.debug(f"Cleanup for cloned repo skipped: path not provided or does not exist ('{repo_path}').") 