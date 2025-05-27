import os
import subprocess
import logging
import uuid
import json
from typing import Dict, Optional, Any, Callable
# import shlex # No longer used directly
# import tempfile # No longer used directly
import time # Still used in async create_container simulation path (if that path were still active)
# import docker # No longer used for client
from docker.errors import BuildError, APIError, ImageNotFound # Import specific errors
# import tarfile # No longer used
# import io # No longer used
import shutil
import select # For non-blocking reads
import platform

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DockerManager:
    def __init__(self, use_sudo=None):
        self.base_image = "repopilot/base:latest" 
        self.containers_dir = os.path.join(os.path.expanduser('~'), '.repopilot', 'containers')
        self.dockerfiles_dir = os.path.abspath('docker_files')
        self.clone_dir = os.path.abspath('cloned_repos')
        os.makedirs(self.containers_dir, exist_ok=True)
        os.makedirs(self.dockerfiles_dir, exist_ok=True)
        os.makedirs(self.clone_dir, exist_ok=True)
        
        if use_sudo is None:
            try:
                # Try without sudo first
                subprocess.run(["docker", "info"], check=True, capture_output=True, timeout=5)
                self.use_sudo = False
                logger.info("Docker access available without sudo.")
            except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
                try:
                    # Try with passwordless sudo
                    subprocess.run(["sudo", "-n", "docker", "info"], check=True, capture_output=True, timeout=5)
                    self.use_sudo = True
                    logger.info("Docker access available with passwordless sudo.")
                except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
                    # Fallback: assume sudo might be needed with a password, or Docker isn't set up.
                    # The actual commands will fail later if Docker isn't usable.
                    self.use_sudo = True # Default to trying with sudo if checks fail or are inconclusive.
                    logger.warning("Could not confirm Docker access without sudo or with passwordless sudo. Will attempt with sudo. Ensure Docker is running and permissions are set.")
        else:
            self.use_sudo = use_sudo
    
    def _run_docker_command(self, args: list, log_callback: Optional[Callable[[str, str], None]] = None, check: bool = False, **kwargs) -> subprocess.CompletedProcess:
        """
        Run a docker command with or without sudo as needed, streaming output if a callback is provided.
        The 'check' parameter behaves like in subprocess.run. If True and the process exits with a non-zero code,
        CalledProcessError is raised.
        Returns a CompletedProcess-like object (or raises an error if check=True).
        Additional kwargs are passed to Popen.
        """
        cmd = ["sudo", "docker"] if self.use_sudo else ["docker"]
        cmd.extend(args)
        
        full_command_str = ' '.join(cmd) # For logging
        logger.debug(f"Executing Docker command: {full_command_str}")
        if log_callback:
            log_callback(f"Executing: docker {' '.join(args)}", "info")

        # Ensure text=True is not passed directly to Popen if we handle decoding
        kwargs.pop('text', None)
        kwargs.pop('capture_output', None) # We manage pipes directly

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False, **kwargs) # text=False to handle bytes

        stdout_lines = []
        stderr_lines = []

        try:
            # Use select for non-blocking reads if on Unix-like system
            # For Windows, this approach would need adjustment (e.g., threads)
            # Assuming Linux environment for Docker operations primarily.
            if os.name != 'posix':
                 logger.warning("_run_docker_command uses select() for non-blocking I/O, which is POSIX-specific. Streaming might behave differently on other OS.")

            streams = [process.stdout, process.stderr]
            while streams:
                readable_streams, _, _ = select.select(streams, [], [], 0.1) # Small timeout
                for stream in readable_streams:
                    line_bytes = stream.readline()
                    if line_bytes:
                        line = line_bytes.decode('utf-8', errors='replace').strip()
                        if stream is process.stdout:
                            stdout_lines.append(line)
                            if log_callback:
                                try:
                                    log_callback(line, "stdout")
                                except Exception as e_cb_stdout:
                                    logger.error(f"Error in stdout log_callback: {e_cb_stdout}")
                        elif stream is process.stderr:
                            stderr_lines.append(line)
                            if log_callback:
                                try:
                                    log_callback(line, "stderr")
                                except Exception as e_cb_stderr:
                                    logger.error(f"Error in stderr log_callback: {e_cb_stderr}")
                    else: # End of stream
                        streams.remove(stream)
                
                if process.poll() is not None and not readable_streams: # Process finished and no more data in pipes
                    break
        finally:
            # Ensure process is cleaned up
            if process.poll() is None: # If still running
                try:
                    process.terminate() # Try to terminate gracefully
                    process.wait(timeout=5) # Wait for termination
                except subprocess.TimeoutExpired:
                    process.kill() # Force kill if terminate fails
                except Exception as e_term:
                    logger.error(f"Error during Popen process cleanup: {e_term}")
            
            # Close pipes
            if process.stdout: process.stdout.close()
            if process.stderr: process.stderr.close()
            
        returncode = process.returncode if process.returncode is not None else -1 # Ensure returncode is set

        if check and returncode != 0:
            raise subprocess.CalledProcessError(returncode, cmd, output='\\n'.join(stdout_lines), stderr='\\n'.join(stderr_lines))

        # Mimic CompletedProcess object
        return subprocess.CompletedProcess(args=cmd, returncode=returncode, stdout='\\n'.join(stdout_lines), stderr='\\n'.join(stderr_lines))

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
            host_analysis_results_dir = os.path.join(self.dockerfiles_dir, container_id, "analysis_results")
            # Create the directory and set permissions
            os.makedirs(host_analysis_results_dir, exist_ok=True)
            os.chmod(host_analysis_results_dir, 0o777)  # Set full permissions
            logger.info(f"Mounting host analysis results directory: {host_analysis_results_dir}")
            run_cmd = [
                "run", "-d",
                "--network", "llm-net",
                "--name", container_name,
                "-v", f"{host_analysis_results_dir}:/workspace/analysis_results",
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
    """
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

    """
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
# Point to Ollama server in the llm-net network
ENV OLLAMA_HOST=my-ollama:11434
ENV OLLAMA_API_BASE=http://my-ollama:11434
ENV REPO_BASENAME={repo_basename}

# Install curl and then Aider using its official script
RUN wget -qO- https://aider.chat/install.sh | sh


# Setup app directory and copy necessary files
WORKDIR /app
COPY container_agent.py /app/container_agent.py
COPY container_agent_requirements.txt /app/container_agent_requirements.txt
{issue_txt_copy_instruction}

# Install Python dependencies for the agent (e.g., ollama)
# Aider is installed above via script, ensure container_agent_requirements.txt reflects this (e.g., no aider-chat pip install)
RUN pip install --no-cache-dir -r /app/container_agent_requirements.txt

# Copy and run the script to clone the repository and install its specific dependencies
COPY clone_repo.sh /app/clone_repo.sh
# RUN chmod +x /usr/local/bin/clone_repo.sh
# Run the clone script. It handles cloning, checkout, and installing repo-specific dependencies.
# It will exit with non-zero if cloning fails, stopping the build.
RUN /app/clone_repo.sh

# Set the entrypoint for the container (can be overridden)
# The container_agent.py will be executed when the container runs with this entrypoint.
ENTRYPOINT ["python3", "/app/container_agent.py"]

# Default command (useful if entrypoint is just python3, or for interactive use)
# CMD ["/app/container_agent.py"]

# For development, keep the container running
CMD ["tail", "-f", "/dev/null"]
"""
        
        logger.info(f"Dockerfile created at: {dockerfile_path}")
        # logger.debug(f"Dockerfile content:\n{dockerfile_content}") # Can be very verbose

        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile_content)
        
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
    
    def execute_command(self, container_id: str, command: str, log_callback: Optional[Callable[[str, str], None]] = None) -> Optional[str]:
        """Execute a command in a container, optionally streaming output."""
        try:
            container_config = self._get_container_config(container_id)
            if not container_config:
                logger.error(f"Container config not found for ID: {container_id}")
                if log_callback: log_callback(f"Cannot execute command, container {container_id} not found or not running.", "error")
                return None
                
            container_name = container_config.get('container_name')
            if not container_name:
                logger.error(f"Container name not found in config for ID: {container_id}")
                if log_callback: log_callback(f"Cannot execute command, container {container_id} not found or not running.", "error")
                return None
                
            if container_config.get('status') != 'running':
                logger.error(f"Container {container_name} is not running")
                if log_callback: log_callback(f"Cannot execute command, container {container_name} is not running.", "error")
                return None
                
            logger.info(f"Executing command in container {container_name}: {command}")
            if log_callback: log_callback(f"Executing in {container_name}: {command}", "info")

            cmd_args = ["exec", container_name, "/bin/bash", "-c", command]
            process_result = self._run_docker_command(cmd_args, log_callback=log_callback, check=False)
            if process_result.returncode != 0:
                # Stderr is already streamed by log_callback
                logger.error(f"Command execution failed in {container_name} (code {process_result.returncode}). Summary: {process_result.stderr[:200]}")
                return None # Or return error indication
            return process_result.stdout # Return collected stdout
        except Exception as e:
            logger.error(f"Exception executing command in {container_name}: {str(e)}")
            if log_callback: log_callback(f"Exception during exec: {str(e)}", "error")
            return None
    
    def get_container_logs(self, container_id: str) -> Optional[str]:
        """Get logs from a container"""
        try:
            container_config = self._get_container_config(container_id)
            if not container_config:
                logger.error(f"Container config not found for ID: {container_id}")
                return None
                
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

    def _copy_file_from_image_to_host(self, image_id_or_tag, container_path, host_path, log_callback: Optional[Callable[[str, str], None]] = None):
        """
        Copies a file from a given path inside an image to a specified host path.
        Uses Docker CLI commands via _run_docker_command.
        Accepts an optional log_callback for streaming.
        """
        temp_container_id_val = None # Renamed to avoid conflict with temp_container_id in some scopes
        temp_container_name = f"repopilot-copy-temp-{uuid.uuid4().hex[:12]}"
        try:
            create_cmd_args = ["create", "--name", temp_container_name, image_id_or_tag]
            logger.debug(f"Creating temporary container from image {image_id_or_tag} with name {temp_container_name}")
            if log_callback: log_callback(f"Creating temp container {temp_container_name} from {image_id_or_tag} for copy...", "info")
            
            process_create = self._run_docker_command(create_cmd_args, log_callback=log_callback, check=False)

            if process_create.returncode != 0:
                err_msg = f"Failed to create temporary container {temp_container_name} from image {image_id_or_tag}. Stderr: {process_create.stderr.strip()}"
                logger.error(err_msg)
                if log_callback: log_callback(err_msg, "error")
                if process_create.stdout.strip() and log_callback: # Log stdout as well
                    log_callback(f"Stdout from failed create: {process_create.stdout.strip()}", "info")
                return False
            
            temp_container_id_val = process_create.stdout.strip()
            if not temp_container_id_val:
                 logger.error(f"Temporary container ID not captured from stdout for image {image_id_or_tag} using name {temp_container_name}. stdout: '{process_create.stdout}', stderr: '{process_create.stderr}'")
                 if log_callback: log_callback(f"Warning: Temp container ID not found for {temp_container_name}, copy may fail or use name.", "warning")
                 temp_container_id_val = temp_container_name # Fallback to using name for cp and rm
                 # If create returned 0 but no ID, this is unusual. Proceed with name.
            
            if log_callback: log_callback(f"Temporary container {temp_container_id_val[:12]} (name: {temp_container_name}) created.", "info")

            os.makedirs(os.path.dirname(host_path), exist_ok=True)
            
            docker_source_path = f"{temp_container_id_val}:{container_path}" # Use temp_container_id_val (actual ID or name)
            cp_cmd_args = ["cp", docker_source_path, host_path]
            logger.debug(f"Copying {docker_source_path} to {host_path}")
            if log_callback: log_callback(f"Copying {container_path} from temp container to {host_path}...", "info")
            
            process_cp = self._run_docker_command(cp_cmd_args, log_callback=log_callback, check=False)

            if process_cp.returncode != 0:
                err_msg = f"Failed to copy {container_path} from temp container {temp_container_id_val[:12]}. Stderr: {process_cp.stderr.strip()}"
                logger.error(err_msg)
                if log_callback: log_callback(err_msg, "error")
                if process_cp.stdout.strip() and log_callback:
                    log_callback(f"Stdout from failed cp: {process_cp.stdout.strip()}", "info")
                return False

            if log_callback: log_callback(f"Successfully copied {container_path} to {host_path}.", "success")
            return True

        except Exception as e:
            logger.error(f"General error in _copy_file_from_image_to_host for image {image_id_or_tag}: {str(e)}", exc_info=True)
            if log_callback: log_callback(f"Error during file copy: {str(e)}", "error")
            return False
        finally:
            # Use temp_container_id_val if set (actual ID from create or the name), else fallback to temp_container_name
            id_to_remove = temp_container_id_val if temp_container_id_val else temp_container_name
            if id_to_remove: # Ensure we have something to attempt removal on
                logger.debug(f"Attempting to remove temporary container: {id_to_remove}")
                if log_callback: log_callback(f"Cleaning up temporary container {id_to_remove[:12]}...", "info")
                rm_cmd_args = ["rm", "-f", id_to_remove]
                # For cleanup, we typically don't need to stream its output in detail unless debugging cleanup itself.
                # Pass a minimal or no callback for cleanup.
                process_rm = self._run_docker_command(rm_cmd_args, log_callback=None, check=False) 
                if process_rm.returncode != 0:
                    err_msg = f"Failed to remove temporary container {id_to_remove}. Stderr: {process_rm.stderr.strip()}"
                    logger.error(err_msg)
                    if log_callback: log_callback(err_msg, "warning") # Log as warning as main op might have succeeded
                else:
                    if log_callback: log_callback(f"Successfully removed temporary container {id_to_remove[:12]}.", "info")
            else:
                 logger.debug("No temporary container ID or name was set, skipping cleanup.")
                 if log_callback: log_callback("Skipped temp container cleanup as no ID/name was available.", "debug")

    def clone_repo_and_create_image(self, repo_url, repo_name, issue_number, issue_body, branch_name=None, access_token=None, log_callback: Optional[Callable[[str, str], None]] = None):
        """
        Clone a repository and create a Docker image for it.
        Returns a tuple of (image_id_or_tag, build_context_id, build_logs_list, repo_dir)
        """
        build_context_id = str(uuid.uuid4())
        dockerfile_path = os.path.join(self.dockerfiles_dir, build_context_id, "Dockerfile")
        build_logs_list = []

        try:
            # Create build context directory and copy necessary files
            build_context_dir = os.path.join(self.dockerfiles_dir, build_context_id)
            os.makedirs(build_context_dir, exist_ok=True)
            analysis_results_dir = os.path.join(build_context_dir, "analysis_results")
            os.makedirs(analysis_results_dir, exist_ok=True)
            os.chmod(analysis_results_dir, 0o777)  # Set full permissions for analysis results directory

            if log_callback: log_callback(f"Preparing build context {build_context_id} for {repo_name} issue #{issue_number}", "info")
            dockerfile_path = self._create_custom_dockerfile(
                container_id=build_context_id,
                repo_url=repo_url,
                repo_name=repo_name,
                branch=branch_name if branch_name else 'main',
                access_token=access_token,
                issue_body_content=issue_body
            )

            logger.info(f"Building Docker image with context: {build_context_dir}, Dockerfile: {os.path.basename(dockerfile_path)}")
            if log_callback: log_callback(f"Dockerfile created at {dockerfile_path}. Starting image build.", "info")
            
            image_tag = f"repopilot-issue-{build_context_id[:8]}"
            
            build_cmd_args = [
                "build",
                "-t", image_tag,
                "-f", dockerfile_path,
            ]

            # Add host.docker.internal mapping for Linux Docker builds
            # to allow container to connect to Ollama running on the host.
            # if platform.system() == "Linux":
            #     build_cmd_args.append("--add-host=host.docker.internal:host-gateway")

            build_cmd_args.append(build_context_dir)

            logger.info(f"Executing Docker build command: docker {' '.join(build_cmd_args)}")
            # build_logs_list will collect internal DockerManager logs, subprocess output is streamed by callback
            process_result = self._run_docker_command(build_cmd_args, log_callback=log_callback, check=False) # check=False to handle error manually

            # Collect stdout/stderr from process_result if needed, though callback should handle streaming
            # For build_logs_list, we might add a summary or key messages here.
            # if process_result.stdout: build_logs_list.extend(process_result.stdout.splitlines()) # Already handled by callback

            if process_result.returncode != 0:
                error_message = f"Docker image build failed (return code {process_result.returncode})."
                # Stderr is captured by callback, but also available in process_result.stderr
                if process_result.stderr:
                    # error_message += f" Stderr: {process_result.stderr.strip()}" # Redundant if streamed
                    logger.error(f"Build Stderr (summary): {process_result.stderr.strip()[:500]}...") # Log a summary
                
                logger.error(error_message)
                build_logs_list.append(f"ERROR: {error_message}") # Add to local log summary
                if log_callback: log_callback(f"ERROR: {error_message}", "error")
                
                # Constructing a BuildError-like structure for the return
                # The original BuildError took (msg, build_log_list)
                # Here, build_log is streamed, so we pass the summary collected in build_logs_list
                raise BuildError(error_message, build_logs_list)

            image_id_or_tag_for_copy = image_tag 
            logger.info(f"Successfully built and tagged image: {image_tag}")
            if log_callback: log_callback(f"Successfully built and tagged image: {image_tag}", "success")
            build_logs_list.append(f"Image built: {image_tag}")

            # Create build context directory and copy necessary files
            build_context_dir = os.path.join(self.dockerfiles_dir, build_context_id)
            os.makedirs(build_context_dir, exist_ok=True)
            analysis_results_dir = os.path.join(build_context_dir, "analysis_results")
            os.makedirs(analysis_results_dir, exist_ok=True)
            os.chmod(analysis_results_dir, 0o777)  # Set full permissions for analysis results directory
            
            # Copy container_agent.py to build context
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
                branch_name if branch_name else 'main',  # Use branch_name here
                repo_basename,
                access_token if access_token else ''
            )
        
            with open(os.path.join(build_context_dir, 'clone_repo.sh'), 'w') as f:
                f.write(clone_script_content)
            os.chmod(os.path.join(build_context_dir, 'clone_repo.sh'), 0o755)
            
            if issue_body is not None:
                with open(os.path.join(build_context_dir, 'issue.txt'), 'w') as f_issue:
                    f_issue.write(issue_body)
                logger.info(f"Created issue.txt in build context: {os.path.join(build_context_dir, 'issue.txt')}")
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
# Point to Ollama server in the llm-net network
ENV OLLAMA_HOST=my-ollama:11434
ENV OLLAMA_API_BASE=http://my-ollama:11434
ENV REPO_BASENAME={repo_basename}

# Install curl and then Aider using its official script
RUN wget -qO- https://aider.chat/install.sh | sh


# Setup app directory and copy necessary files
WORKDIR /app
COPY container_agent.py /app/container_agent.py
COPY container_agent_requirements.txt /app/container_agent_requirements.txt
{issue_txt_copy_instruction}

# Install Python dependencies for the agent (e.g., ollama)
# Aider is installed above via script, ensure container_agent_requirements.txt reflects this (e.g., no aider-chat pip install)
RUN pip install --no-cache-dir -r /app/container_agent_requirements.txt

# Copy and run the script to clone the repository and install its specific dependencies
COPY clone_repo.sh /app/clone_repo.sh
# RUN chmod +x /usr/local/bin/clone_repo.sh
# Run the clone script. It handles cloning, checkout, and installing repo-specific dependencies.
# It will exit with non-zero if cloning fails, stopping the build.
RUN /app/clone_repo.sh

# Set the entrypoint for the container (can be overridden)
# The container_agent.py will be executed when the container runs with this entrypoint.
ENTRYPOINT ["python3", "/app/container_agent.py"]

# Default command (useful if entrypoint is just python3, or for interactive use)
# CMD ["/app/container_agent.py"]

# For development, keep the container running
CMD ["tail", "-f", "/dev/null"]
"""
        
            logger.info(f"Dockerfile created at: {dockerfile_path}")
            # logger.debug(f"Dockerfile content:\n{dockerfile_content}") # Can be very verbose

            with open(dockerfile_path, 'w') as f:
                f.write(dockerfile_content)
            
            return image_id_or_tag_for_copy, build_context_id, build_logs_list, None # repo_dir is None

        except BuildError as e_build:
            logger.error(f"Docker BuildError for {repo_name} issue #{issue_number}: {e_build.msg}")
            # build_log is now part of e_build.msg or streamed if callback was used
            error_log_details = e_build.msg # Or construct from e_build.build_log if still populated
            build_logs_list.append(f"Build Failed: {error_log_details}")
            if log_callback: log_callback(f"Build Failed: {error_log_details}", "error")
            
            logger.warning(f"Dockerfile context for build_id {build_context_id} has been preserved for debugging due to BuildError.")
            return None, build_context_id, build_logs_list, None
        except APIError as e_api: # This error might be less relevant now if not using docker-py client directly
            logger.error(f"Docker APIError for {repo_name} issue #{issue_number}: {e_api}", exc_info=True)
            err_msg = f"Docker API Error: {str(e_api)}"
            build_logs_list.append(err_msg)
            if log_callback: log_callback(err_msg, "error")
            self.cleanup_dockerfile_context(build_context_id)
            return None, build_context_id, build_logs_list, None
        except Exception as e_gen:
            logger.error(f"General error in clone_repo_and_create_image for {repo_name} issue #{issue_number}: {str(e_gen)}", exc_info=True)
            err_msg = f"General Error: {str(e_gen)}"
            build_logs_list.append(err_msg)
            if log_callback: log_callback(err_msg, "error")
            self.cleanup_dockerfile_context(build_context_id)
            return None, build_context_id, build_logs_list, None

    def cleanup_dockerfile_context(self, build_context_id: str):
        """Clean up a Dockerfile build context directory."""
        context_path = os.path.join(self.dockerfiles_dir, build_context_id)
        if os.path.exists(context_path):
            try:
                # shutil.rmtree(context_path)
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