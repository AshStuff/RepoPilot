#!/usr/bin/env python3
import sys
import os
import json
import logging
import re # Ensure re is imported
import time # Add time import
import subprocess # Add subprocess import for docker commands

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

try:
    from github import Github
    PYGITHUB_AVAILABLE = True
except ImportError:
    PYGITHUB_AVAILABLE = False

# --- BEGIN: Setup for logging ---
ANALYSIS_RESULTS_DIR = '/workspace/analysis_results'
# Ensure the target directory for logs exists
os.makedirs(ANALYSIS_RESULTS_DIR, exist_ok=True)

ANALYSIS_ERR_LOG_PATH = os.path.join(ANALYSIS_RESULTS_DIR, 'analysis_err.log')

# Configure logging to go to ANALYSIS_ERR_LOG_PATH
# This basicConfig should be effective for all subsequent logger calls in this script.
logging.basicConfig(
    filename=ANALYSIS_ERR_LOG_PATH, 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(module)s - %(funcName)s - %(lineno)d - %(message)s', # More detailed format
    force=True # Ensure basicConfig overrides any existing handlers if script is re-imported/re-run in same process
)
logger = logging.getLogger(__name__)

# Keep a reference to the original stdout if needed for the final status message.
original_stdout = sys.stdout
# --- END: Setup for logging ---

# Log a startup message immediately.
logger.info("container_agent.py: Execution started.")

# Removed problematic sys.path.append
logger.info("container_agent.py: Initial imports (json, logging) successful.")

AIDER_AVAILABLE = False
try:
    logger.info("container_agent.py: Attempting to import aider components.")
    from aider.coders import Coder
    from aider.models import Model
    from aider.io import InputOutput
    logger.info("container_agent.py: Successfully imported aider components.")
    AIDER_AVAILABLE = True
except ImportError as e_import:
    logger.error(f"container_agent.py: ImportError for aider components: {str(e_import)}")
    logger.warning("container_agent.py: WARNING - aider components not found. Ensure aider is installed in the environment.")

# If aider import failed, log it officially now that logger is up.
if not AIDER_AVAILABLE:
    logger.warning("Aider components (Coder, Model, InputOutput) could not be imported. LLM analysis will be skipped.")

if not PYGITHUB_AVAILABLE:
    logger.warning("PyGithub could not be imported. Pull Request creation will be skipped.")

# --- Directory and File Reading Tools (to be used by the LLM agent) ---
def list_directory_contents(path='.'):
    """Lists files and directories at the given path within the /workspace/repo_name/ directory.
    Defaults to the root of the cloned repository.
    Path should be relative to /workspace/repo_name/.
    """
    base_repo_path = _get_repo_path()
    if not base_repo_path:
        return "Error: Repository path could not be determined."
    
    target_path = os.path.join(base_repo_path, path.lstrip('/'))
    
    if not os.path.exists(target_path) or not os.path.isdir(target_path):
        return f"Error: Path '{path}' does not exist or is not a directory within the repository."
    try:
        return str(os.listdir(target_path))
    except Exception as e:
        return f"Error listing directory '{path}': {str(e)}"

def read_file_content(filepath):
    """Reads the content of a specified file within the /workspace/repo_name/ directory.
    Filepath should be relative to /workspace/repo_name/.
    """
    logger.info(f"container_agent.py: read_file_content called with filepath: {filepath}")
    base_repo_path = _get_repo_path()
    if not base_repo_path:
        return "Error: Repository path could not be determined."

    target_filepath = os.path.join(base_repo_path, filepath.lstrip('/'))

    if not os.path.exists(target_filepath) or not os.path.isfile(target_filepath):
        return f"Error: File '{filepath}' does not exist or is not a file within the repository."
    try:
        with open(target_filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # Limit content size to avoid overwhelming LLM or output
        max_len = 15000 
        if len(content) > max_len:
            return content[:max_len] + "\n... [file truncated]"
        return content
    except Exception as e:
        return f"Error reading file '{filepath}': {str(e)}"

def _get_repo_path():
    logger.info("container_agent.py: _get_repo_path called")
    """Determines the path to the cloned repository inside the container.
    Uses REPO_BASENAME environment variable if set, otherwise tries to discover it.
    """
    workspace_dir = '/workspace'
    repo_basename_env = os.environ.get('REPO_BASENAME')
    if repo_basename_env:
        found_path = os.path.join(workspace_dir, repo_basename_env)
        if os.path.exists(found_path) and os.path.isdir(found_path):
            logger.info(f"container_agent.py: Using REPO_BASENAME env var, repo path: {found_path}")
            return found_path
        else:
            logger.warning(f"container_agent.py: REPO_BASENAME '{repo_basename_env}' not found at {found_path}. Falling back to discovery.")

    # Fallback to discovery if REPO_BASENAME is not set or path doesn't exist
    try:
        logger.info(f"container_agent.py: REPO_BASENAME not set or invalid. Discovering repo in {workspace_dir}")
        entries = os.listdir(workspace_dir)
        logger.info(f"container_agent.py: Entries in {workspace_dir}: {entries}")
        
        # Filter out common non-repo items like '.DS_Store' or if other files are expected
        potential_repos = [d for d in entries if os.path.isdir(os.path.join(workspace_dir, d)) and not d.startswith('.')]

        if not potential_repos:
            logger.error("No suitable repository directories found in /workspace.")
            return None
        
        # If multiple, could add logic or take the first one
        # For now, assuming the first valid directory is the repo.
        repo_name_dir = potential_repos[0]
        found_path = os.path.join(workspace_dir, repo_name_dir)
        logger.info(f"container_agent.py: Discovered repo path: {found_path}")
        return found_path
    except FileNotFoundError:
        logger.error(f"Workspace directory '{workspace_dir}' not found.")
        return None
    except Exception as e:
        logger.error(f"Error determining repo path via discovery: {str(e)}")
        return None

def get_all_codebase_files(repo_base_path):
    """Walks the repository path and returns a list of all file paths relative to the repo_base_path."""
    all_files = []
    if not repo_base_path or not os.path.isdir(repo_base_path):
        logger.error(f"Cannot get codebase files, invalid repo_base_path: {repo_base_path}")
        return all_files

    for root, _, files in os.walk(repo_base_path):
        for file in files:
            # Ignore .git directory and its contents
            if '.git' in root.split(os.sep):
                continue
            # Optionally, ignore other common unwanted files/directories (e.g., __pycache__)
            if '__pycache__' in root.split(os.sep) or file.startswith('.'): # Example: ignore hidden files
                continue

            full_path = os.path.join(root, file)
            # Return absolute paths for aider
            all_files.append(full_path)
    logger.info(f"Found {len(all_files)} files in codebase at {repo_base_path} (excluding .git, hidden files, and __pycache__)")
    return all_files

def cleanup_container():
    """Attempts to kill the current Docker container after analysis completion.
    
    REQUIREMENTS FOR THIS FUNCTIONALITY TO WORK:
    
    1. Docker Socket Access: The container needs access to the Docker daemon.
       Mount the Docker socket when running the container:
       docker run -v /var/run/docker.sock:/var/run/docker.sock ...
    
    2. Docker CLI: The container needs the Docker CLI installed.
       Add to Dockerfile: RUN apt-get update && apt-get install -y docker.io
    
    3. Permissions: The container process needs permission to access Docker.
       Either run as root or add user to docker group.
    
    4. Alternative Setup (Host-based cleanup):
       If self-cleanup is not desired, the host system should monitor
       the container and clean it up when analysis_output.json is written.
    
    DETECTION METHODS:
    - Tries to get container ID from hostname (most reliable)
    - Falls back to parsing /proc/self/cgroup
    - Uses HOSTNAME environment variable as last resort
    
    CLEANUP METHODS (in order of preference):
    - docker kill <container_id>
    - docker stop <container_id>  
    - os._exit(0) to force container process termination
    
    Returns:
        bool: True if cleanup was successful, False otherwise
    """
    logger.info("Starting container cleanup process...")
    
    try:
        # Get the current container ID from /proc/self/cgroup or hostname
        container_id = None
        
        # Method 1: Try to get container ID from hostname (works in most Docker setups)
        try:
            container_id = os.uname().nodename
            if len(container_id) == 12 or len(container_id) == 64:  # Docker container ID length
                logger.info(f"Container ID detected from hostname: {container_id}")
            else:
                container_id = None
        except:
            pass
            
        # Method 2: Try to get container ID from /proc/self/cgroup
        if not container_id:
            try:
                with open('/proc/self/cgroup', 'r') as f:
                    cgroup_content = f.read()
                # Look for docker container ID in cgroup
                for line in cgroup_content.splitlines():
                    if 'docker' in line and '/' in line:
                        parts = line.split('/')
                        if len(parts) > 1:
                            potential_id = parts[-1]
                            if len(potential_id) >= 12:
                                container_id = potential_id[:12]  # Use first 12 chars
                                logger.info(f"Container ID detected from cgroup: {container_id}")
                                break
            except Exception as e:
                logger.warning(f"Could not read /proc/self/cgroup: {e}")
        
        # Method 3: Try environment variable if set by docker run
        if not container_id:
            container_id = os.environ.get('HOSTNAME')
            if container_id:
                logger.info(f"Container ID from HOSTNAME env var: {container_id}")
        
        if not container_id:
            logger.error("Could not determine container ID for cleanup")
            return False
            
        # Attempt to kill the container using docker CLI
        logger.info(f"Attempting to kill container {container_id}...")
        
        # Give a small delay to ensure any file operations are flushed
        time.sleep(2)
        
        # Try to kill the container
        try:
            # First try docker kill
            result = subprocess.run(['docker', 'kill', container_id], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                logger.info(f"Successfully killed container {container_id}")
                return True
            else:
                logger.warning(f"Docker kill failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error("Docker kill command timed out")
        except FileNotFoundError:
            logger.warning("Docker CLI not found in container")
        except Exception as e:
            logger.error(f"Error running docker kill: {e}")
            
        # Alternative: Try to stop the container
        try:
            result = subprocess.run(['docker', 'stop', container_id], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                logger.info(f"Successfully stopped container {container_id}")
                return True
            else:
                logger.warning(f"Docker stop failed: {result.stderr}")
        except Exception as e:
            logger.error(f"Error running docker stop: {e}")
            
        # If docker commands fail, try alternative cleanup methods
        logger.warning("Docker commands failed, attempting alternative cleanup...")
        
        # Try to exit the container process forcefully
        logger.info("Attempting to exit container process...")
        os._exit(0)  # Force exit the container process
        
    except Exception as e:
        logger.error(f"Container cleanup failed: {e}")
        return False
    
    return False

def main():
    logger.info("container_agent.py: main() started.")
    # The logger below was redundant as main() already logs its start.
    # logger.info("Container agent started (logged to stderr via logger config).") 

    analysis_results_dir = ANALYSIS_RESULTS_DIR # Use the global constant
    analysis_output_path = os.path.join(analysis_results_dir, 'analysis_output.json')

    final_output = {
        "issue_summary": "Analysis not performed.",
        "codebase_overview": {"files": [], "error": None},
        "solution_analysis": {"error": "Agent did not run or failed."}
    }

    issue_file_path = '/app/issue.txt'
    issue_content = ""
    logger.info(f"container_agent.py: Checking for issue file at {issue_file_path}")
    if os.path.exists(issue_file_path):
        with open(issue_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            issue_content = f.read()
        logger.info(f"Successfully read issue content from {issue_file_path}")
    else:
        logger.warning(f"Issue file not found at {issue_file_path}")
        issue_content = "Issue content not available."
        final_output["issue_summary"] = "Error: Issue file not found at /app/issue.txt."
        with open(analysis_output_path, 'w') as f_out:
            json.dump(final_output, f_out, indent=4)
        logger.error(f"container_agent.py: Critical error - issue file not found. Outputting error to {analysis_output_path} and exiting.")
        # Cleanup container even on error
        logger.info("Initiating container cleanup after error...")
        cleanup_container()
        return

    repo_path = _get_repo_path()
    if not repo_path:
        logger.error("Repository path could not be determined. Cannot analyze codebase.")
        final_output["codebase_overview"]["error"] = "Repository path could not be determined inside container."
        final_output["issue_summary"] = issue_content # We have issue, but no codebase
        final_output["solution_analysis"]["error"] = "Codebase not found."
        with open(analysis_output_path, 'w') as f_out:
            json.dump(final_output, f_out, indent=4)
        logger.error(f"container_agent.py: Critical error - repo path not found. Outputting error to {analysis_output_path} and exiting.")
        # Cleanup container even on error
        logger.info("Initiating container cleanup after error...")
        cleanup_container()
        return

    logger.info(f"Repository path determined as: {repo_path}")

    codebase_files = get_all_codebase_files(repo_path)
    final_output["codebase_overview"]["files"] = codebase_files
    if not codebase_files:
        final_output["codebase_overview"]["error"] = "No files found in the codebase or error during scan."
        logger.warning(f"No files found in the codebase at {repo_path}. Proceeding with issue only for LLM prompt.")
        # The prompt will show an empty file list.

    # Handle missing Aider components
    if not AIDER_AVAILABLE:
        logger.error("Aider components not available. Cannot initialize LLM agent for analysis.")
        # Preserve issue summary and codebase files (if any) gathered so far
        final_output["issue_summary"] = issue_content
        # final_output["codebase_overview"]["files"] is already set
        
        # Populate solution_analysis with detailed error information
        final_output["solution_analysis"] = {
            "error": "LLM Agent (aider) not available in container. Import failed for 'aider' components.",
            "issue_summary": "Analysis via LLM could not be performed because the 'aider' library is missing or not installed correctly.",
            "relevant_files": [],
            "solution_strategy": "Ensure the 'aider' library is installed in the container environment. Check Dockerfile and requirements.txt.",
            "further_investigation_needed": "Verify Python environment and dependencies within the container for 'aider' installation."
        }
        
        with open(analysis_output_path, 'w') as f_out:
            json.dump(final_output, f_out, indent=4)
        logger.error(f"container_agent.py: Critical error - Aider not available. Error report written to {analysis_output_path} and exiting.")
        # Cleanup container even on error
        logger.info("Initiating container cleanup after error...")
        cleanup_container()
        return # Exit main()

    coder = None
    try:
        logger.info("container_agent.py: Initializing Aider LLM coder...")

        # Ensure codebase_files are strings and valid paths for Aider.
        # get_all_codebase_files now returns absolute paths which are strings.
        valid_codebase_files = [f for f in codebase_files if os.path.exists(f) and os.path.isfile(f) and f.endswith(".py") and ".venv" not in os.path.normpath(f).split(os.sep)]
        if len(valid_codebase_files) != len(codebase_files):
            logger.warning(f"Some files from get_all_codebase_files were not valid, not .py, or in .venv. Initial: {len(codebase_files)}, Valid .py files: {len(valid_codebase_files)}")
        
        if not valid_codebase_files:
            logger.warning("No valid .py codebase files (excluding .venv) to provide to Aider. Aider will run with an empty file context, relying on the prompt's file list.")
            # Aider can still run with fnames=[]

        io = InputOutput(yes=True) # Auto-approve any Aider internal confirmations if any (usually for tool calls, not simple run)
        
        # Configure the model for Aider, using the ollama model string like in test_aider.py
        # Original script used 'ollama-qwen2.5-coder:32b', test_aider.py 'ollama/qwen2.5-coder:32b'
        main_model = Model("ollama/qwen2.5-coder:32b")

        coder = Coder.create(
            main_model=main_model,
            edit_format="whole", # For generating textual JSON output, not diffs
            fnames=valid_codebase_files, # Provide absolute paths to files
            io=io,
            use_git=False, # Original script did not imply git usage for this analysis
            # auto_commits=False, # Default is True, set to False if no commits desired implicitly
            # dry_run=False, # Not applying changes, so less relevant here
        )
        logger.info("Aider LLM coder initialized.")

        # Tool registration for list_directory_contents and read_file_content is removed.
        # Aider will use the files provided in `fnames`. The prompt asks it to analyze based on this.
        # If the LLM needed to explore *beyond* these files, Aider's own tooling or more complex prompting would be needed.
        # For this task, the existing files are the context.
        logger.info("Aider tools are implicitly managed by providing fnames. No explicit tool registration needed for this task.")

    except Exception as e:
        logger.error(f"Failed to initialize Aider LLM coder: {str(e)}", exc_info=True)
        final_output["solution_analysis"]["error"] = f"Aider LLM Coder initialization failed: {str(e)}"
        final_output["issue_summary"] = issue_content # Preserve issue content
        with open(analysis_output_path, 'w') as f_out:
            json.dump(final_output, f_out, indent=4)
        logger.error(f"container_agent.py: Critical error - Aider init failed. Outputting error to {analysis_output_path} and exiting.")
        # Cleanup container even on error
        logger.info("Initiating container cleanup after error...")
        cleanup_container()
        return

    # Construct the prompt for the LLM
    # Limiting file list length in prompt to avoid excessive token usage
    max_files_in_prompt = 200 
    files_for_prompt = codebase_files
    

    # Updated prompt for Aider to fix the code
    prompt = f"""You are an expert software engineering assistant.
Your task is to identify and fix a bug in the provided codebase.

The user has reported the following issue:
---
{issue_content}
---

Please analyze the issue and the codebase.
Then, modify the code to fix the bug described in the issue.
After applying the fix, please briefly explain the changes you made and why. The explanation should be under the **Explanation** section. 
"""

    logger.info(f"Prompting Aider LLM. Issue content length: {len(issue_content)}, Codebase files in prompt context: {len(files_for_prompt)}")
    logger.info("Aider LLM interaction starting (Aider will attempt to modify files directly based on the prompt).")

    aider_start_time = time.time()
    llm_conversation_raw = coder.run(prompt) # Aider's run method returns the conversation string
    aider_end_time = time.time()
    aider_processing_time = round(aider_end_time - aider_start_time, 2)
    logger.info(f"Aider LLM interaction completed in {aider_processing_time} seconds. Raw conversation length: {len(llm_conversation_raw)}")
    
    # Extract the explanation from the conversation
    explanation_marker_match = re.search(r"(?:\*\*|#+|)\s*Explanation[:\*\*]*", llm_conversation_raw, re.IGNORECASE)
    explanation = "No explanation provided in the LLM response."

    if explanation_marker_match:
        explanation_start_offset = explanation_marker_match.end()
        explanation = llm_conversation_raw[explanation_start_offset:].strip()
    
    git_changes = {
        "has_changes": False,
        "changed_files": [],
        "file_diffs": {},
        "summary": "No file changes detected by Aider or git diff.",
        "pr_url": None # Initialize pr_url
    }
    
    if llm_conversation_raw: # Only proceed if Aider ran
        if GIT_AVAILABLE:
            logger.info("LLM conversation completed. Analyzing git changes...")
            try:
                repo = git.Repo(repo_path)
                
                # Check for uncommitted changes first
                if repo.is_dirty(untracked_files=True):
                    logger.info("Uncommitted changes found by Aider.")
                    
                    changed_files_paths = [item.a_path for item in repo.index.diff(None)] + repo.untracked_files
                    
                    file_diffs = {}
                    for file_path in changed_files_paths:
                        try:
                            if file_path in repo.untracked_files:
                                full_file_path = os.path.join(repo_path, file_path)
                                if os.path.exists(full_file_path):
                                    with open(full_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                        content = f.read()
                                    file_diffs[file_path] = {
                                        "status": "new_file",
                                        "diff": f"+++ {file_path}\\n" + "\\n".join([f"+{line}" for line in content.splitlines()])
                                    }
                            else:
                                diff_text = repo.git.diff(file_path) # Diff against working tree
                                file_diffs[file_path] = {
                                    "status": "modified",
                                    "diff": diff_text
                                }
                        except Exception as e_diff:
                            logger.warning(f"Could not get diff for file {file_path}: {str(e_diff)}")
                            file_diffs[file_path] = {
                                "status": "error",
                                "diff": f"Error getting diff: {str(e_diff)}"
                            }

                    git_changes["has_changes"] = True
                    git_changes["changed_files"] = changed_files_paths
                    git_changes["file_diffs"] = file_diffs
                    git_changes["summary"] = f"Found {len(changed_files_paths)} files modified by Aider."
                    logger.info(f"Git diff analysis completed. {len(file_diffs)} files processed.")

                    # --- GitHub PR Creation ---
                    github_token = os.environ.get('GITHUB_TOKEN')
                    repo_name_env = os.environ.get('REPO_NAME') # e.g., "owner/repo"
                    issue_number_env = os.environ.get('ISSUE_NUMBER')
                    issue_url_env = os.environ.get('ISSUE_URL')


                    if PYGITHUB_AVAILABLE and github_token and repo_name_env and issue_number_env and issue_url_env:
                        logger.info(f"Attempting to create Pull Request for issue {issue_number_env} in repo {repo_name_env}.")
                        try:
                            g = Github(github_token)
                            gh_repo = g.get_repo(repo_name_env)
                            
                            branch_name = f"repopilot-fix-issue-{issue_number_env}"
                            
                            # Check if branch already exists
                            try:
                                existing_branch = gh_repo.get_branch(branch_name)
                                if existing_branch:
                                    # Branch exists, append a short unique ID to make it new
                                    # This is a simple way to avoid conflicts, more robust handling might be needed
                                    # for very frequent runs on the same issue.
                                    logger.warning(f"Branch {branch_name} already exists. Appending timestamp to branch name.")
                                    branch_name = f"repopilot-fix-issue-{issue_number_env}-{int(time.time())}"
                            except Exception: # Branch does not exist, which is good
                                pass

                            logger.info(f"Creating new branch: {branch_name}")
                            # Create new branch from the current HEAD (which should be the repo's default branch or specified checkout)
                            # Assuming the repo is already on the correct base branch.
                            # Using repo.head.commit directly to support detached HEAD state.
                            current_commit = repo.head.commit
                            new_branch = repo.create_head(branch_name, current_commit)
                            new_branch.checkout()
                            
                            # Stage all changes (Aider should have handled what to change)
                            repo.git.add(A=True)
                            
                            commit_message = f"Fix: Apply Aider's fix for issue #{issue_number_env}\\n\\nAddresses: {issue_url_env}"
                            repo.index.commit(commit_message)
                            logger.info(f"Committed changes to branch {branch_name}.")
                            
                            # Push the new branch
                            origin = repo.remote(name='origin')
                            
                            # Construct authenticated URL for push
                            repo_owner_slash_name = repo_name_env # Expected format "owner/repo"
                            authenticated_url = f"https://x-access-token:{github_token}@github.com/{repo_owner_slash_name}.git"
                            
                            logger.info(f"Pushing branch {branch_name} to authenticated URL...")
                            # Push using the specific authenticated URL directly, creating the remote if it doesn't match
                            # or use a temporary remote for the push operation.
                            # For simplicity, we'll try to push to the specific URL.
                            # This requires the GITHUB_TOKEN to have push permissions.
                            try:
                                repo.git.push(authenticated_url, f'{branch_name}:{branch_name}', set_upstream=True)
                            except git.exc.GitCommandError as e_push:
                                logger.error(f"Failed to push to {authenticated_url}. Error: {e_push.stderr}")
                                # Fallback: Attempt to push to the existing origin remote. 
                                # This might work if SSH keys are set up or a credential helper is already configured in the container.
                                logger.info(f"Push to authenticated URL failed. Attempting push to existing origin remote: {origin.url}")
                                try:
                                    origin.push(refspec=f'{branch_name}:{branch_name}', set_upstream=True)
                                except Exception as e_origin_push:
                                    logger.error(f"Fallback push to origin also failed: {e_origin_push}")
                                    raise e_origin_push # Re-raise the error if fallback also fails

                            logger.info(f"Pushed branch {branch_name} to origin.")
                            
                            # Generate a PR title. Use a snippet of the issue title or a generic one if issue title is unavailable.
                            issue_title_for_pr = "Automated Fix"
                            if issue_content:
                                first_line_of_issue = issue_content.splitlines()[0] if issue_content.splitlines() else ""
                                issue_title_for_pr = first_line_of_issue[:70] # Take first 70 chars of issue's first line
                                if not issue_title_for_pr:
                                    issue_title_for_pr = "Automated Fix for Issue"

                            pr_title = f"Repopilot Fix: Issue #{issue_number_env} - {issue_title_for_pr}"
                            pr_body = f"**Issue:** [{repo_name_env}#{issue_number_env}]({issue_url_env})\n\n**Explanation from Aider:**\n\n{explanation}"
                            
                            # Determine base branch (repo's default branch)
                            base_branch_name = gh_repo.default_branch
                            logger.info(f"Creating PR against base branch: {base_branch_name}")

                            pull_request = gh_repo.create_pull(
                                title=pr_title,
                                body=pr_body,
                                head=branch_name,
                                base=base_branch_name 
                            )
                            git_changes["pr_url"] = pull_request.html_url
                            # Format the summary to include a markdown link for the PR
                            git_changes["summary"] += f" Pull Request created: [View PR]({pull_request.html_url})"
                            logger.info(f"Successfully created Pull Request: {pull_request.html_url}")

                        except Exception as e_pr:
                            logger.error(f"Failed to create Pull Request: {str(e_pr)}", exc_info=True)
                            git_changes["summary"] += " Failed to create Pull Request."
                            git_changes["error"] = (git_changes.get("error", "") + f" PR creation failed: {str(e_pr)}").strip()
                    elif not PYGITHUB_AVAILABLE:
                        logger.warning("PyGithub not available. Skipping Pull Request creation.")
                        git_changes["summary"] += " PR creation skipped (PyGithub not available)."
                    elif not (github_token and repo_name_env and issue_number_env and issue_url_env):
                        logger.warning("Missing GitHub token, repo name, issue number, or issue URL for PR creation. Skipping.")
                        missing_vars = []
                        if not github_token: missing_vars.append("GITHUB_TOKEN")
                        if not repo_name_env: missing_vars.append("REPO_NAME")
                        if not issue_number_env: missing_vars.append("ISSUE_NUMBER")
                        if not issue_url_env: missing_vars.append("ISSUE_URL")
                        details = f"Missing environment variables: {', '.join(missing_vars)}"
                        git_changes["summary"] += f" PR creation skipped ({details})."
                        git_changes["error"] = (git_changes.get("error", "") + f" PR creation skipped: {details}.").strip()

                else: # No uncommitted changes
                    logger.info("No uncommitted changes detected by Aider.")
                    git_changes["summary"] = "No file changes detected by Aider that required commit."
            
            except git.InvalidGitRepositoryError:
                logger.error(f"The path {repo_path} is not a valid Git repository. Skipping git diff and PR creation.")
                git_changes["error"] = "Not a valid Git repository."
                git_changes["summary"] = "Git analysis failed (not a repo)."
            except Exception as e_git:
                logger.error(f"Error during git operations or PR creation: {str(e_git)}", exc_info=True)
                git_changes["error"] = (git_changes.get("error", "") + f" Git/PR Error: {str(e_git)}").strip()
                git_changes["summary"] = "Git analysis or PR creation failed."
        
        elif not GIT_AVAILABLE:
            logger.warning("GitPython not available. Skipping git diff analysis and PR creation.")
            git_changes["error"] = "GitPython not available in container"
            git_changes["summary"] = "Git diff analysis and PR creation unavailable."
    else: # No LLM conversation
        logger.info("No LLM conversation occurred, skipping git diff analysis and PR creation.")
        git_changes["summary"] = "No LLM interaction, so no changes to report or PR."

    final_output["issue_summary"] = issue_content
    final_output["solution_analysis"] = {
        "action_taken": "Aider LLM was instructed to identify and fix the bug based on the issue.",
        "aider_conversation_log": llm_conversation_raw,
        "explanation": explanation,
        "aider_processing_time_seconds": aider_processing_time, # Add processing time
        "notes": "Aider attempts to modify files directly in the workspace. Check the /workspace/repo_name/ directory for changes.",
        "git_changes": git_changes
    }

    # Write the final structured output to analysis_output.json
    try:
        with open(analysis_output_path, 'w') as f_out:
            json.dump(final_output, f_out, indent=4)
        logger.info(f"Analysis output successfully written to {analysis_output_path}")
    except Exception as e_write:
        logger.error(f"Failed to write analysis output to {analysis_output_path}: {str(e_write)}")

    # The original script printed the raw LLM response to stdout for the host.
    # Now, the host (IssueAnalyzer) should read analysis_output.json instead.
    # For direct observation or simpler host scripts, we can still print a summary or the JSON path.
    # Use original_stdout to ensure this message goes to the actual stdout, not the log file.
    print(f"Analysis complete. Output written to {analysis_output_path}", file=original_stdout)
    original_stdout.flush()
    logger.info("container_agent.py: main() finished.")
    
    # Container cleanup - kill the Docker container after analysis completion
    logger.info("Analysis completed successfully. Initiating container cleanup...")
    cleanup_success = cleanup_container()
    
    if not cleanup_success:
        logger.warning("Container cleanup failed or not possible. Container may need manual cleanup.")
        # Still exit normally so the container can be cleaned up by the host
        sys.exit(0)
    else:
        logger.info("Container cleanup initiated successfully.")

if __name__ == '__main__':
    logger.info("container_agent.py: Script __main__ started.")
    try:
        main()
    except Exception as e_run:
        # Catch-all for any unhandled exceptions during main()
        # This ensures that some error output is produced if main() itself crashes unexpectedly.
        logger.critical(f"Critical error running main: {str(e_run)}", exc_info=True)
        # Attempt to write a minimal error to the output file
        error_output_path = os.path.join(ANALYSIS_RESULTS_DIR, 'analysis_output.json')
        try:
            with open(error_output_path, 'w') as f_err:
                json.dump({
                    "error": f"Critical failure in container_agent.py execution: {str(e_run)}",
                    "issue_summary": "Analysis failed critically during main execution.",
                    "codebase_overview": {},
                    "solution_analysis": {}
                }, f_err, indent=4)
            logger.info(f"container_agent.py: Minimal error JSON written to {error_output_path}")
        except Exception as e_final_write:
            logger.error(f"container_agent.py: Could not even write minimal error JSON: {str(e_final_write)}")
        
        # Cleanup container even on critical error
        logger.info("Initiating container cleanup after critical error...")
        try:
            cleanup_container()
        except Exception as e_cleanup:
            logger.error(f"Container cleanup also failed: {e_cleanup}")
        
        sys.exit(1) # Exit with error code 