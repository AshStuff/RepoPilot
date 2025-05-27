from cursor_agent_tools.agent import create_agent
import re
import json
from typing import Dict, Optional, List, Tuple, Any
import logging
from models import ConnectedRepository, IssueAnalysis
import os
import subprocess
import asyncio
from datetime import datetime
import threading
import signal
import atexit
import requests
from .docker_manager import DockerManager
import traceback
import uuid
import time
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define ANSI color codes for terminal output
COLORS = {
    "info": "",            # Default color
    "success": "\033[92m", # Green
    "error": "\033[91m",   # Red
    "warning": "\033[93m", # Yellow
    "loading": "\033[94m", # Blue
    "reset": "\033[0m"     # Reset color
}

# Define spinner animation frames
SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

# Global dict to track active loading animations
_ACTIVE_ANIMATIONS = {}

# Global event loop storage for cleanup
_RUNNING_TASKS = set()

def _register_task(task):
    """Register a task for cleanup during shutdown."""
    _RUNNING_TASKS.add(task)
    task.add_done_callback(_RUNNING_TASKS.discard)

def cleanup_running_tasks():
    """Cancel any running asyncio tasks to prevent shutdown errors."""
    # Stop all animations first
    for animation_id in list(_ACTIVE_ANIMATIONS.keys()):
        _ACTIVE_ANIMATIONS[animation_id]['running'] = False
    
    # Wait a moment for animations to stop
    time.sleep(0.2 )
     
    # Cancel any running asyncio tasks
    for task in _RUNNING_TASKS:
        try:
            if not task.done():
                task.cancel()
        except:
            pass

# Register cleanup handlers
atexit.register(cleanup_running_tasks)

class IssueAnalyzer:
    def __init__(self):
        self.logger = logger
        # LLM agent initialization (create_agent, OllamaAgentAdapter) removed.
        # self.agent attribute is removed.
            
        self.docker_manager = DockerManager()
        # self._register_tools() call removed.
        self._background_tasks = {}  # Store background analysis tasks

    async def _get_branch_name_from_issue_body(self, issue_body: str) -> Optional[str]:
        """Extracts branch or tag name from the issue body using regex."""
        branch_to_clone = None
        try:
            # Prioritize version/tag over branch if both are somehow present
            version_tag_regex_match = re.search(r'(?:version|tag):\s*(\S+)', issue_body, re.IGNORECASE)
            if version_tag_regex_match:
                branch_to_clone = version_tag_regex_match.group(1).strip()
            else:
                branch_regex_match = re.search(r'branch:\s*(\S+)', issue_body, re.IGNORECASE)
                if branch_regex_match:
                    branch_to_clone = branch_regex_match.group(1).strip()
            
            if branch_to_clone:
                self.logger.info(f"Extracted branch/tag from issue body: {branch_to_clone}")
            else:
                self.logger.info("No specific branch/tag found in issue body.")
        except Exception as e_parse:
            self.logger.error(f"Error parsing branch/tag from issue body: {e_parse}")
            # Return None, caller will handle default
        return branch_to_clone

    # _register_tools method and all its agent.register_tool calls removed (previously lines approx 130-222)

    # _analyze_issue_content method removed (previously lines approx 224-235)

    async def check_issue_updates(self, analysis: IssueAnalysis, issue_body: str, comments: List[Dict], access_token: Optional[str] = None):
        """
        Check if an issue has been updated with new system information in comments.
        
        Args:
            analysis: The existing IssueAnalysis object
            issue_body: The original issue body
            comments: List of comments on the issue
            access_token: GitHub access token for API access
            
        Returns:
            bool: True if analysis should be rerun, False otherwise
        """
        # Only check for updates if we're in 'needs_info' status
        if analysis.analysis_status != 'needs_info':
            return False
            
        # Get the original comment timestamp if available
        comment_timestamp = None
        if analysis.analysis_results and 'comment_posted' in analysis.analysis_results:
            comment_id = analysis.analysis_results.get('comment_id')
            if comment_id:
                # Find the timestamp of our comment
                for comment in comments:
                    if str(comment.get('id')) == str(comment_id):
                        comment_timestamp = comment.get('created_at')
                        break
        
        # If we don't have a timestamp, we can't determine which comments are new
        if not comment_timestamp:
            logger.warning(f"No comment timestamp found for analysis {analysis.id}")
            return False
            
        # Look for comments after our system info request
        new_comments = []
        for comment in comments:
            comment_date = comment.get('created_at')
            # Skip comments before our request or from the bot itself
            if comment_date <= comment_timestamp or comment.get('id') == comment_id:
                continue
            new_comments.append(comment.get('body', ''))
            
        if not new_comments:
            return False
            
        # Combine all new comments with the original issue
        combined_text = issue_body + "\n\n" + "\n\n".join(new_comments)
        
        # Check if the combined text now has sufficient system info
        has_system_info, _ = await self.check_system_info(combined_text)
        
        if has_system_info:
            # We have enough info, update the analysis to rerun
            analysis.analysis_status = 'pending'
            analysis.updated_at = datetime.utcnow()
            analysis.save()
            
            # Add a note to the issue that we're reanalyzing
            if access_token:
                comment_body = """
                ### Analysis Restarted
                
                Thank you for providing the additional system information. We're reanalyzing the issue now.
                """
                
                self.post_github_comment(
                    analysis.repository.name,
                    analysis.issue_number,
                    comment_body,
                    access_token
                )
                
            return True
            
        return False
        
    async def get_or_create_analysis(
        self,
        issue_body: str,
        repository: ConnectedRepository,
        issue_number: int,
        issue_id: str, # This is the GitHub issue ID string
        access_token: Optional[str] = None,
        requirements_content: Optional[str] = None,
        initial_analysis_object: Optional[IssueAnalysis] = None  # New parameter
    ) -> Tuple[Optional[IssueAnalysis], bool]:
        """
        Get an existing analysis or create a new one if it doesn't exist.
        The initial_analysis_object is prioritized if provided.
        Returns the analysis object and a boolean indicating if it was newly created by this call.
        """
        created_by_this_call = False
        analysis_to_process = None

        if initial_analysis_object:
            self.logger.info(f"Analyzer: Received initial_analysis_object for issue #{initial_analysis_object.issue_number}, ID in object: {initial_analysis_object.id}")
            if initial_analysis_object.id: # Already saved, came from DB via app.py
                self.logger.info(f"Analyzer: Using pre-existing DB object (ID: {initial_analysis_object.id}) for issue #{initial_analysis_object.issue_number}.")
                analysis_to_process = initial_analysis_object
                # Double-check it's truly in the DB (paranoid check)
                if not IssueAnalysis.objects(id=initial_analysis_object.id).first():
                    self.logger.warning(f"Analyzer: Initial object for issue #{initial_analysis_object.issue_number} had an ID but was not found in DB. Will attempt to save.")
                    # It had an ID but wasn't in DB, something is odd. Let it try to save.
                    initial_analysis_object.id = None # Clear ID to force save as new if needed
                    # Fall through to logic that saves an object without an ID
                else:
                    created_by_this_call = False # Was found in DB, not created now
            else: # New in-memory object from app.py, needs to be saved
                self.logger.info(f"Analyzer: Initial object for issue #{initial_analysis_object.issue_number} is new (in-memory). Checking DB before saving.")
                # Defensive check for race conditions: query DB one last time before saving the in-memory one
                existing_in_db = IssueAnalysis.objects(repository=repository, issue_number=initial_analysis_object.issue_number).first()
                if existing_in_db:
                    self.logger.warning(f"Analyzer: Race condition? DB record for issue #{initial_analysis_object.issue_number} found (ID: {existing_in_db.id}) even though initial object was in-memory. Using DB record.")
                    analysis_to_process = existing_in_db
                    created_by_this_call = False
                else:
                    self.logger.info(f"Analyzer: Saving new in-memory object for issue #{initial_analysis_object.issue_number}.")
                    try:
                        initial_analysis_object.save() # Save the in-memory object
                        analysis_to_process = initial_analysis_object
                        created_by_this_call = True
                    except Exception as e:
                        self.logger.error(f"Analyzer: Failed to save new in-memory analysis for issue #{initial_analysis_object.issue_number}: {e}")
                        # Fallback to querying or creating from scratch if save failed
                        analysis_to_process = None 
        
        if not analysis_to_process: # If no initial object, or if initial in-memory object failed to save
            self.logger.info(f"Analyzer: No valid initial_analysis_object, proceeding with standard DB query/create for issue #{issue_number}.")
            analysis_to_process = IssueAnalysis.objects(repository=repository, issue_number=issue_number).first()
            if analysis_to_process:
                self.logger.info(f"Analyzer: Found existing analysis (ID: {analysis_to_process.id}) in DB for issue #{issue_number} during standard query.")
                created_by_this_call = False
            else:
                self.logger.info(f"Analyzer: No analysis in DB for issue #{issue_number}. Creating and saving new.")
                try:
                    analysis_to_process = IssueAnalysis(
                repository=repository,
                issue_number=issue_number,
                        issue_id=issue_id, # Use the passed issue_id if creating fully new here
                        issue_title="Issue Title Placeholder", # Placeholder, might be updated later if full issue_data is fetched
                        issue_body=issue_body, # issue_body is primarily used for analysis context
                        analysis_status="pending",
                        logs=[]
                    )
                    analysis_to_process.save()
                    created_by_this_call = True
                except Exception as e:
                    self.logger.error(f"Analyzer: Failed to create and save brand new analysis for issue #{issue_number}: {e}")
                    return None, False

        if not analysis_to_process:
            self.logger.error(f"Analyzer: Ultimately failed to get or create an analysis object for issue #{issue_number}.")
            return None, False

        # At this point, analysis_to_process is the definitive object, either from DB or just saved.
        # Proceed with starting the background task if needed.
        if created_by_this_call or (analysis_to_process.analysis_status not in ['completed', 'in_progress', 'failed']):
            self.logger.info(f"Analyzer: Analysis for issue #{analysis_to_process.issue_number} (status: {analysis_to_process.analysis_status}) requires processing. Starting/Restarting analysis thread.")
            # Ensure we pass the ID (string) of the analysis object, not the object itself.
            analysis_db_id = str(analysis_to_process.id)
            thread = threading.Thread(
                target=self._run_async_in_thread,
                args=(self._analyze_in_background(
                    analysis_db_id, # Pass the string ID
                            issue_body,
                    analysis_to_process.repository,
                    analysis_to_process.issue_number,
                    analysis_to_process.issue_id,
                            access_token,
                            requirements_content
                ),)
            )
            thread.start()
        else:
            self.logger.info(f"Analyzer: Analysis for issue #{analysis_to_process.issue_number} (status: {analysis_to_process.analysis_status}) does not require new processing at this time.")

        return analysis_to_process, created_by_this_call

    def _run_async_in_thread(self, coro):
        """Helper to run an asyncio coroutine in a new thread with its own event loop."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            self.logger.debug(f"Starting new event loop in thread {threading.get_ident()} for coroutine.")
            loop.run_until_complete(coro)
        except Exception as e:
            self.logger.error(f"Exception in _run_async_in_thread for coroutine: {e}")
            self.logger.error(traceback.format_exc())
        finally:
            self.logger.debug(f"Closing event loop in thread {threading.get_ident()}.")
            # Ensure the loop is closed to prevent resource leaks
            if not loop.is_closed():
                # Cancel all remaining tasks on the loop before closing
                try:
                    all_tasks = asyncio.all_tasks(loop)
                    if all_tasks:
                        for task in all_tasks:
                            task.cancel()
                        # Allow tasks to be cancelled
                        loop.run_until_complete(asyncio.gather(*all_tasks, return_exceptions=True))
                except Exception as task_cancel_e:
                    self.logger.error(f"Exception during task cancellation in _run_async_in_thread: {task_cancel_e}")
                finally:
                    loop.close()

    async def _analyze_in_background(self, analysis_id: str, issue_body: str, repository: ConnectedRepository, issue_number: int, issue_id_gh: str, access_token: Optional[str] = None, requirements_content: Optional[str] = None):
        analysis = None
        image_tag_for_cleanup = None
        build_context_id_for_cleanup = None
        analysis_reloaded = False # Flag to track if analysis object was reloaded

        try:
            # Ensure analysis object is fetched fresh within the thread/async task
            analysis = IssueAnalysis.objects(id=analysis_id).first()
            if not analysis:
                self.logger.error(f"Analysis ID {analysis_id} not found in _analyze_in_background.")
                return
            
            analysis.analysis_status = 'in_progress'
            analysis.started_at = datetime.utcnow()
            analysis.add_log(f"Analysis started in background.", "info")
            analysis_reloaded = True

            self.logger.info(f"Starting analysis for issue #{issue_number} in {repository.name}")

            # Define a log callback that updates the specific analysis object
            def docker_log_callback(log_line: str, stream_type: str):
                # Ensure analysis object is fresh for each log to avoid issues with stale objects
                current_analysis = IssueAnalysis.objects(id=analysis_id).first()
                if not current_analysis:
                    # If analysis object is gone, log to general logger
                    self.logger.warning(f"[BuildLog {analysis_id[:8]} Stream: {stream_type}] {log_line} (Analysis object no longer found)")
                    return

                # Validate that the analysis object has all required fields before proceeding
                if not current_analysis.repository or not current_analysis.issue_number or not current_analysis.issue_id:
                    self.logger.error(f"Analysis object {analysis_id} is missing required fields: repository={current_analysis.repository}, issue_number={current_analysis.issue_number}, issue_id={current_analysis.issue_id}")
                    # Try to fix the object by reloading required data
                    try:
                        if not current_analysis.repository and repository:
                            current_analysis.repository = repository
                        if not current_analysis.issue_number and issue_number:
                            current_analysis.issue_number = issue_number
                        if not current_analysis.issue_id and issue_id_gh:
                            current_analysis.issue_id = issue_id_gh
                        
                        # Try to save the fixed object
                        current_analysis.save()
                        self.logger.info(f"Successfully fixed missing required fields for analysis {analysis_id}")
                    except Exception as fix_error:
                        self.logger.error(f"Failed to fix analysis object {analysis_id}: {fix_error}. The original log message from Docker was: '{log_line}'")
                        # Log to general server logs as fallback, since we couldn't save to the specific analysis object
                        self.logger.info(f"[BuildLog {analysis_id[:8]} Stream: {stream_type}] {log_line} (Failed to save to analysis object after attempting fix due to: {fix_error})")
                        return

                # Determine log type for add_log based on stream_type
                log_type_for_db = stream_type.lower()
                if stream_type.lower() not in ["info", "error", "warning", "success", "debug"]:
                    log_type_for_db = "info" # Default if stream_type is stdout/stderr etc.

                try:
                    current_analysis.add_log(log_line, log_type_for_db)
                except Exception as log_error:
                    self.logger.error(f"Failed to add log to analysis {analysis_id}: {log_error}")
                    # Log to general logger as fallback
                    self.logger.info(f"[BuildLog {analysis_id[:8]} Stream: {stream_type}] {log_line}")
                
                # Limit logs to prevent excessive growth (e.g., last 200 lines) - add_log does not handle this, so keep it here if needed after save by add_log
                # This logic might be better placed within add_log or as a separate cleanup if add_log saves frequently.
                # For now, assuming add_log handles its own save, and log limiting is a separate concern.
                # max_log_entries = 200 
                # if len(current_analysis.logs) > max_log_entries:
                #     current_analysis.logs = current_analysis.logs[-max_log_entries:]
                
                # try:
                #     current_analysis.save() # add_log already saves
                # except Exception as e_save:
                #     self.logger.error(f"Error saving analysis log for {analysis_id}: {e_save}")


            branch_name = await self._get_branch_name_from_issue_body(issue_body)
            if not branch_name:
                branch_name = 'main' # Default branch
                analysis.add_log(f"Could not determine branch/tag from issue body, defaulting to 'main'.", "warning")
            else:
                analysis.add_log(f"Using branch/tag: {branch_name} (from issue body or default)", "info")

            self.logger.info(f"Building Docker image for {repository.name} issue #{issue_number}, branch: {branch_name}.")
            docker_log_callback(f"Attempting to build image for: {repository.name}, issue #{issue_number}, branch: {branch_name}", "info")
            
            image_tag, build_context_id, build_logs, _ = self.docker_manager.clone_repo_and_create_image(
                repo_url=f"https://github.com/{repository.name}.git",
                repo_name=repository.name,
                issue_number=issue_number,
                issue_body=issue_body, # Pass the full issue body for issue.txt
                branch_name=branch_name,
                log_callback=docker_log_callback
            )
            image_tag_for_cleanup = image_tag
            build_context_id_for_cleanup = build_context_id

            if build_logs: # clone_repo_and_create_image now returns build_logs directly
                # The docker_log_callback should have handled detailed logging.
                # We can add a summary log here if needed.
                docker_log_callback(f"Image build process completed. Summary of internal logs: {len(build_logs)} entries.", "info")

            if not image_tag:
                self.logger.error(f"Docker image build failed for issue #{issue_number}.")
                docker_log_callback(f"Docker image build failed for issue #{issue_number}. Check logs for errors.", "error")
                analysis.analysis_status = 'failed'
                analysis.error_message = "Docker image build failed. See logs for details."
                analysis.ended_at = datetime.utcnow()
                analysis.save()
                return

            self.logger.info(f"Docker image {image_tag} built successfully for issue #{issue_number}.")
            docker_log_callback(f"Docker image {image_tag} built successfully.", "success")
            
            # --- Docker Run ---
            host_ollama_models_path = os.path.expanduser("~/.ollama/models")
            # Ensure the path exists, or Docker will create it as root, which might be problematic.
            # However, for read-only mount of models, it should be fine if it exists.
            if not os.path.isdir(host_ollama_models_path):
                docker_log_callback(f"Warning: Host Ollama models path {host_ollama_models_path} does not exist or is not a directory. Ollama in container may not find models.", "warning")
                # Decide if this is a fatal error or just a warning. For now, warning.

            analysis_results_host_dir = os.path.join(self.docker_manager.dockerfiles_dir, build_context_id, "analysis_results")
            os.makedirs(analysis_results_host_dir, exist_ok=True)
            docker_log_callback(f"Host directory for analysis results: {analysis_results_host_dir}", "info")

            container_name = f"repopilot-agent-run-{build_context_id[:8]}"

            run_cmd_args = [
                "run", 
                "-d",
                "--network", "llm-net",
                "--name", container_name,
                "-v", f"{host_ollama_models_path}:/root/.ollama:ro",
                "-v", f"{analysis_results_host_dir}:/workspace/analysis_results",
            ]
            
            # Add host.docker.internal mapping if OLLAMA_HOST is set to it (it is, in Dockerfile)
            # This is needed for the container to reach Ollama on the host if host.docker.internal is used.
            # The Dockerfile sets ENV OLLAMA_HOST=http://host.docker.internal:11434
            # The --add-host for build was for build-time access, this is for runtime.
            if sys.platform == "linux" or sys.platform == "linux2":
                 run_cmd_args.append("--add-host=host.docker.internal:host-gateway")
            
            run_cmd_args.append(image_tag)
            # No command/args appended, as ENTRYPOINT will be used.

            docker_log_callback(f"Executing container {container_name} from image {image_tag} with command: docker {' '.join(run_cmd_args)}", "info")
            
            try:
                process_run_result = self.docker_manager._run_docker_command(
                    run_cmd_args, 
                    log_callback=docker_log_callback, 
                    check=False # check=False to handle non-zero exit codes manually
                )
                docker_log_callback(f"Process run result: {process_run_result}", "info")
                if process_run_result.returncode != 0:
                    docker_log_callback(f"Container {container_name} exited with error code {process_run_result.returncode}. Stderr: {process_run_result.stderr}", "error")
                    analysis.analysis_status = 'failed'
                    analysis.error_message = f"Agent execution in container failed (exit code {process_run_result.returncode}). Check logs."
                    # Attempt to get error log content if it exists
                    error_log_path_host = os.path.join(analysis_results_host_dir, "analysis_error.log")
                    if os.path.exists(error_log_path_host):
                        try:
                            with open(error_log_path_host, 'r') as f_err:
                                error_details = f_err.read(1000) # Read first 1000 chars
                                analysis.error_message += f" Agent error log snippet: {error_details}"
                        except Exception as e_read_err:
                            docker_log_callback(f"Could not read agent error log: {e_read_err}", "warning")
                else:
                    docker_log_callback(f"Container {container_name} completed successfully.", "success")
            except Exception as e_container_run:
                self.logger.error(f"Error running Docker container {container_name}: {e_container_run}", exc_info=True)
                docker_log_callback(f"Failed to run Docker container {container_name}: {e_container_run}", "error")
                analysis.analysis_status = 'failed'
                analysis.error_message = f"Failed to run Docker container: {e_container_run}"
                analysis.ended_at = datetime.utcnow()
                analysis.save()
                return # Exit if container run command itself failed catastrophically

            # --- End Docker Run ---

            # Process results from the host filesystem with polling
            output_json_path_host = os.path.join(analysis_results_host_dir, "analysis_output.json")
            error_log_path_host = os.path.join(analysis_results_host_dir, "analysis_error.log")

            # Wait for analysis to complete with polling
            max_wait_time = 600  # 10 minutes maximum wait time
            poll_interval = 5    # Check every 5 seconds
            wait_start_time = time.time()
            
            docker_log_callback("Waiting for analysis to complete. Container is still running...", "info")
            
            analysis_completed = False
            last_milestone_logged = 0  # Track milestones for reduced logging
            
            while time.time() - wait_start_time < max_wait_time:
                if os.path.exists(output_json_path_host):
                    logger.info(f"Found path: {output_json_path_host}")
                    docker_log_callback(f"Found analysis_output.json after {int(time.time() - wait_start_time)} seconds", "info")
                    analysis_completed = True
                    break
                
                elapsed_time = int(time.time() - wait_start_time)
                logger.info(f"Waiting for analysis to complete... ({elapsed_time}s elapsed)")
                # Only log at significant milestones (every 30 seconds) to reduce spam
                if elapsed_time > 0 and elapsed_time % 30 == 0 and elapsed_time != last_milestone_logged:
                    docker_log_callback(f"Still waiting for analysis completion... ({elapsed_time}s elapsed)", "info")
                    last_milestone_logged = elapsed_time
                
                await asyncio.sleep(poll_interval)
            
            if not analysis_completed:
                docker_log_callback(f"Analysis did not complete within {max_wait_time} seconds. Timing out.", "error")
                analysis.analysis_status = 'failed'
                analysis.error_message = f"Analysis timed out after {max_wait_time} seconds"
                
                # Check for error log
                if os.path.exists(error_log_path_host):
                    try:
                        with open(error_log_path_host, 'r') as f_err:
                            error_log_content = f_err.read(2000)
                        analysis.error_message += f" Error log found: {error_log_content}"
                        docker_log_callback(f"Found error log content: {error_log_content[:200]}...", "info")
                    except Exception as e_read_err:
                        docker_log_callback(f"Could not read analysis_error.log: {e_read_err}", "warning")
            else:
                # Analysis output file exists, now check its contents
                try:
                    with open(output_json_path_host, 'r') as f:
                        analysis_results = json.load(f)
                    
                    # Check for the specific key structure: solution_analysis.aider_conversation_log
                    aider_conversation_log = None
                    if (isinstance(analysis_results, dict) and 
                        'solution_analysis' in analysis_results and 
                        isinstance(analysis_results['solution_analysis'], dict) and
                        'aider_conversation_log' in analysis_results['solution_analysis']):
                        
                        aider_conversation_log = analysis_results['solution_analysis']['aider_conversation_log']
                    
                    explanation = None
                    if (isinstance(analysis_results, dict) and
                        'solution_analysis' in analysis_results and
                        isinstance(analysis_results['solution_analysis'], dict) and
                        'explanation' in analysis_results['solution_analysis']):
                        explanation = analysis_results['solution_analysis']['explanation']

                    git_changes = None
                    if (isinstance(analysis_results, dict) and
                        'solution_analysis' in analysis_results and
                        isinstance(analysis_results['solution_analysis'], dict) and
                        'git_changes' in analysis_results['solution_analysis']):
                        git_changes = analysis_results['solution_analysis']['git_changes']

                    aider_processing_time = None
                    if (isinstance(analysis_results, dict) and
                        'solution_analysis' in analysis_results and
                        isinstance(analysis_results['solution_analysis'], dict) and
                        'aider_processing_time_seconds' in analysis_results['solution_analysis']):
                        aider_processing_time = analysis_results['solution_analysis']['aider_processing_time_seconds']

                    pr_url = None # Initialize pr_url
                    if (isinstance(analysis_results, dict) and
                        'solution_analysis' in analysis_results and
                        isinstance(analysis_results['solution_analysis'], dict) and
                        'git_changes' in analysis_results['solution_analysis'] and
                        isinstance(analysis_results['solution_analysis']['git_changes'], dict) and
                        'pr_url' in analysis_results['solution_analysis']['git_changes']):
                        pr_url = analysis_results['solution_analysis']['git_changes']['pr_url']

                    # Check if aider_conversation_log is empty or null
                    if not aider_conversation_log or (isinstance(aider_conversation_log, (list, str)) and len(aider_conversation_log) == 0):
                        docker_log_callback("Analysis failed: aider_conversation_log is empty or missing", "error")
                        analysis.analysis_status = 'failed'
                        analysis.error_message = "Analysis failed: No aider conversation log generated"
                        analysis.analysis_results = analysis_results  # Still save the partial results
                    else:
                        # Success - aider_conversation_log has content
                        docker_log_callback("Analysis completed successfully with aider conversation log", "success")
                        
                        # Pretty print the conversation log under SUMMARY section
                        docker_log_callback("=" * 80, "info")
                        docker_log_callback("SUMMARY", "success")
                        docker_log_callback("=" * 80, "info")
                        
                        # Format and display the conversation log
                        if isinstance(aider_conversation_log, list):
                            for i, log_entry in enumerate(aider_conversation_log, 1):
                                docker_log_callback(f"[{i}] {log_entry}", "info")
                        elif isinstance(aider_conversation_log, str):
                            # Split by lines for better readability
                            for line in aider_conversation_log.split('\n'):
                                if line.strip():
                                    docker_log_callback(line, "info")
                        else:
                            docker_log_callback(f"Conversation log: {aider_conversation_log}", "info")
                        
                        docker_log_callback("=" * 80, "info")

                        if explanation:
                            docker_log_callback("SUMMARY - EXPLANATION", "success")
                            docker_log_callback("=" * 80, "info")
                            for line in explanation.split('\n'):
                                if line.strip():
                                    docker_log_callback(line, "info")
                            docker_log_callback("=" * 80, "info")
                            analysis.final_output = explanation # Store explanation in final_output
                        else:
                            docker_log_callback("No explanation found in analysis results.", "warning")
                            analysis.final_output = "No explanation provided by the LLM."

                        # Store git changes information if available
                        if git_changes:
                            analysis.git_changes = git_changes
                            if git_changes.get('has_changes', False):
                                docker_log_callback("SUMMARY - GIT CHANGES", "success")
                                docker_log_callback("=" * 80, "info")
                                docker_log_callback(f"Git changes summary: {git_changes.get('summary', 'No summary available')}", "info")
                                changed_files = git_changes.get('changed_files', [])
                                if changed_files:
                                    docker_log_callback(f"Modified files ({len(changed_files)}):", "info")
                                    for file_path in changed_files:
                                        docker_log_callback(f"  • {file_path}", "info")
                                docker_log_callback("=" * 80, "info")
                            else:
                                docker_log_callback("No git changes detected after LLM analysis.", "info")
                        else:
                            docker_log_callback("Git changes information not available.", "warning")

                        if aider_processing_time is not None:
                            analysis.aider_processing_time_seconds = aider_processing_time
                            docker_log_callback(f"Aider processing time: {aider_processing_time} seconds", "info")
                        else:
                            docker_log_callback("Aider processing time not available.", "warning")

                        if pr_url:
                            analysis.pr_url = pr_url
                            docker_log_callback(f"Pull Request created: {pr_url}", "success")
                        else:
                            docker_log_callback("No Pull Request URL found in analysis results.", "info")

                        analysis.analysis_results = analysis_results
                        analysis.analysis_status = 'completed'
                        analysis.error_message = None
                        
                    # docker_log_callback(f"Successfully processed analysis_output.json from {output_json_path_host}", "success")
                    
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to decode analysis_output.json for issue #{issue_number}: {e}")
                    docker_log_callback(f"Failed to decode analysis_output.json: {e}", "error")
                    analysis.analysis_status = 'failed'
                    analysis.error_message = f"Failed to decode analysis_output.json: {e}"
                except Exception as e_read:
                    self.logger.error(f"Failed to read analysis_output.json for issue #{issue_number}: {e_read}")
                    docker_log_callback(f"Failed to read analysis_output.json: {e_read}", "error")
                    analysis.analysis_status = 'failed'
                    analysis.error_message = f"Failed to read analysis_output.json: {e_read}"
            
            analysis.ended_at = datetime.utcnow()
            analysis.save()
            self.logger.info(f"Analysis for issue #{issue_number} finished with status: {analysis.analysis_status}")
            docker_log_callback(f"Analysis for issue #{issue_number} finished with status: {analysis.analysis_status}", "info")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"CalledProcessError during analysis for issue #{issue_number if analysis else 'unknown'}: {e.stderr}", exc_info=True)
            if analysis_reloaded and analysis: # Check if analysis was loaded
                analysis.analysis_status = 'failed'
                analysis.error_message = f"Docker operation failed: {e.stderr}"
                analysis.ended_at = datetime.utcnow()
                analysis.save()
        except Exception as e:
            self.logger.error(f"Unexpected error during analysis for issue #{issue_number if analysis else 'unknown'}: {str(e)}", exc_info=True)
            if analysis_reloaded and analysis: # Check if analysis was loaded
                analysis.analysis_status = 'failed'
                analysis.error_message = f"An unexpected error occurred: {str(e)}"
                analysis.ended_at = datetime.utcnow()
                analysis.save() 
        finally:
            if image_tag_for_cleanup: 
                try:
                    self.logger.info(f"Cleaning up Docker image {image_tag_for_cleanup}...")
                    # Use a generic log callback or none for cleanup, as the specific analysis log callback might rely on analysis object state.
                    cleanup_log_callback = lambda msg, lvl: self.logger.info(f"[Cleanup {image_tag_for_cleanup[:8]}]: {msg}")
                    # self.docker_manager._run_docker_command(["rmi", "-f", image_tag_for_cleanup], log_callback=cleanup_log_callback, check=False)
                except Exception as e_rmi:
                    self.logger.error(f"Error cleaning up image {image_tag_for_cleanup}: {e_rmi}")
            
            if build_context_id_for_cleanup: 
                try:
                    self.logger.info(f"Cleaning up Dockerfile context {build_context_id_for_cleanup}...")
                    self.docker_manager.cleanup_dockerfile_context(build_context_id_for_cleanup)
                except Exception as e_cleanup_ctx:
                    self.logger.error(f"Error cleaning up context {build_context_id_for_cleanup}: {e_cleanup_ctx}")
            
            if analysis_reloaded and analysis and analysis.id: # Ensure analysis object exists and has an ID
                # Clear task from global tracking if it was backgrounded via _ACTIVE_ANIMATIONS or similar mechanism
                # This part might need adjustment depending on how _analyze_in_background is invoked and tracked by _ACTIVE_ANIMATIONS
                task_key = f"analysis_{str(analysis.id)}" # Example key, adjust if different
                if task_key in _ACTIVE_ANIMATIONS: # Using _ACTIVE_ANIMATIONS as a proxy for task tracking
                    _ACTIVE_ANIMATIONS[task_key]['running'] = False # Mark as not running
                    # Potentially remove from dict if no longer needed, or let _end_loading_animation handle it
                    self.logger.info(f"Marked background task {task_key} as completed in finally block.")

    def _execute_in_container(self, container_id: str, command: str) -> Dict:
        """Execute a command in the Docker container"""
        try:
            result = self.docker_manager.execute_command(container_id, command)
            if result is None:
                return {"status": "error", "message": "Failed to execute command in container"}
            
            return {
                "status": "success", 
                "result": result
            }
        except Exception as e:
            logger.error(f"Error executing command in container: {str(e)}")
            return {"status": "error", "message": str(e)}

    async def _create_custom_container(self, repo_name: str, issue_number: int, 
                                      branch: str = 'main',
                                      access_token: Optional[str] = None,
                                      animation_id: Optional[str] = None,
                                      analysis_id: Optional[str] = None,
                                      issue_body_for_txt_file: Optional[str] = None) -> Dict[str, Any]:
        """Create a custom container for the repository with the specified branch/tag."""
        try:
            # Update animation if provided
            if animation_id:
                self._update_loading_animation(animation_id, f"Creating container for {repo_name} ({branch})")
            
            # Create repo URL from repo name
            repo_url = f"https://github.com/{repo_name}"
            # Create Docker container with the repository and branch
            container = await self.docker_manager.create_container(
                repo_url=repo_url,
                repo_name=repo_name,
                issue_number=issue_number,
                branch=branch,
                access_token=access_token,
                issue_body_for_txt_file=issue_body_for_txt_file # Pass it down
            )
            
            # Update animation with success
            if animation_id:
                self._update_loading_animation(animation_id, f"Container {container.get('container_name')} created. Environment setup occurs during image build.")
            
            # Get the current branch to verify checkout was successful
            current_branch = self.docker_manager.execute_command(
                container['container_id'], 
                "cd /workspace/$(ls /workspace) && git rev-parse --abbrev-ref HEAD"
            ).strip()
            
            # Check if checkout was successful
            if branch.strip() != current_branch:
                self._log_workspace_message(f"Warning: Current branch '{current_branch}' doesn't match requested branch '{branch}'", type="warning", analysis_id=analysis_id)
                
                # List available branches for information
                branches_result = self.docker_manager.execute_command(
                    container['container_id'], 
                    "cd /workspace/$(ls /workspace) && git branch -a"
                )
                
                if branches_result:
                    self._log_workspace_message(f"Available branches:\n{branches_result}", analysis_id=analysis_id)
            else:
                self._log_workspace_message(f"Successfully using branch: {branch}", type="success", analysis_id=analysis_id)
            
            # The checks for requirements.txt and pyproject.toml using execute_command 
            # that were here (previously lines approx 717-727) are now removed.
            # These checks are redundant as dependency installation is handled by 
            # clone_repo.sh during the 'docker build' process.
            
            # Make sure the container has the required keys
            if 'container_id' not in container or 'container_name' not in container:
                logger.error(f"Container object missing required keys: {container}")
                
                # In case keys don't match as expected, add compatibility layer
                if 'id' in container and 'container_id' not in container:
                    container['container_id'] = container['id']
                if 'name' in container and 'container_name' not in container:
                    container['container_name'] = container['name']
            
            return container
            
        except Exception as e:
            logger.error(f"Error creating custom container: {str(e)}")
            raise

    def _log_workspace_message(self, message: str, type="info", analysis_id=None) -> Dict:
        """
        Log a message to the workspace terminal with optional styling
        
        Args:
            message: The message to display
            type: Message type (info, success, error, loading_start, loading_update, loading_end)
            analysis_id: Optional ID of the analysis to log to (if known)
        """
        # Define icons for different message types
        icons = {
            "info": "",
            "success": "✓ ",
            "error": "✗ ",
            "warning": "⚠ ",
            "loading": "⟳ ",
            "loading_start": "⟳ ",
            "loading_update": "⟳ ",
            "loading_end_success": "✓ ",
            "loading_end_error": "✗ "
        }
        
        # Handle loading animation
        if type == "loading_start":
            # Start a loading message
            logger.info(f"{COLORS['loading']}{icons['loading_start']}{message}...{COLORS['reset']}")
        elif type == "loading_update":
            # Update an existing loading message
            logger.info(f"{COLORS['loading']}{icons['loading_update']}{message}...{COLORS['reset']}")
        elif type == "loading_end_success":
            # End loading with success
            logger.info(f"{COLORS['success']}{icons['loading_end_success']}{message}{COLORS['reset']}")
        elif type == "loading_end_error":
            # End loading with error
            logger.info(f"{COLORS['error']}{icons['loading_end_error']}{message}{COLORS['reset']}")
        else:
            # Standard message types
            if type in COLORS:
                logger.info(f"{COLORS[type]}{icons[type]}{message}{COLORS['reset']}")
            else:
                # Default to info for unknown types
                logger.info(message)
        
        # Try to store log in the database for the current analysis
        try:
            # Find the current analysis being processed
            from models import IssueAnalysis
            
            current_analysis = None
            
            # If an analysis ID was provided directly, try to use it first
            if analysis_id:
                try:
                    current_analysis = IssueAnalysis.objects(id=analysis_id).first()
                except Exception as e:
                    # If we can't find by ID, continue to other methods
                    pass
            
            # If we still don't have an analysis, try other methods
            if not current_analysis:
                # Method 1: Look for an analysis in the _background_tasks dictionary
                for task_key, thread in self._background_tasks.items():
                    if thread.is_alive():
                        # Extract repository name and issue number from the task key
                        parts = task_key.split('_')
                        if len(parts) >= 2:
                            try:
                                repo_name = parts[0]
                                issue_number = int(parts[1])
                                
                                # Find the analysis
                                analysis = IssueAnalysis.objects(
                                    repository__name=repo_name,
                                    issue_number=issue_number
                                ).first()
                                
                                if analysis:
                                    current_analysis = analysis
                                    break
                            except (ValueError, IndexError):
                                continue
                
                # Method 2: If we couldn't find the analysis from background tasks,
                # look for any in-progress analyses
                if not current_analysis:
                    # Find any in-progress analyses (there should typically be only one)
                    in_progress_analyses = IssueAnalysis.objects(
                        analysis_status='in_progress'
                    ).order_by('-updated_at').limit(1)
                    
                    if in_progress_analyses:
                        current_analysis = in_progress_analyses[0]
            
            # If we found an analysis, add the log to it
            if current_analysis:
                current_analysis.add_log(message, type)
            else:
                # Just log to console without the warning - this is normal during restart
                # when the analysis has been deleted
                pass
                
        except Exception as e:
            # Log the error but don't show warnings to users
            logger.debug(f"Error storing log in database: {str(e)}")
        
        return {"status": "success", "message": "Message logged to workspace"}
    
    def _start_loading_animation(self, message: str) -> str:
        """
        Start a real-time loading animation in the workspace terminal
        
        Args:
            message: Base message to display with animation
            
        Returns:
            str: Animation ID to use with _update_loading and _end_loading
        """
        animation_id = str(uuid.uuid4())[:8]
        
        # Create animation thread data
        animation_data = {
            'message': message,
            'running': True,
            'thread': None
        }
        
        # Function to run the animation in a thread
        def run_animation():
            i = 0
            try:
                while animation_data['running']:
                    frame = SPINNER_FRAMES[i % len(SPINNER_FRAMES)]
                    current_message = animation_data['message']
                    
                    # Log the animated message
                    logger.info(f"{COLORS['loading']}{frame} {current_message}...{COLORS['reset']}")
                    
                    # Sleep briefly
                    time.sleep(0.1)
                    i += 1
            except Exception as e:
                logger.error(f"Animation error: {str(e)}")
        
        # Create and start the animation thread
        animation_thread = threading.Thread(target=run_animation)
        animation_thread.daemon = True
        animation_thread.start()
        
        # Store the animation data
        animation_data['thread'] = animation_thread
        _ACTIVE_ANIMATIONS[animation_id] = animation_data
        
        return animation_id
    
    def _update_loading_animation(self, animation_id: str, message: str) -> None:
        """
        Update an existing loading animation
        
        Args:
            animation_id: ID returned by _start_loading_animation
            message: Updated message to display
        """
        if animation_id in _ACTIVE_ANIMATIONS:
            _ACTIVE_ANIMATIONS[animation_id]['message'] = message
        else:
            # If animation doesn't exist, just log the message
            self._log_workspace_message(f"{message}", type="loading_update")
    
    def _end_loading_animation(self, animation_id: str, message: str, success: bool = True) -> None:
        """
        End a loading animation with success or error
        
        Args:
            animation_id: ID returned by _start_loading_animation
            message: Final message to display
            success: Whether the operation was successful
        """
        # Stop the animation if it exists
        if animation_id in _ACTIVE_ANIMATIONS:
            _ACTIVE_ANIMATIONS[animation_id]['running'] = False
            
            # Wait for the thread to finish
            if _ACTIVE_ANIMATIONS[animation_id]['thread']:
                _ACTIVE_ANIMATIONS[animation_id]['thread'].join(timeout=0.5)
            
            # Remove from active animations
            del _ACTIVE_ANIMATIONS[animation_id]
        
        # Log the final message
        end_type = "loading_end_success" if success else "loading_end_error"
        self._log_workspace_message(message, type=end_type)

    def post_github_comment(self, repo_name: str, issue_number: int, comment_body: str, access_token: str) -> Dict:
        """Post a comment on a GitHub issue."""
        try:
            url = f"https://api.github.com/repos/{repo_name}/issues/{issue_number}/comments"
            headers = {
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            data = {"body": comment_body}
            
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            
            return {
                "status": "success",
                "comment_id": response.json().get("id"),
                "url": response.json().get("html_url")
            }
        except Exception as e:
            logger.error(f"Error posting GitHub comment: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }

    # check_system_info method removed.

# End of file 