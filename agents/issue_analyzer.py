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
        # Renamed issue_id to issue_id_gh to avoid conflict with analysis_id
        current_thread = threading.current_thread()
        self._background_tasks[analysis_id] = current_thread
        animation_id = None
        build_context_id_for_paths = None # To store build_context_id for path construction
        cloned_repo_path_for_cleanup = None # To store cloned_repo_path for cleanup

        try:
            analysis = IssueAnalysis.objects(id=analysis_id).first()
            if not analysis:
                self.logger.error(f"Analysis object with ID {analysis_id} not found.")
                self._log_workspace_message(f"Error: Analysis object not found for issue #{issue_number}.", "error", analysis_id=analysis_id)
                return
            
            analysis.analysis_status = "in_progress"
            analysis.add_log("Starting background analysis...", "info")
            analysis.save()
            self.logger.info(f"[{analysis_id}] Saved initial status as 'in_progress'.")

            self._log_workspace_message(f"Starting background analysis for issue #{issue_number} ({analysis_id})...", "loading", analysis_id=analysis_id)
            animation_id = self._start_loading_animation(f"Analyzing issue #{issue_number}...")

            # Determine branch/tag (simple regex for now, as LLM is in container)
            branch_to_clone = 'main'
            try:
                print(f"Issue body: {issue_body}")
                branch_regex_match = re.search(r'branch:\s*(\S+)', issue_body, re.IGNORECASE)
                print(f"Branch regex match: {branch_regex_match}")
                import pdb; pdb.set_trace()
                version_tag_regex_match = re.search(r'(?:version|tag):\s*(\S+)', issue_body, re.IGNORECASE)
                if version_tag_regex_match:
                    branch_to_clone = version_tag_regex_match.group(1).strip()
                elif branch_regex_match:
                    branch_to_clone = branch_regex_match.group(1).strip()
                analysis.add_log(f"Determined branch/version to clone: {branch_to_clone}", "info")
            except Exception as e_branch:
                self.logger.error(f"[{analysis_id}] Error parsing branch/tag: {e_branch}")
                analysis.add_log(f"Could not determine branch/tag, defaulting to '{branch_to_clone}'.", "warning")
            analysis.save()
            
            self._update_loading_animation(animation_id, f"Preparing Docker environment for issue #{issue_number} (branch: {branch_to_clone})...")
            self._log_workspace_message(f"Preparing Docker environment for issue #{issue_number} (branch: {branch_to_clone})...", "loading", analysis_id=analysis_id)

            # Construct the repository URL from the ConnectedRepository's name attribute
            repo_url = f"https://github.com/{repository.name}.git"
            
            # The call to self.docker_manager.clone_repo_and_create_image needs app_context if it uses current_app
            # However, DockerManager is instantiated once, so it should not need app_context per call.
            # Let's assume the method is designed to be called directly.
            
            image_id, build_context_id, build_logs, cloned_repo_path = self.docker_manager.clone_repo_and_create_image(
                repo_url=repo_url,
                repo_name=repository.name,
                issue_number=issue_number,
                issue_body=issue_body, # Full issue body for issue.txt
                branch_name=branch_to_clone
            )
            build_context_id_for_paths = build_context_id
            cloned_repo_path_for_cleanup = cloned_repo_path

            # Log build logs from image creation
            if build_logs:
                for log_line in build_logs:
                    analysis.add_log(log_line, "build") # Using "build" as type for Docker build logs
                analysis.save()

            if not image_id:
                self.logger.error(f"[{analysis_id}] Failed to create image. Details in DockerManager logs.")
                analysis.analysis_status = "error"
                analysis.error_message = "Docker image creation failed. Check logs."
                analysis.add_log("Error: Docker image creation failed.", "error")
                analysis.save()
                self._end_loading_animation(animation_id, "Image creation failed.", success=False)
                self._log_workspace_message(f"Error: Docker image creation failed for issue #{issue_number}.", "error", analysis_id=analysis_id)
                return

            analysis.docker_image_id = image_id # Storing actual image_id
            analysis.build_context_id = build_context_id # Storing build_context_id
            analysis.analysis_status = "image_built" 
            analysis.add_log(f"Docker image {image_id[:12]} built successfully (context: {build_context_id}). LLM agent ran during build. Retrieving output from host.", "success")
            analysis.save()
            self.logger.info(f"[{analysis_id}] Docker image built. LLM output pre-computed. Status: image_built.")
            self._log_workspace_message(f"Docker image built. Retrieving pre-computed LLM analysis for issue #{issue_number} from host...", "loading", analysis_id=analysis_id)
            self._update_loading_animation(animation_id, f"Retrieving LLM analysis from host for issue #{issue_number}...")

            # --- Retrieve analysis output and error log from HOST filesystem ---
            analysis.analysis_status = 'processing_output'
            analysis.add_log("Attempting to read analysis files from host...", "info")
            analysis.save()

            llm_output_content = None
            llm_error_content = None

            if build_context_id_for_paths:
                dockerfiles_base_dir = self.docker_manager.dockerfiles_dir
                output_json_host_path = os.path.join(dockerfiles_base_dir, build_context_id_for_paths, "analysis_output.json")
                error_log_host_path = os.path.join(dockerfiles_base_dir, build_context_id_for_paths, "analysis_error.log")

                analysis.add_log(f"Looking for output JSON at: {output_json_host_path}", "debug")
                if os.path.exists(output_json_host_path):
                    try:
                        with open(output_json_host_path, 'r', encoding='utf-8') as f:
                            llm_output_content = f.read()
                        analysis.add_log("Successfully read analysis_output.json from host.", "info")
                    except Exception as e_read_out:
                        analysis.add_log(f"Error reading analysis_output.json from host: {str(e_read_out)}", "error")
                        self.logger.error(f"[{analysis_id}] Error reading {output_json_host_path}: {e_read_out}")
                else:
                    analysis.add_log("analysis_output.json not found on host.", "warning")
                    self.logger.warning(f"[{analysis_id}] File not found: {output_json_host_path}")

                analysis.add_log(f"Looking for error log at: {error_log_host_path}", "debug")
                if os.path.exists(error_log_host_path):
                    try:
                        with open(error_log_host_path, 'r', encoding='utf-8') as f:
                            llm_error_content = f.read()
                        if llm_error_content and llm_error_content.strip():
                            analysis.add_log("Successfully read analysis_error.log from host. Content preview:", "info")
                            error_preview = "\\n".join(llm_error_content.splitlines()[:20]) # Show more lines
                            analysis.add_log(f"--- Error Log Preview ---\\n{error_preview}\\n--- End Error Log Preview ---", "error_log_preview")
                            self.logger.info(f"[{analysis_id}] Content of {error_log_host_path}:\\n{llm_error_content}")
                        else:
                            analysis.add_log("analysis_error.log found on host but is empty.", "info")
                    except Exception as e_read_err:
                        analysis.add_log(f"Error reading analysis_error.log from host: {str(e_read_err)}", "error")
                        self.logger.error(f"[{analysis_id}] Error reading {error_log_host_path}: {e_read_err}")
                analysis.save()
            else:
                analysis.add_log("Build context ID not available, cannot locate analysis files on host.", "error")
                self.logger.error(f"[{analysis_id}] build_context_id_for_paths is None, cannot form host paths.")
                analysis.save()

            if llm_output_content:
                try:
                    parsed_output = json.loads(llm_output_content)
                    analysis.issue_summary = parsed_output.get('issue_summary', 'Summary not provided.')
                    analysis.code_analysis_summary = parsed_output.get('code_analysis_summary', 'Code analysis not provided.')
                    analysis.proposed_solutions = parsed_output.get('proposed_solutions', [])
                    analysis.raw_llm_output = llm_output_content
                    
                    final_output_parts = [f"Issue Summary: {analysis.issue_summary}"]
                    if analysis.code_analysis_summary and analysis.code_analysis_summary not in ["Code analysis not provided.", ""]:
                        final_output_parts.append(f"Code Analysis: {analysis.code_analysis_summary}")
                    if analysis.proposed_solutions:
                        solutions_str = "\\n".join([f"- {s}" for s in analysis.proposed_solutions])
                        final_output_parts.append(f"Proposed Solutions:\\n{solutions_str}")
                    analysis.final_output = "\\n\\n".join(final_output_parts)

                    if parsed_output.get('error'):
                        analysis.add_log(f"LLM agent reported an error in its output: {parsed_output.get('error')}", "error")
                        analysis.analysis_status = 'error'
                        analysis.error_message = f"LLM agent error: {parsed_output.get('error')}"
                    else:
                        analysis.analysis_status = 'completed' # Changed from 'analysis_complete' for consistency
                    analysis.add_log("Successfully processed LLM analysis output from host.", "success")

                except json.JSONDecodeError as e_json:
                    analysis.analysis_status = 'error' # Changed from 'llm_output_error'
                    analysis.error_message = f"Failed to parse LLM output JSON: {str(e_json)}"
                    analysis.add_log(f"Failed to parse LLM analysis output (JSONDecodeError): {str(e_json)}", "error")
                    analysis.add_log(f"Raw LLM output (from host) was: \\n{llm_output_content[:1000]}...", "debug") # Log preview
                    analysis.raw_llm_output = llm_output_content
                    self.logger.error(f"[{analysis_id}] JSONDecodeError: {e_json}. Raw output preview: {llm_output_content[:500]}")
                else:
                    analysis.analysis_status = 'error' # Changed from 'llm_failed'
                    analysis.error_message = "LLM analysis output file was not found or was empty on host."
                    analysis.add_log("LLM analysis output file (analysis_output.json) was not found or was empty on host.", "error")
                    if llm_error_content and llm_error_content.strip():
                        analysis.add_log("Error log (analysis_error.log) was found on host, indicating a potential script failure during image build. Review error log preview above and full logs.", "warning")
                    else: # No output and no error log, or error log empty
                        analysis.add_log("No significant content found in analysis_error.log either. This suggests the agent script might not have run correctly or produced any output/error during image build.", "warning")
            
            analysis.updated_at = datetime.utcnow()
            analysis.save()
            self_assessment_msg = f"Analysis for issue #{issue_number} finished with status: {analysis.analysis_status}."
            self._end_loading_animation(animation_id, self_assessment_msg, success=(analysis.analysis_status == "completed"))
            self._log_workspace_message(self_assessment_msg, "success" if analysis.analysis_status == "completed" else "error", analysis_id=analysis_id)
                
        except Exception as e:
            self.logger.error(f"[{analysis_id}] Unhandled error in _analyze_in_background for issue #{issue_number}: {str(e)}\\n{traceback.format_exc()}")
            try:
                # Try to update analysis status to error if an object exists
                analysis_obj = IssueAnalysis.objects(id=analysis_id).first()
                if analysis_obj: # Check if analysis_obj might have become None due to earlier errors
                    analysis_obj.analysis_status = "failed" # Universal 'error' changed to 'failed'
                    analysis_obj.error_message = f"Critical background analysis error: {str(e)}"
                    analysis_obj.add_log(f"Critical error in analysis background task: {str(e)}", "error")
                    analysis_obj.save()
                self._log_workspace_message(f"Critical error during analysis of issue #{issue_number}. Check logs.", "error", analysis_id=analysis_id)
                if animation_id: # Ensure animation_id exists before trying to end it
                    self._end_loading_animation(animation_id, "Analysis critically failed.", success=False)
            except Exception as e_save:
                self.logger.error(f"[{analysis_id}] Failed to save error status during critical failure: {e_save}")
        finally:
            if analysis_id in self._background_tasks:
                del self._background_tasks[analysis_id]
            
            # Cleanup the cloned repository directory using the path returned by docker_manager
            if cloned_repo_path_for_cleanup and os.path.exists(cloned_repo_path_for_cleanup):
                try:
                    self.docker_manager.cleanup_cloned_repo(cloned_repo_path_for_cleanup)
                    self.logger.info(f"[{analysis_id}] Cleaned up cloned repo: {cloned_repo_path_for_cleanup}")
                    if analysis: # Check if analysis object exists
                         analysis.add_log(f"Cleaned up cloned repo: {os.path.basename(cloned_repo_path_for_cleanup)}", "info")
                         analysis.save()
                except Exception as e_cleanup:
                    self.logger.error(f"[{analysis_id}] Error cleaning up cloned repo {cloned_repo_path_for_cleanup}: {e_cleanup}")
                    if analysis: # Check if analysis object exists
                        analysis.add_log(f"Error cleaning up repo: {e_cleanup}", "warning")
                        analysis.save()
            self.logger.info(f"[{analysis_id}] Background analysis task finished.")

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