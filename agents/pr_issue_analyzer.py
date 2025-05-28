import re
import json
from typing import Dict, Optional, List, Tuple, Any
import logging
from models import ConnectedRepository, CiPrAnalysis
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
import zipfile
import io
import tempfile

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
    time.sleep(0.2)
     
    # Cancel any running asyncio tasks
    for task in _RUNNING_TASKS:
        try:
            if not task.done():
                task.cancel()
        except:
            pass

# Register cleanup handlers
atexit.register(cleanup_running_tasks)

class PrIssueAnalyzer:
    def __init__(self):
        self.logger = logger
        self.docker_manager = DockerManager()
        self._background_tasks = {}  # Store background analysis tasks

    async def _extract_branch_from_pr_data(self, pr_data: Dict) -> Optional[str]:
        """
        Extracts the source branch from PR data.
        
        Args:
            pr_data: GitHub PR data containing head and base information
            
        Returns:
            str: The source branch name (from "head.ref")
        """
        try:
            if 'head' in pr_data and 'ref' in pr_data['head']:
                branch_name = pr_data['head']['ref']
                self.logger.info(f"Extracted source branch from PR: {branch_name}")
                return branch_name
            else:
                self.logger.warning("No head.ref found in PR data")
                return None
        except Exception as e:
            self.logger.error(f"Error extracting branch from PR data: {e}")
            return None

    async def _extract_ci_logs_from_target_url(self, target_url: str, access_token: Optional[str] = None) -> Optional[str]:
        """
        Extracts CI failure logs from the target URL.
        This method should be implemented based on the CI provider (CircleCI, GitHub Actions, etc.)
        
        Args:
            target_url: URL to the CI job
            access_token: GitHub access token for API access
            
        Returns:
            str: Extracted logs or None if extraction fails
        """
        try:
            if not target_url:
                return None
            
            # Determine CI provider from URL
            if 'circleci.com' in target_url:
                return await self._extract_circleci_logs(target_url, access_token)
            elif 'github.com' in target_url and '/actions/' in target_url:
                return await self._extract_github_actions_logs(target_url, access_token)
            else:
                self.logger.warning(f"Unsupported CI provider for URL: {target_url}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error extracting CI logs from {target_url}: {e}")
            return None

    async def _extract_circleci_logs(self, target_url: str, access_token: Optional[str] = None) -> Optional[str]:
        """Extract logs from CircleCI job URL"""
        try:
            # CircleCI API pattern: https://app.circleci.com/pipelines/github/owner/repo/job_id
            # We would need to convert this to API calls to get the actual logs
            # For now, return a placeholder
            self.logger.info(f"Attempting to extract CircleCI logs from: {target_url}")
            
            # Extract job information from URL
            url_parts = target_url.split('/')
            if len(url_parts) >= 7:
                # Try to extract owner/repo and job info
                owner_repo_index = url_parts.index('github') + 1 if 'github' in url_parts else -1
                if owner_repo_index > 0 and owner_repo_index + 1 < len(url_parts):
                    owner = url_parts[owner_repo_index]
                    repo = url_parts[owner_repo_index + 1]
                    
                    # For now, return a structured message indicating CI failure
                    return f"CircleCI job failed for {owner}/{repo}. Target URL: {target_url}"
            
            return f"CircleCI job failed. Target URL: {target_url}"
            
        except Exception as e:
            self.logger.error(f"Error extracting CircleCI logs: {e}")
            return None

    async def _extract_github_actions_logs(self, target_url: str, access_token: Optional[str] = None) -> Optional[str]:
        """Extract logs from GitHub Actions job URL"""
        try:
            self.logger.info(f"Attempting to extract GitHub Actions logs from: {target_url}")
            extracted_log_summary = f"GitHub Actions job failed. Target URL: {target_url}\n"

            if not access_token:
                self.logger.warning("No GitHub access token provided, cannot fetch detailed GitHub Actions logs.")
                return extracted_log_summary

            url_parts = target_url.split('/')
            owner, repo, run_id = None, None, None

            if 'github.com' in url_parts and 'actions' in url_parts and 'runs' in url_parts:
                try:
                    github_index = url_parts.index('github.com')
                    owner = url_parts[github_index + 1]
                    repo = url_parts[github_index + 2]
                    run_id_index = url_parts.index('runs') + 1
                    if run_id_index < len(url_parts):
                        run_id = url_parts[run_id_index].split('#')[0] # Remove any anchors like #summary
                except ValueError:
                    self.logger.error(f"Could not parse owner, repo, or run_id from GitHub Actions URL: {target_url}")
                    return extracted_log_summary

            if not (owner and repo and run_id and run_id.isdigit()):
                self.logger.error(f"Invalid owner, repo, or run_id extracted for GitHub Actions URL: {target_url} (Owner: {owner}, Repo: {repo}, RunID: {run_id})")
                return extracted_log_summary

            headers = {
                'Authorization': f'token {access_token}',
                'Accept': 'application/vnd.github.v3+json'
            }

            # 1. Get workflow run details (to confirm it failed)
            run_api_url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs/{run_id}"
            run_response = requests.get(run_api_url, headers=headers)
            if run_response.status_code == 200:
                run_data = run_response.json()
                run_conclusion = run_data.get('conclusion', 'unknown')
                workflow_name = run_data.get('name', 'Unknown Workflow')
                extracted_log_summary = f"GitHub Actions workflow '{workflow_name}' (Run ID: {run_id}) concluded with: {run_conclusion}. Target URL: {target_url}\n"
                if run_conclusion not in ['failure', 'cancelled', 'timed_out', 'action_required']:
                    self.logger.info(f"Workflow run {run_id} did not fail (conclusion: {run_conclusion}), not fetching detailed logs.")
                    return extracted_log_summary # No need to fetch logs if the overall run didn't fail in a way we care about.
            else:
                self.logger.error(f"Failed to fetch run details for {run_id}: {run_response.status_code} - {run_response.text}")
                return extracted_log_summary + "Could not verify run status.\n"

            # 2. Get jobs for the workflow run
            jobs_api_url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs/{run_id}/jobs"
            jobs_response = requests.get(jobs_api_url, headers=headers)
            self.logger.info(f"Jobs response: {jobs_response.json()}")
            if jobs_response.status_code != 200:
                self.logger.error(f"Failed to fetch jobs for run {run_id}: {jobs_response.status_code} - {jobs_response.text}")
                return extracted_log_summary + "Could not fetch job list.\n"

            jobs_data = jobs_response.json()
            failed_jobs_logs = []

            for job in jobs_data.get('jobs', []):
                job_id = job.get('id')
                job_name = job.get('name')
                job_conclusion = job.get('conclusion')

                if job_conclusion in ['failure', 'cancelled', 'timed_out']:
                    self.logger.info(f"Fetching logs for failed/cancelled/timed_out job: '{job_name}' (ID: {job_id})")
                    job_log_api_url = f"https://api.github.com/repos/{owner}/{repo}/actions/jobs/{job_id}/logs"
                    
                    # GitHub API for logs redirects to a temporary download URL.
                    # We need to handle the redirect without allowing requests to store cookies from the first hop.
                    log_download_response = requests.get(job_log_api_url, headers=headers, allow_redirects=False)

                    if log_download_response.status_code == 302: # Found (redirect)
                        download_url = log_download_response.headers.get('Location')
                        if download_url:
                            try:
                                # Make a new request to the download URL without auth headers, as it's usually a pre-signed S3/Azure URL
                                actual_log_response = requests.get(download_url, timeout=30, stream=True) # stream=True for binary content
                                actual_log_response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                                
                                log_content_bytes = actual_log_response.content # Get raw bytes
                                all_errors_from_job = []

                                # Check if content is a ZIP file (basic check using magic number PK\x03\x04)
                                if log_content_bytes.startswith(b'PK\x03\x04'):
                                    self.logger.info(f"Log for job '{job_name}' is a ZIP archive. Extracting...")
                                    with tempfile.TemporaryDirectory() as temp_dir:
                                        zip_file_path = os.path.join(temp_dir, 'logs.zip')
                                        with open(zip_file_path, 'wb') as f_zip:
                                            f_zip.write(log_content_bytes)
                                        
                                        with zipfile.ZipFile(zip_file_path, 'r') as archive:
                                            for member_name in archive.namelist():
                                                # Process only .log or .txt files, or files with no extension in a step folder
                                                if member_name.endswith(('.log', '.txt')) or (member_name.count('/') > 0 and '.' not in os.path.basename(member_name)):
                                                    self.logger.info(f"Processing '{member_name}' from archive for job '{job_name}'.")
                                                    try:
                                                        member_content = archive.read(member_name).decode('utf-8', errors='replace')
                                                        error_snippet = self._extract_errors_from_log_content(member_content)
                                                        if error_snippet:
                                                            all_errors_from_job.append(f"File: {member_name}\n{error_snippet}")
                                                    except Exception as e_member_proc:
                                                        self.logger.warning(f"Could not process/decode member '{member_name}' from zip for job '{job_name}': {e_member_proc}")
                                else: # Not a zip file, treat as plain text
                                    self.logger.info(f"Log for job '{job_name}' is plain text.")
                                    log_content_text = log_content_bytes.decode('utf-8', errors='replace')
                                    error_snippet = self._extract_errors_from_log_content(log_content_text)
                                    if error_snippet:
                                        all_errors_from_job.append(error_snippet)
                                
                                if all_errors_from_job:
                                    combined_errors = "\n---\n".join(all_errors_from_job)
                                    failed_jobs_logs.append(f"--- Job: {job_name} (Conclusion: {job_conclusion}) ---\nRelevant error snippets found:\n{combined_errors}\n")
                                    self.logger.info(f"Successfully extracted error snippets for job '{job_name}'.")
                                else:
                                    # If no specific errors found by regex, fall back to tail of the (first/primary) log
                                    log_lines = log_content_bytes.decode('utf-8', errors='replace').splitlines()
                                    tail_lines_count = 50 # Shorter tail if no specific error found
                                    tail_section = "\n".join(log_lines[-tail_lines_count:])
                                    failed_jobs_logs.append(f"--- Job: {job_name} (Conclusion: {job_conclusion}) ---\nNo specific error keywords found. Log tail (last {tail_lines_count} lines):\n{tail_section}\n")
                                    self.logger.info(f"No specific errors found for job '{job_name}', extracted tail.")

                            except requests.exceptions.RequestException as e_log_dl:
                                self.logger.error(f"Error downloading log for job '{job_name}' from {download_url}: {e_log_dl}")
                                failed_jobs_logs.append(f"--- Job: {job_name} (Conclusion: {job_conclusion}) ---\nError downloading logs: {e_log_dl}\n")
                            except Exception as e_log_proc:
                                self.logger.error(f"Error processing log for job '{job_name}': {e_log_proc}")
                                failed_jobs_logs.append(f"--- Job: {job_name} (Conclusion: {job_conclusion}) ---\nError processing logs: {e_log_proc}\n")
                        else:
                            self.logger.warning(f"Log download redirect URL not found for job '{job_name}'.")
                            failed_jobs_logs.append(f"--- Job: {job_name} (Conclusion: {job_conclusion}) ---\nLog download URL missing.\n")
                    elif log_download_response.status_code == 204: # No Content, logs might be empty or expired
                         self.logger.info(f"No log content (204) for job '{job_name}'. Logs might be empty or expired.")
                         failed_jobs_logs.append(f"--- Job: {job_name} (Conclusion: {job_conclusion}) ---\nNo log content available (possibly empty or expired).\n")
                    else:
                        self.logger.error(f"Failed to get log download URL for job '{job_name}': {log_download_response.status_code} - {log_download_response.text}")
                        failed_jobs_logs.append(f"--- Job: {job_name} (Conclusion: {job_conclusion}) ---\nFailed to retrieve log location: {log_download_response.status_code}\n")
            
            if failed_jobs_logs:
                extracted_log_summary += "\nDetailed Logs (Tail Sections):\n" + "\n".join(failed_jobs_logs)
            else:
                extracted_log_summary += "No detailed logs from failed jobs could be retrieved or no jobs explicitly failed.\n"

            return extracted_log_summary

        except Exception as e:
            self.logger.error(f"Error extracting GitHub Actions logs for {target_url}: {e}", exc_info=True)
            return f"Error during GitHub Actions log extraction: {str(e)}\nTarget URL: {target_url}"

    def _extract_errors_from_log_content(self, log_content: str) -> Optional[str]:
        """Extracts text after the first occurrence of error keywords using regex."""
        # Regex to find the first occurrence of error keywords (case-insensitive) and capture everything after.
        # Includes common delimiters like space or colon after the keyword.
        # re.DOTALL allows .* to match across newlines.
        match = re.search(r'(?:ERROR|Error|FAIL|FAILURE|fatal)[\s:]*(.*)', log_content, re.IGNORECASE | re.DOTALL)
        if match:
            # Return everything after the keyword
            return match.group(1).strip()
        return None

    async def get_or_create_analysis(
        self,
        pr_data: Dict,
        repository: ConnectedRepository,
        access_token: Optional[str] = None,
        initial_analysis_object: Optional[CiPrAnalysis] = None
    ) -> Tuple[Optional[CiPrAnalysis], bool]:
        """
        Get an existing CI PR analysis or create a new one if it doesn't exist.
        
        Args:
            pr_data: GitHub PR data
            repository: ConnectedRepository object
            access_token: GitHub access token
            initial_analysis_object: Existing analysis object if available
            
        Returns:
            Tuple of (analysis_object, was_created_by_this_call)
        """
        created_by_this_call = False
        analysis_to_process = None

        if initial_analysis_object:
            self.logger.info(f"PR Analyzer: Received initial_analysis_object for PR #{initial_analysis_object.pr_number}")
            analysis_to_process = initial_analysis_object
        else:
            # Try to find existing analysis
            pr_number = pr_data.get('number')
            existing_analysis = CiPrAnalysis.objects(
                repository=repository,
                pr_number=pr_number
            ).first()
            
            if existing_analysis:
                self.logger.info(f"Found existing CI PR analysis for PR #{pr_number}")
                analysis_to_process = existing_analysis
            else:
                # Create new analysis
                self.logger.info(f"Creating new CI PR analysis for PR #{pr_number}")
                
                analysis_to_process = CiPrAnalysis(
                    repository=repository,
                    pr_number=pr_number,
                    pr_id=str(pr_data.get('id', '')),
                    pr_title=pr_data.get('title', ''),
                    pr_html_url=pr_data.get('html_url', ''),
                    commit_sha=pr_data.get('head', {}).get('sha', ''),
                    ci_status='failed',
                    analysis_status='not_started'
                )
                analysis_to_process.save()
                created_by_this_call = True

        return analysis_to_process, created_by_this_call

    def _run_async_in_thread(self, coro):
        """
        Run an async coroutine in a separate thread with its own event loop.
        This prevents issues with existing event loops.
        """
        def run_in_thread():
            try:
                # Create a new event loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                try:
                    result = loop.run_until_complete(coro)
                    return result
                finally:
                    loop.close()
                    
            except Exception as e:
                logger.error(f"Error running async operation in thread: {str(e)}")
                logger.error(traceback.format_exc())
                return None
        
        # Run in a separate thread
        thread = threading.Thread(target=run_in_thread)
        thread.start()
        thread.join()  # Wait for completion

    async def _analyze_in_background(
        self,
        analysis_id: str,
        pr_data: Dict,
        repository: ConnectedRepository,
        access_token: Optional[str] = None
    ):
        """
        Perform the actual CI failure analysis in the background.
        
        Args:
            analysis_id: ID of the CiPrAnalysis object
            pr_data: GitHub PR data
            repository: ConnectedRepository object
            access_token: GitHub access token
        """
        analysis = None
        animation_id = None
        
        try:
            # Get the analysis object
            analysis = CiPrAnalysis.objects(id=analysis_id).first()
            if not analysis:
                self.logger.error(f"Could not find CI PR analysis with ID: {analysis_id}")
                return
            
            # Update status to in_progress
            analysis.analysis_status = 'in_progress'
            analysis.save()
            
            # Start loading animation
            animation_id = self._start_loading_animation("Analyzing CI failure")
            
            # Extract branch name from PR data
            branch_name = await self._extract_branch_from_pr_data(pr_data)
            if branch_name:
                self._log_workspace_message(f"Extracted source branch: {branch_name}", "info", analysis_id)
            else:
                branch_name = "main"  # Default fallback
                self._log_workspace_message(f"Could not extract branch, using default: {branch_name}", "warning", analysis_id)
            
            # Extract CI logs if target URL is available
            target_url = getattr(analysis, 'ci_target_url', None)
            self.logger.info(f"PR Analyzer: Extracting CI logs from {target_url}")
            import pdb; pdb.set_trace()
            if target_url:
                self._update_loading_animation(animation_id, "Extracting CI failure logs")
                
                ci_logs = await self._extract_ci_logs_from_target_url(target_url, access_token)
                
                if ci_logs:
                    self._log_workspace_message(f"Extracted CI logs", "success", analysis_id)
                    self._log_workspace_message(f"CI Logs:\n{ci_logs}", "info", analysis_id)
                else:
                    self._log_workspace_message("Could not extract detailed CI logs", "warning", analysis_id)
            else:
                self._log_workspace_message("No CI target URL available for log extraction", "warning", analysis_id)
            
            # Create container for analysis
            self._update_loading_animation(animation_id, "Setting up analysis environment")
            
            try:
                container_info = await self._create_custom_container(
                    repo_name=repository.name,
                    pr_number=analysis.pr_number,
                    branch=branch_name,
                    access_token=access_token,
                    animation_id=animation_id,
                    analysis_id=analysis_id,
                    pr_data=pr_data
                )
                
                if container_info and container_info.get('container_id'):
                    self._log_workspace_message(f"Created analysis container: {container_info['container_id'][:12]}", "success", analysis_id)
                    
                    # Run analysis commands in container
                    await self._run_ci_analysis_in_container(
                        container_info['container_id'],
                        analysis,
                        animation_id
                    )
                    
                else:
                    raise Exception("Failed to create analysis container")
                    
            except Exception as container_error:
                self._log_workspace_message(f"Container setup failed: {str(container_error)}", "error", analysis_id)
                raise
            
            # Update analysis status to completed
            analysis.analysis_status = 'completed'
            analysis.save()
            
            self._end_loading_animation(animation_id, "CI failure analysis completed", True)
            self._log_workspace_message("CI failure analysis completed successfully", "success", analysis_id)
            
        except Exception as e:
            self.logger.error(f"Error in CI PR analysis: {str(e)}")
            self.logger.error(traceback.format_exc())
            
            if analysis:
                analysis.analysis_status = 'failed'
                analysis.error_message = str(e)
                analysis.save()
            
            if animation_id:
                self._end_loading_animation(animation_id, f"Analysis failed: {str(e)}", False)
            
            self._log_workspace_message(f"Analysis failed: {str(e)}", "error", analysis_id)

    async def _create_custom_container(
        self,
        repo_name: str,
        pr_number: int,
        branch: str = 'main',
        access_token: Optional[str] = None,
        animation_id: Optional[str] = None,
        analysis_id: Optional[str] = None,
        pr_data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Create a custom Docker container for CI failure analysis.
        
        Args:
            repo_name: Repository name (owner/repo)
            pr_number: PR number (used as issue_number for DockerManager)
            branch: Branch name to checkout
            access_token: GitHub access token
            animation_id: Loading animation ID for UI updates
            analysis_id: Analysis object ID for logging
            pr_data: GitHub PR data for additional context (e.g., PR body for issue.txt)
            
        Returns:
            Dict containing container information
        """
        try:
            if animation_id:
                self._update_loading_animation(animation_id, f"Creating container for {repo_name} PR #{pr_number}")
            
            repo_url = f"https://github.com/{repo_name}" # Construct repo_url
            
            pr_body_for_issue_txt = "No PR body provided." # Default
            if pr_data and pr_data.get('body'):
                pr_body_for_issue_txt = pr_data.get('body')
            elif pr_data:
                 pr_body_for_issue_txt = f"PR Title: {pr_data.get('title', 'N/A')}\nPR Number: #{pr_data.get('number', 'N/A')}"

            self.logger.info(f"Calling DockerManager.create_container for {repo_url}, PR #{pr_number}, branch {branch}")
            # Corrected method name and arguments to match DockerManager.create_container
            container = await self.docker_manager.create_container(
                repo_url=repo_url,
                repo_name=repo_name,
                issue_number=pr_number, # Use pr_number as issue_number for DockerManager context
                branch=branch,
                access_token=access_token,
                issue_body_for_txt_file=pr_body_for_issue_txt
            )
            
            if container and animation_id:
                 self._log_workspace_message(f"DockerManager.create_container call completed for PR #{pr_number}. Container data: {container.get('container_name', 'N/A')}", "info", analysis_id)

            if not container or 'container_id' not in container or 'container_name' not in container:
                err_msg = f"DockerManager.create_container did not return expected container_id/container_name. Got: {container}"
                self.logger.error(err_msg)
                if analysis_id: self._log_workspace_message(err_msg, "error", analysis_id)
                raise Exception(err_msg)
            
            return container
            
        except Exception as e:
            self.logger.error(f"Error creating custom container for PR #{pr_number}: {str(e)}", exc_info=True)
            if analysis_id: self._log_workspace_message(f"Error in _create_custom_container: {str(e)}", "error", analysis_id)
            raise # Re-raise to be caught by _analyze_in_background

    async def _run_ci_analysis_in_container(
        self,
        container_id: str,
        analysis: CiPrAnalysis,
        animation_id: Optional[str] = None
    ):
        """
        Run CI failure analysis commands in the container.
        
        Args:
            container_id: Docker container ID
            analysis: CiPrAnalysis object
            animation_id: Loading animation ID
        """
        try:
            if animation_id:
                self._update_loading_animation(animation_id, "Running CI failure analysis")
            
            # Basic analysis commands
            commands = [
                "pwd",
                "ls -la",
                "git status",
                "git log --oneline -5",
                "git diff HEAD~1 HEAD --name-only"  # Show changed files
            ]
            
            for cmd in commands:
                self._log_workspace_message(f"Running: {cmd}", "info", str(analysis.id))
                result = self._execute_in_container(container_id, cmd)
                
                if result.get('exit_code') == 0:
                    output = result.get('output', '').strip()
                    if output:
                        self._log_workspace_message(f"Output:\n{output}", "info", str(analysis.id))
                else:
                    error_output = result.get('output', '') + result.get('error', '')
                    self._log_workspace_message(f"Command failed: {error_output}", "error", str(analysis.id))
            
            # Try to run tests to reproduce the CI failure
            if animation_id:
                self._update_loading_animation(animation_id, "Attempting to reproduce CI failure")
            
            self._log_workspace_message("Attempting to reproduce CI failure by running tests", "info", str(analysis.id))
            
            # Common test commands to try
            test_commands = [
                "npm test",
                "python -m pytest",
                "python -m unittest discover",
                "make test",
                "./test.sh"
            ]
            
            for test_cmd in test_commands:
                # Check if the command/tool exists first
                check_cmd = f"command -v {test_cmd.split()[0]} || which {test_cmd.split()[0]}"
                check_result = self._execute_in_container(container_id, check_cmd)
                
                if check_result.get('exit_code') == 0:
                    self._log_workspace_message(f"Found {test_cmd.split()[0]}, running tests", "info", str(analysis.id))
                    test_result = self._execute_in_container(container_id, test_cmd)
                    
                    output = test_result.get('output', '') + test_result.get('error', '')
                    if test_result.get('exit_code') != 0:
                        self._log_workspace_message(f"Test failure reproduced with {test_cmd}:", "error", str(analysis.id))
                        self._log_workspace_message(output, "error", str(analysis.id))
                        break
                    else:
                        self._log_workspace_message(f"Tests passed with {test_cmd}", "success", str(analysis.id))
            
        except Exception as e:
            self.logger.error(f"Error running CI analysis in container: {str(e)}")
            self._log_workspace_message(f"Error during container analysis: {str(e)}", "error", str(analysis.id))

    def _execute_in_container(self, container_id: str, command: str) -> Dict:
        """
        Execute a command in the specified container.
        
        Args:
            container_id: Docker container ID
            command: Command to execute
            
        Returns:
            Dict with execution results
        """
        try:
            result = subprocess.run(
                ['docker', 'exec', container_id, 'bash', '-c', command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                'exit_code': result.returncode,
                'output': result.stdout,
                'error': result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {
                'exit_code': -1,
                'output': '',
                'error': 'Command timed out'
            }
        except Exception as e:
            return {
                'exit_code': -1,
                'output': '',
                'error': str(e)
            }

    def analyze_ci_failure(
        self,
        pr_data: Dict,
        repository: ConnectedRepository,
        access_token: Optional[str] = None,
        initial_analysis_object: Optional[CiPrAnalysis] = None
    ) -> Optional[CiPrAnalysis]:
        """
        Main entry point for CI failure analysis.
        
        Args:
            pr_data: GitHub PR data
            repository: ConnectedRepository object
            access_token: GitHub access token
            initial_analysis_object: Existing analysis object if available
            
        Returns:
            CiPrAnalysis object
        """
        self.logger.info(f"PrIssueAnalyzer: analyze_ci_failure called for PR #{initial_analysis_object.pr_number if initial_analysis_object else pr_data.get('number')} in {repository.name}")
        
        analysis_id_for_logs = str(initial_analysis_object.id) if initial_analysis_object and initial_analysis_object.id else None
        if analysis_id_for_logs:
             self._log_workspace_message(f"PrIssueAnalyzer: analyze_ci_failure entered (ID: {analysis_id_for_logs}).", "info", analysis_id_for_logs)

        try:
            # Get or create analysis object
            analysis, created = asyncio.run(
                self.get_or_create_analysis(
                    pr_data=pr_data,
                    repository=repository,
                    access_token=access_token,
                    initial_analysis_object=initial_analysis_object
                )
            )
            
            if not analysis:
                self.logger.error("Failed to get or create CI PR analysis")
                if analysis_id_for_logs: self._log_workspace_message("PrIssueAnalyzer: Failed to get/create CiPrAnalysis object.", "error", analysis_id_for_logs)
                return None
            
            if not analysis_id_for_logs and analysis.id: 
                analysis_id_for_logs = str(analysis.id)
                self._log_workspace_message(f"PrIssueAnalyzer: CiPrAnalysis object obtained/created, ID: {analysis_id_for_logs}.", "info", analysis_id_for_logs)

            task_key = f"{repository.name}_pr_{analysis.pr_number}"
            
            if task_key not in self._background_tasks or not self._background_tasks[task_key].is_alive():
                self.logger.info(f"PrIssueAnalyzer: Attempting to start background analysis thread for PR #{analysis.pr_number}, task_key: {task_key}")
                if analysis_id_for_logs: 
                    self._log_workspace_message(f"PrIssueAnalyzer: Preparing to start background analysis thread.", "info", analysis_id_for_logs)
                
                analysis_coro = self._analyze_in_background(
                    analysis_id=str(analysis.id),
                    pr_data=pr_data,
                    repository=repository,
                    access_token=access_token
                )
                
                analysis_thread = threading.Thread(
                    target=self._run_async_in_thread,
                    args=(analysis_coro,)
                )
                analysis_thread.daemon = True
                analysis_thread.start()
                
                self._background_tasks[task_key] = analysis_thread
                self.logger.info(f"Started CI failure analysis for PR #{analysis.pr_number}")
                if analysis_id_for_logs: 
                    self._log_workspace_message(f"PrIssueAnalyzer: Background analysis thread started.", "info", analysis_id_for_logs)
            else:
                self.logger.info(f"CI failure analysis already running for PR #{analysis.pr_number}")
                if analysis_id_for_logs: 
                    self._log_workspace_message(f"PrIssueAnalyzer: Background analysis thread already running or task key present.", "warning", analysis_id_for_logs)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error in analyze_ci_failure: {str(e)}")
            self.logger.error(traceback.format_exc())
            if analysis_id_for_logs: self._log_workspace_message(f"PrIssueAnalyzer: Exception in analyze_ci_failure: {str(e)}", "error", analysis_id_for_logs)
            return None

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
            logger.info(f"{COLORS['loading']}{icons['loading_start']}{message}...{COLORS['reset']}")
        elif type == "loading_update":
            logger.info(f"{COLORS['loading']}{icons['loading_update']}{message}...{COLORS['reset']}")
        elif type == "loading_end_success":
            logger.info(f"{COLORS['success']}{icons['loading_end_success']}{message}{COLORS['reset']}")
        elif type == "loading_end_error":
            logger.info(f"{COLORS['error']}{icons['loading_end_error']}{message}{COLORS['reset']}")
        else:
            # Standard message types
            if type in COLORS:
                logger.info(f"{COLORS[type]}{icons[type]}{message}{COLORS['reset']}")
            else:
                logger.info(message)
        
        # Try to store log in the database for the current analysis
        try:
            from models import CiPrAnalysis
            
            current_analysis = None
            
            # If an analysis ID was provided directly, try to use it first
            if analysis_id:
                try:
                    current_analysis = CiPrAnalysis.objects(id=analysis_id).first()
                except Exception as e:
                    pass # Keep it simple, if it fails, it fails.
            
            # If we found an analysis, add the log to it
            if current_analysis:
                current_analysis.add_log(message, type)
                current_analysis.save()
                
        except Exception as e:
            logger.debug(f"Error storing log in database: {str(e)}")
        
        # Attempt to flush standard output to ensure visibility in terminal
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass # Ignore if flushing fails (e.g., in some non-terminal environments)
            
        return {"status": "success", "message": "Message logged to workspace"}

    def _start_loading_animation(self, message: str) -> str:
        """Start a real-time loading animation in the workspace terminal"""
        animation_id = str(uuid.uuid4())[:8]
        
        animation_data = {
            'message': message,
            'running': True,
            'thread': None
        }
        
        def run_animation():
            i = 0
            try:
                while animation_data['running']:
                    frame = SPINNER_FRAMES[i % len(SPINNER_FRAMES)]
                    current_message = animation_data['message']
                    
                    logger.info(f"{COLORS['loading']}{frame} {current_message}...{COLORS['reset']}")
                    
                    time.sleep(0.1)
                    i += 1
            except Exception as e:
                logger.error(f"Animation error: {str(e)}")
        
        animation_thread = threading.Thread(target=run_animation)
        animation_thread.daemon = True
        animation_thread.start()
        
        animation_data['thread'] = animation_thread
        _ACTIVE_ANIMATIONS[animation_id] = animation_data
        
        return animation_id

    def _update_loading_animation(self, animation_id: str, message: str) -> None:
        """Update an existing loading animation"""
        if animation_id in _ACTIVE_ANIMATIONS:
            _ACTIVE_ANIMATIONS[animation_id]['message'] = message
        else:
            self._log_workspace_message(f"{message}", type="loading_update")

    def _end_loading_animation(self, animation_id: str, message: str, success: bool = True) -> None:
        """End a loading animation with success or error"""
        if animation_id in _ACTIVE_ANIMATIONS:
            _ACTIVE_ANIMATIONS[animation_id]['running'] = False
            
            if _ACTIVE_ANIMATIONS[animation_id]['thread']:
                _ACTIVE_ANIMATIONS[animation_id]['thread'].join(timeout=0.5)
            
            del _ACTIVE_ANIMATIONS[animation_id]
        
        end_type = "loading_end_success" if success else "loading_end_error"
        self._log_workspace_message(message, end_type) 