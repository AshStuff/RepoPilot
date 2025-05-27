#!/usr/bin/env python3
import sys
import os
import json
import logging
import re # Ensure re is imported

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

    llm_conversation_raw = coder.run(prompt) # Aider's run method returns the conversation string
    logger.info(f"Aider LLM interaction completed. Raw conversation length: {len(llm_conversation_raw)}")
    # Extract the explanation from the conversation
    explanation_marker_match = re.search(r"(?:\*\*|##|#|)\s*Explanation[:\*\*]*", llm_conversation_raw, re.IGNORECASE)
    explanation = "No explanation provided in the LLM response."

    if explanation_marker_match:
        explanation_start_offset = explanation_marker_match.end()
        explanation = llm_conversation_raw[explanation_start_offset:].strip()
    # else: explanation remains the default message
    
    # logger.debug(f"Aider raw conversation: {llm_conversation_raw}") # Potentially very long
    
    # Update final_output structure based on Aider's attempt to fix code
    final_output["issue_summary"] = issue_content # Keep the original issue content
    final_output["solution_analysis"] = {
        "action_taken": "Aider LLM was instructed to identify and fix the bug based on the issue.",
        "aider_conversation_log": llm_conversation_raw,
        "explanation": explanation,
        "notes": "Aider attempts to modify files directly in the workspace. Check the /workspace/repo_name/ directory for changes."
    }

    # The old JSON parsing logic for LLM response is no longer needed as Aider's response is a conversation string and changes are file-based.
    # The `llm_response_json` related try-except block and subsequent assignments are removed.

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
        sys.exit(1) # Exit with error code 