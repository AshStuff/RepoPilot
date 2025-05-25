#!/usr/bin/env python3
import sys
import os

# --- BEGIN: Early setup for log redirection ---
ANALYSIS_RESULTS_DIR = '/workspace/analysis_results'
# Ensure the target directory for logs exists
os.makedirs(ANALYSIS_RESULTS_DIR, exist_ok=True)

# User wants the variable for 'analysis_err.log' path to be analysis_output_err_path
ANALYSIS_ERR_LOG_PATH = os.path.join(ANALYSIS_RESULTS_DIR, 'analysis_err.log')

# Open the log file in append mode.
# Keep a reference to the original stdout/stderr if needed for some reason, though typically not.
# original_stdout = sys.stdout
# original_stderr = sys.stderr

log_file_handle = open(ANALYSIS_ERR_LOG_PATH, 'a')
sys.stdout = log_file_handle
sys.stderr = log_file_handle
# --- END: Early setup for log redirection ---

# Print a startup message to stderr immediately to help debug execution and redirection.
# This should appear in /app/analysis_error.log if the script starts and stderr is captured.
print("container_agent.py: Execution started.", file=sys.stderr)
sys.stderr.flush()

import json
import logging

# Remove the problematic sys.path.append for ../../.venv
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.venv/lib/python3.10/site-packages')))

print("container_agent.py: Initial imports (json, logging) successful.", file=sys.stderr)
sys.stderr.flush()

try:
    print("container_agent.py: Attempting to import create_agent from cursor_agent_tools.", file=sys.stderr)
    sys.stderr.flush()
    from cursor_agent_tools.agent import create_agent
    print("container_agent.py: Successfully imported create_agent.", file=sys.stderr)
    sys.stderr.flush()
except ImportError as e_import:
    print(f"container_agent.py: ImportError for create_agent: {str(e_import)}", file=sys.stderr)
    sys.stderr.flush()
    # Fallback if cursor_agent_tools is not found in the typical path
    # This is a placeholder and might need adjustment based on actual Docker image structure
    # The pip install in Dockerfile should handle this.
    logging.warning("cursor_agent_tools not found directly. Ensure it was installed by requirements.txt in Dockerfile.")
    # Create a mock agent if the import fails, so the script can at least output structured error.
    def create_agent(model=None):
        print("container_agent.py: Using MockAgent due to import failure.", file=sys.stderr)
        sys.stderr.flush()
        class MockAgent:
            async def run(self, prompt):
                return json.dumps({
                    "error": "LLM Agent (cursor_agent_tools) not available in container. Import failed.",
                    "issue_summary": "Error: LLM could not be initialized.",
                    "proposed_solutions": ["Ensure LLM tooling (cursor_agent_tools) is installed in the Docker image via requirements.txt."]
                })
            def register_tool(self, **kwargs): pass
        return MockAgent()

# Configure logging to go to ANALYSIS_ERR_LOG_PATH
logging.basicConfig(filename=ANALYSIS_ERR_LOG_PATH, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
    print("container_agent.py: _get_repo_path called", file=sys.stderr)
    sys.stderr.flush()
    """Determines the path to the cloned repository inside the container.
    Uses REPO_BASENAME environment variable if set, otherwise tries to discover it.
    """
    workspace_dir = '/workspace'
    repo_basename_env = os.environ.get('REPO_BASENAME')

    if repo_basename_env:
        found_path = os.path.join(workspace_dir, repo_basename_env)
        if os.path.exists(found_path) and os.path.isdir(found_path):
            print(f"container_agent.py: Using REPO_BASENAME env var, repo path: {found_path}", file=sys.stderr)
            sys.stderr.flush()
            return found_path
        else:
            print(f"container_agent.py: REPO_BASENAME '{repo_basename_env}' not found at {found_path}. Falling back to discovery.", file=sys.stderr)
            sys.stderr.flush()

    # Fallback to discovery if REPO_BASENAME is not set or path doesn't exist
    try:
        print(f"container_agent.py: REPO_BASENAME not set or invalid. Discovering repo in {workspace_dir}", file=sys.stderr)
        sys.stderr.flush()
        entries = os.listdir(workspace_dir)
        print(f"container_agent.py: Entries in {workspace_dir}: {entries}", file=sys.stderr)
        sys.stderr.flush()
        
        # Filter out common non-repo items like '.DS_Store' or if other files are expected
        potential_repos = [d for d in entries if os.path.isdir(os.path.join(workspace_dir, d)) and not d.startswith('.')]

        if not potential_repos:
            logger.error("No suitable repository directories found in /workspace.")
            print("container_agent.py: No suitable repository directories found in /workspace.", file=sys.stderr)
            sys.stderr.flush()
            return None
        
        # If multiple, could add logic or take the first one
        # For now, assuming the first valid directory is the repo.
        repo_name_dir = potential_repos[0]
        found_path = os.path.join(workspace_dir, repo_name_dir)
        print(f"container_agent.py: Discovered repo path: {found_path}", file=sys.stderr)
        sys.stderr.flush()
        return found_path
    except FileNotFoundError:
        logger.error(f"Workspace directory '{workspace_dir}' not found.")
        print(f"container_agent.py: Workspace directory '{workspace_dir}' not found.", file=sys.stderr)
        sys.stderr.flush()
        return None
    except Exception as e:
        logger.error(f"Error determining repo path via discovery: {str(e)}")
        print(f"container_agent.py: Error determining repo path via discovery: {str(e)}", file=sys.stderr)
        sys.stderr.flush()
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
            relative_path = os.path.relpath(full_path, repo_base_path)
            all_files.append(relative_path)
    logger.info(f"Found {len(all_files)} files in codebase at {repo_base_path} (excluding .git and hidden files)")
    return all_files

async def main():
    print("container_agent.py: main() started.", file=sys.stderr)
    sys.stderr.flush()
    logger.info("Container agent started (logged to stderr via logger config).")

    analysis_results_dir = ANALYSIS_RESULTS_DIR # Use the global constant
    # os.makedirs(analysis_results_dir, exist_ok=True) # Already done at the top
    analysis_output_path = os.path.join(analysis_results_dir, 'analysis_output.json')

    final_output = {
        "issue_summary": "Analysis not performed.",
        "codebase_overview": {"files": [], "error": None},
        "solution_analysis": {"error": "Agent did not run or failed."}
    }

    issue_file_path = '/app/issue.txt'
    issue_content = ""
    print(f"container_agent.py: Checking for issue file at {issue_file_path}", file=sys.stderr)
    sys.stderr.flush()
    if os.path.exists(issue_file_path):
        with open(issue_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            issue_content = f.read()
        logger.info(f"Successfully read issue content from {issue_file_path}")
        print(f"container_agent.py: Successfully read {issue_file_path}", file=sys.stderr)
        sys.stderr.flush()
    else:
        logger.warning(f"Issue file not found at {issue_file_path}")
        print(f"container_agent.py: Issue file not found at {issue_file_path}", file=sys.stderr)
        sys.stderr.flush()
        issue_content = "Issue content not available."
        final_output["issue_summary"] = "Error: Issue file not found at /app/issue.txt."
        # Early exit if no issue content, as analysis would be pointless
        with open(analysis_output_path, 'w') as f_out:
            json.dump(final_output, f_out, indent=4)
        print(f"container_agent.py: Critical error - issue file not found. Outputting error to {analysis_output_path} and exiting.", file=sys.stderr)
        return

    repo_path = _get_repo_path()
    if not repo_path:
        logger.error("Repository path could not be determined. Cannot analyze codebase.")
        print("container_agent.py: Repository path is None. Exiting.", file=sys.stderr)
        sys.stderr.flush()
        final_output["codebase_overview"]["error"] = "Repository path could not be determined inside container."
        final_output["issue_summary"] = issue_content # We have issue, but no codebase
        final_output["solution_analysis"]["error"] = "Codebase not found."
        with open(analysis_output_path, 'w') as f_out:
            json.dump(final_output, f_out, indent=4)
        print(f"container_agent.py: Critical error - repo path not found. Outputting error to {analysis_output_path} and exiting.", file=sys.stderr)
        return

    logger.info(f"Repository path determined as: {repo_path}")
    print(f"container_agent.py: Repository path: {repo_path}", file=sys.stderr)
    sys.stderr.flush()

    codebase_files = get_all_codebase_files(repo_path)
    final_output["codebase_overview"]["files"] = codebase_files
    if not codebase_files:
        final_output["codebase_overview"]["error"] = "No files found in the codebase or error during scan."
        # Continue to LLM, maybe it can still say something based on issue.
        logger.warning(f"No files found in the codebase at {repo_path}. Proceeding with issue only.")


    agent = None
    try:
        print("container_agent.py: Initializing LLM agent...", file=sys.stderr)
        sys.stderr.flush()
        agent = create_agent(model='ollama-qwen2.5-coder')
        logger.info("LLM agent initialized.")
        print("container_agent.py: LLM agent initialized.", file=sys.stderr)
        sys.stderr.flush()

        # Tools are already registered in the provided code, assuming they are useful for the LLM
        # If not, they can be removed or new ones added specific to summarization/analysis.
        # For now, keeping existing tools.
        agent.register_tool(
            name="list_repository_directory",
            function=list_directory_contents,
            description="Lists files and directories at a given relative path within the cloned repository. Use this to explore the codebase structure if needed.",
            parameters={"type": "object", "properties": {"path": {"type": "string", "description": "The relative path to list contents from. Defaults to repository root if not specified."}}, "required": []}
        )
        agent.register_tool(
            name="read_repository_file",
            function=read_file_content,
            description="Reads the content of a specific file (given its relative path) from the cloned repository. Use this to understand specific code segments if needed for deeper analysis.",
            parameters={"type": "object", "properties": {"filepath": {"type": "string", "description": "The relative path of the file to read."}}, "required": ["filepath"]}
        )
        logger.info("Agent tools registered.")
        print("container_agent.py: Agent tools registered.", file=sys.stderr)
        sys.stderr.flush()

    except Exception as e:
        logger.error(f"Failed to initialize LLM agent or register tools: {str(e)}")
        print(f"container_agent.py: LLM agent/tool registration failed: {str(e)}", file=sys.stderr)
        sys.stderr.flush()
        final_output["solution_analysis"]["error"] = f"LLM Agent initialization failed: {str(e)}"
        final_output["issue_summary"] = issue_content # We have issue content
        with open(analysis_output_path, 'w') as f_out:
            json.dump(final_output, f_out, indent=4)
        print(f"container_agent.py: Critical error - LLM init failed. Outputting error to {analysis_output_path} and exiting.", file=sys.stderr)
        return

    # Construct the prompt for the LLM
    # Limiting file list length in prompt to avoid excessive token usage
    max_files_in_prompt = 200 
    files_for_prompt = codebase_files
    if len(codebase_files) > max_files_in_prompt:
        files_for_prompt = codebase_files[:max_files_in_prompt] + ["... (list truncated)"]
    
    codebase_structure_info = "\n".join(files_for_prompt)

    prompt = f"""
You are an expert software engineering assistant. Your task is to analyze a GitHub issue and the associated codebase structure to provide a concise summary and a high-level plan for a solution.

**GitHub Issue:**
```
{issue_content}
```

**Codebase Structure (List of files):**
```
{codebase_structure_info}
```

**Your Task:**
1.  **Summarize the Issue:** Briefly explain the problem reported in the GitHub issue.
2.  **Analyze and Propose Solution Strategy:** 
    *   Based on the issue and the list of files, identify which 1-3 files are *most likely* to be relevant for addressing this issue.
    *   Outline a high-level plan or a general strategy to solve the issue. Do NOT write actual code. Describe the steps or changes that would likely be needed.
    *   If the issue is unclear or more information is needed from the codebase, state what you would investigate further.

Please provide your response in a JSON format with the following keys:
- "issue_summary": (string) Your summary of the issue.
- "relevant_files": (list of strings) List of 1-3 file paths you identified as most relevant.
- "solution_strategy": (string) Your high-level plan or strategy.
- "further_investigation_needed": (string, optional) If applicable, what else needs to be checked.

Example JSON output format:
{{
  "issue_summary": "The user is reporting that the login button is not working on the checkout page.",
  "relevant_files": ["src/components/CheckoutPage.js", "src/api/auth.js"],
  "solution_strategy": "Investigate the onClick handler for the login button in CheckoutPage.js. Check if the API call to the authentication service in auth.js is being made correctly and if there are any errors in the response. Ensure user session is correctly handled.",
  "further_investigation_needed": "Verify browser console logs for any client-side errors when the button is clicked."
}}
"""

    logger.info(f"Prompting LLM agent. Issue content length: {len(issue_content)}, Codebase files: {len(codebase_files)}")
    # Make sure agent.run() is awaited if it's an async function
    llm_response_raw = await agent.chat(prompt) # Removed host parameter here
    logger.info("LLM agent chat completed.")
    print("container_agent.py: LLM agent chat completed.", file=sys.stderr)
    
    # Attempt to parse the LLM response as JSON
    try:
        logger.info(f"container_agent.py: LLM response: {llm_response_raw}", file=sys.stderr)
        llm_response_json = json.loads(llm_response_raw)
        final_output["issue_summary"] = llm_response_json.get("issue_summary", "LLM did not provide an issue summary.")
        # Preserve the full LLM analysis under solution_analysis for more detail
        final_output["solution_analysis"] = llm_response_json 
    except json.JSONDecodeError:
        logger.error("LLM response was not valid JSON. Storing raw response.")
        print("container_agent.py: LLM response was not valid JSON.", file=sys.stderr)
        sys.stderr.flush()
        final_output["issue_summary"] = issue_content # Fallback to original issue content
        final_output["solution_analysis"] = {
            "error": "LLM response was not valid JSON.",
            "raw_response": llm_response_raw
        }
    except Exception as e_parse: # Catch any other parsing errors
        logger.error(f"Error processing LLM JSON response: {str(e_parse)}")
        final_output["issue_summary"] = issue_content
        final_output["solution_analysis"] = {
            "error": f"Error processing LLM JSON response: {str(e_parse)}",
            "raw_response": llm_response_raw
        }

    # Write the final structured output to analysis_output.json
    try:
        with open(analysis_output_path, 'w') as f_out:
            json.dump(final_output, f_out, indent=4)
        logger.info(f"Analysis output successfully written to {analysis_output_path}")
        print(f"container_agent.py: Output written to {analysis_output_path}", file=sys.stderr)
        sys.stderr.flush()
    except Exception as e_write:
        logger.error(f"Failed to write analysis output to {analysis_output_path}: {str(e_write)}")
        print(f"container_agent.py: Failed to write output to {analysis_output_path}: {str(e_write)}", file=sys.stderr)
        sys.stderr.flush()

    # The original script printed the raw LLM response to stdout for the host.
    # Now, the host (IssueAnalyzer) should read analysis_output.json instead.
    # For direct observation or simpler host scripts, we can still print a summary or the JSON path.
    print(f"Analysis complete. Output written to {analysis_output_path}", file=sys.stdout)
    sys.stdout.flush()
    print("container_agent.py: main() finished.", file=sys.stderr)
    sys.stderr.flush()

if __name__ == '__main__':
    # Ensure that the script can be run with asyncio.run
    import asyncio
    print("container_agent.py: Script __main__ started.", file=sys.stderr)
    sys.stderr.flush()
    try:
        asyncio.run(main())
    except Exception as e_run:
        # Catch-all for any unhandled exceptions during asyncio.run(main())
        # This ensures that some error output is produced if main() itself crashes unexpectedly.
        logger.critical(f"Critical error running main_async: {str(e_run)}", exc_info=True)
        print(f"container_agent.py: Critical error in main_async: {str(e_run)}", file=sys.stderr)
        sys.stderr.flush()
        # Attempt to write a minimal error to the output file
        error_output_path = os.path.join(ANALYSIS_RESULTS_DIR, 'analysis_output.json') # Corrected path
        try:
            with open(error_output_path, 'w') as f_err:
                json.dump({
                    "error": f"Critical failure in container_agent.py: {str(e_run)}",
                    "issue_summary": "Analysis failed critically.",
                    "codebase_overview": {},
                    "solution_analysis": {}
                }, f_err, indent=4)
            print(f"container_agent.py: Minimal error JSON written to {error_output_path}", file=sys.stderr)
        except Exception as e_final_write:
            print(f"container_agent.py: Could not even write minimal error JSON: {str(e_final_write)}", file=sys.stderr)
        sys.exit(1) # Exit with error code 