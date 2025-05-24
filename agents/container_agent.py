#!/usr/bin/env python3
import sys
import os
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

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
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
    """Determines the path to the cloned repository inside the container."""
    # The repo is cloned into /workspace/<repo_name_dir>
    # We need to find out <repo_name_dir>. Usually, there's only one directory in /workspace.
    workspace_dir = '/workspace'
    try:
        print(f"container_agent.py: Listing directory {workspace_dir}", file=sys.stderr)
        sys.stderr.flush()
        entries = os.listdir(workspace_dir)
        print(f"container_agent.py: Entries in {workspace_dir}: {entries}", file=sys.stderr)
        sys.stderr.flush()
        if not entries:
            logger.error("No directories found in /workspace.")
            print("container_agent.py: No directories found in /workspace.", file=sys.stderr)
            sys.stderr.flush()
            return None
        # Assuming the first entry is the repo directory.
        # This could be made more robust if there's a standard naming convention or env var.
        repo_name_dir = entries[0] 
        found_path = os.path.join(workspace_dir, repo_name_dir)
        print(f"container_agent.py: Determined repo path: {found_path}", file=sys.stderr)
        sys.stderr.flush()
        return found_path
    except FileNotFoundError:
        logger.error(f"Workspace directory '{workspace_dir}' not found.")
        print(f"container_agent.py: Workspace directory '{workspace_dir}' not found.", file=sys.stderr)
        sys.stderr.flush()
        return None
    except Exception as e:
        logger.error(f"Error determining repo path: {str(e)}")
        print(f"container_agent.py: Error determining repo path: {str(e)}", file=sys.stderr)
        sys.stderr.flush()
        return None

async def main():
    print("container_agent.py: main() started.", file=sys.stderr)
    sys.stderr.flush()
    logger.info("Container agent started (logged to stderr via logger config).")

    issue_file_path = '/app/issue.txt'
    issue_content = ""
    print(f"container_agent.py: Checking for issue file at {issue_file_path}", file=sys.stderr)
    sys.stderr.flush()
    if os.path.exists(issue_file_path):
        with open(issue_file_path, 'r') as f:
            issue_content = f.read()
        logger.info(f"Successfully read issue content from {issue_file_path}")
        print(f"container_agent.py: Successfully read {issue_file_path}", file=sys.stderr)
        sys.stderr.flush()
    else:
        logger.warning(f"Issue file not found at {issue_file_path}")
        print(f"container_agent.py: Issue file not found at {issue_file_path}", file=sys.stderr)
        sys.stderr.flush()
        issue_content = "Issue content not available."

    repo_path = _get_repo_path()
    if not repo_path:
        logger.error("Repository path could not be determined. Cannot analyze codebase.")
        print("container_agent.py: Repository path is None. Exiting.", file=sys.stderr)
        sys.stderr.flush()
        # Output error JSON and exit
        print(json.dumps({
            "error": "Repository path could not be determined inside container.",
            "issue_summary": "Error: Codebase not found.",
            "proposed_solutions": []
        }))
        return

    logger.info(f"Repository path determined as: {repo_path}")
    print(f"container_agent.py: Repository path: {repo_path}", file=sys.stderr)
    sys.stderr.flush()

    agent = None # Initialize agent variable
    try:
        print("container_agent.py: Initializing LLM agent...", file=sys.stderr)
        sys.stderr.flush()
        agent = create_agent(model='ollama-qwen2.5-coder')
        logger.info("LLM agent initialized.")
        print("container_agent.py: LLM agent initialized.", file=sys.stderr)
        sys.stderr.flush()

        agent.register_tool(
            name="list_repository_directory",
            function=list_directory_contents,
            description="Lists files and directories at a given relative path within the cloned repository. Use this to explore the codebase structure."
        )
        agent.register_tool(
            name="read_repository_file",
            function=read_file_content,
            description="Reads the content of a specific file (given its relative path) from the cloned repository. Use this to understand specific code segments."
        )
        logger.info("Agent tools registered.")
        print("container_agent.py: Agent tools registered.", file=sys.stderr)
        sys.stderr.flush()

    except Exception as e:
        logger.error(f"Failed to initialize LLM agent or register tools: {str(e)}")
        print(f"container_agent.py: LLM agent/tool registration failed: {str(e)}", file=sys.stderr)
        sys.stderr.flush()
        print(json.dumps({
            "error": f"LLM Agent initialization failed: {str(e)}",
            "issue_summary": "Error: LLM could not be initialized for analysis.",
            "proposed_solutions": ["Check LLM agent setup in the container."]
        }))
        return # Exit if agent setup fails

    prompt = f"""
You are an expert software engineering assistant.
Your task is to analyze a GitHub issue and the associated codebase to provide a summary and potential solutions.

**Issue Content (from /app/issue.txt):**
---
{issue_content}
---

**Codebase Context:**
The codebase for this issue is located in the '{repo_path}' directory.
You have tools to explore this codebase:
1. `list_repository_directory(path='relative/path/to/dir')`: To list contents of a directory.
2. `read_repository_file(filepath='relative/path/to/file.py')`: To read a specific file.

**Instructions:**
1.  **Summarize the Issue:** Briefly explain the problem reported in the issue content.
2.  **Analyze Code (If Necessary):** Based on the issue, use your tools to explore relevant parts of the codebase.
    Think step-by-step about what files or directories might be relevant.
    For example, if the issue mentions a specific error message or function name, try to locate it.
    If the issue is about a feature, try to find the code implementing that feature.
3.  **Propose Solutions/Next Steps:** Based on your understanding of the issue and the codebase, suggest 1-3 potential solutions or concrete next steps for debugging or fixing the issue. Be specific. If you need more information, state what information is needed.

**Output Format:**
Please provide your response as a JSON object with the following keys:
- "issue_summary": Your summary of the issue.
- "code_analysis_summary": A brief summary of your codebase exploration and findings (if any).
- "proposed_solutions": A list of strings, where each string is a distinct proposed solution or next step.

Example for `proposed_solutions`:
["Check the `user_authentication` function in `auth.py` for null pointer exceptions.", "Add more logging around the payment processing module.", "Verify the API endpoint `/api/v1/items` is correctly configured in `routes.py`."]

Begin your analysis.
"""
    # Shorten the prompt for this debug log
    print(f"container_agent.py: Prompt prepared (first 100 chars): {prompt[:100].replace('\n', ' ')}", file=sys.stderr)
    sys.stderr.flush()

    llm_output = {} # Initialize with a default error structure
    logger.info("Sending prompt to LLM agent...")
    try:
        print("container_agent.py: Awaiting agent.run(prompt)...", file=sys.stderr)
        sys.stderr.flush()
        llm_response_str = await agent.run(prompt)
        logger.info("LLM agent run completed.")
        print("container_agent.py: LLM agent run completed.", file=sys.stderr)
        sys.stderr.flush()
        # Ensure any print() calls here also go to sys.stdout for the > redirection in Dockerfile
        # Fallback and error JSONs are printed to sys.stdout by default via print()
        try:
            llm_output = json.loads(llm_response_str)
            if not isinstance(llm_output, dict) or \
               not all(k in llm_output for k in ["issue_summary", "code_analysis_summary", "proposed_solutions"]):
                logger.warning(f"LLM output was valid JSON but not in the expected format. Output: {llm_response_str}")
                llm_output = {
                    "issue_summary": llm_output.get("issue_summary", "Summary not provided by LLM."),
                    "code_analysis_summary": llm_output.get("code_analysis_summary", "Code analysis not provided by LLM."),
                    "proposed_solutions": llm_output.get("proposed_solutions", [f"Raw LLM response: {llm_response_str}"])
                }
        except json.JSONDecodeError:
            logger.warning(f"LLM output was not valid JSON. Raw output: {llm_response_str}")
            llm_output = {
                "issue_summary": "LLM output was not valid JSON.",
                "code_analysis_summary": "Could not parse LLM analysis of the code.",
                "proposed_solutions": [f"Raw LLM response: {llm_response_str}"]
            }
            
    except Exception as e:
        logger.error(f"Error during LLM agent execution: {str(e)}")
        print(f"container_agent.py: Error during LLM agent execution: {str(e)}", file=sys.stderr)
        sys.stderr.flush()
        # This print goes to STDOUT, which is redirected to analysis_output.json
        # So if this exception occurs, analysis_output.json will contain this error JSON
        llm_output = {
            "error": f"LLM agent execution failed: {str(e)}",
            "issue_summary": "Error: Analysis by LLM failed.",
            "proposed_solutions": []
        }

    print(json.dumps(llm_output, indent=2)) # This is the main stdout for analysis_output.json
    logger.info("Container agent finished and printed output to stdout.")
    print("container_agent.py: main() finished, printed final JSON to stdout.", file=sys.stderr)
    sys.stderr.flush()

if __name__ == "__main__":
    print("container_agent.py: __main__ block reached.", file=sys.stderr)
    sys.stderr.flush()
    import asyncio
    try:
        asyncio.run(main())
        print("container_agent.py: asyncio.run(main()) completed.", file=sys.stderr)
        sys.stderr.flush()
    except Exception as e_async:
        print(f"container_agent.py: Exception in asyncio.run(main()): {str(e_async)}", file=sys.stderr)
        sys.stderr.flush()
        # Ensure some error output makes it to stdout if the script crashes here
        # This helps diagnose if the script fails before even producing the primary JSON
        print(json.dumps({
            "error": f"Script crashed in main async execution: {str(e_async)}",
            "issue_summary": "Critical script failure.",
            "proposed_solutions": []
        })) 