# edit_with_qwen.py
from pathlib import Path
from aider.coders import Coder
from aider.models import Model
from aider.io import InputOutput

# --- configuration ---------------------------------------------------------
REPO_ROOT = Path("./")         # the code-base you want to modify
# Collect all python files in the REPO_ROOT recursively
# Ensure they are strings, as aider usually expects file paths as strings
TARGET_FILES = [str(p) for p in REPO_ROOT.glob("./**/*.py") if p.is_file() and str(p)[0]!='.' and "test" not in str(p)]
import pdb; pdb.set_trace()
MAIN_MODEL = Model("ollama/qwen2.5-coder:32b",
    editor_edit_format="editor-diff",)

io = InputOutput(yes=True)          # auto-approve tool calls (skip Y/N prompts)
coder = Coder.create(
    edit_format="whole",
    main_model=MAIN_MODEL,
    fnames=TARGET_FILES, # Pass explicit file list
    io=io,
    use_git=False,
    # Optional safety rails
    dry_run=False,   
                   # True = preview patch, False = write & commit
)


with  open("./issue.txt", "r") as f:
	prompt = f.read()
print(prompt)
# You can chain more edits:
coder.run(f"The repo throws an error and the user has raised an issue. Please fix the error. You can run the code and see the error. You must change the codebase locally to fix the error. Issue: {prompt}")
