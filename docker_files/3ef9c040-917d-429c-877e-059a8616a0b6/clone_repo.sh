#!/bin/bash
# Print each command for debugging
set -ex

WORKSPACE_DIR="/workspace"
REPO_URL="https://github.com/AshStuff/JunkRepo.git"
BRANCH="v1.1"
REPO_NAME="JunkRepo"
ACCESS_TOKEN=""

echo "====== DEBUG INFO ======"
echo "Repository URL: $REPO_URL"
echo "Branch/Tag: $BRANCH"
echo "Repository name: $REPO_NAME"
echo "Workspace directory: $WORKSPACE_DIR"
echo "Current directory: $(pwd)"
echo "=======================
"

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
