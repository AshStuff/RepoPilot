#!/bin/bash

# Script to clear MongoDB cache and analyses

# Set colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}RepoPilot MongoDB Cache Cleaner${NC}"
echo "-------------------------------"

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required but not found.${NC}"
    exit 1
fi

# Function to clear all analyses
clear_all() {
    echo -e "${YELLOW}Clearing all analyses and MongoDB cache...${NC}"
    python3 clear_mongodb_cache.py
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Successfully cleared all analyses and cache.${NC}"
    else
        echo -e "${RED}Failed to clear analyses and cache.${NC}"
        exit 1
    fi
}

# Function to clear specific issue analysis
clear_issue() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo -e "${RED}Error: Repository name and issue number are required.${NC}"
        echo "Usage: ./clear_cache.sh issue <repo_name> <issue_number>"
        exit 1
    fi
    
    echo -e "${YELLOW}Clearing analysis for issue #$2 in $1...${NC}"
    python3 clear_mongodb_cache.py "$1" "$2"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Operation completed.${NC}"
    else
        echo -e "${RED}Failed to clear analysis.${NC}"
        exit 1
    fi
}

# Parse command line arguments
if [ $# -eq 0 ]; then
    # No arguments, clear all
    clear_all
elif [ "$1" = "all" ]; then
    # Explicit "all" argument
    clear_all
elif [ "$1" = "issue" ]; then
    # Clear specific issue
    clear_issue "$2" "$3"
else
    echo -e "${RED}Invalid command.${NC}"
    echo "Usage:"
    echo "  ./clear_cache.sh               # Clear all analyses and cache"
    echo "  ./clear_cache.sh all           # Clear all analyses and cache"
    echo "  ./clear_cache.sh issue <repo_name> <issue_number>  # Clear specific issue"
    exit 1
fi

echo -e "${GREEN}Done.${NC}" 