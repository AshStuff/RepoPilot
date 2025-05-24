# MongoDB Cache Clearing for RepoPilot

This document explains how to clear the MongoDB cache and existing analyses in RepoPilot.

## Automatic Cache Clearing

When you click the "Restart" button in the Issue Analysis Terminal, the system will:

1. Clear the existing analysis from MongoDB using the `clear_issue_analysis.py` script
2. Delete any Docker containers and images associated with the analysis
3. Clear all logs from the database
4. Start a fresh analysis

The restart process has been enhanced to ensure complete cache clearing, preventing any stale data from affecting new analyses.

## Manual Cache Clearing

For manual cache clearing, you can use the provided scripts:

### Using the Shell Script

The `clear_cache.sh` script provides a simple interface to clear the MongoDB cache:

```bash
# Clear all analyses and cache
./clear_cache.sh

# Alternative way to clear all analyses and cache
./clear_cache.sh all

# Clear a specific issue analysis
./clear_cache.sh issue <repo_name> <issue_number>

# Example:
./clear_cache.sh issue octocat/Hello-World 42
```

### Using the Python Scripts Directly

You can also use the Python scripts directly:

#### For all analyses:
```bash
# Clear all analyses and cache
python3 clear_mongodb_cache.py
```

#### For a specific issue:
```bash
# Clear a specific issue analysis (general purpose)
python3 clear_mongodb_cache.py <repo_name> <issue_number>

# Clear a specific issue analysis (optimized for UI integration)
python3 clear_issue_analysis.py <repo_name> <issue_number>

# Example:
python3 clear_issue_analysis.py octocat/Hello-World 42
```

## Troubleshooting

If you encounter issues with the MongoDB cache:

1. Stop the RepoPilot application
2. Run `./clear_cache.sh` to clear all analyses
3. Restart the application

This will ensure a clean state for the application.

## Notes

- Clearing the cache will remove all analysis data, including logs and results
- The "Restart" button in the UI will automatically handle Docker resource cleanup
- The specialized `clear_issue_analysis.py` script is optimized for use with the UI 