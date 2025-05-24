from mongoengine import connect
from models import IssueAnalysis  # Assuming your models are in models.py
import os
from dotenv import load_dotenv
import argparse # Import argparse

def clear_all_issue_analyses():
    """
    Connects to MongoDB and deletes all IssueAnalysis documents.
    """
    load_dotenv()

    mongodb_uri = os.getenv("MONGODB_URI")
    if not mongodb_uri:
        print("Error: MONGODB_URI not found in .env file.")
        return

    try:
        print(f"Connecting to MongoDB at {mongodb_uri}...")
        connect(host=mongodb_uri)
        print("Successfully connected to MongoDB.")

        print("Fetching all IssueAnalysis records...")
        analyses = IssueAnalysis.objects()
        count = analyses.count()

        if count == 0:
            print("No IssueAnalysis records found to delete.")
            return

        print(f"Found {count} IssueAnalysis record(s). Deleting them now...")
        
        # Iterate and delete. analyses.delete() should work but to be safe:
        for analysis in analyses:
            print(f"Deleting analysis ID: {analysis.id}, Issue: {analysis.issue_number}, Repo: {analysis.repository.name if analysis.repository else 'N/A'}")
            analysis.delete()
        
        # Verify
        remaining_count = IssueAnalysis.objects.count()
        if remaining_count == 0:
            print(f"Successfully deleted {count} IssueAnalysis record(s).")
        else:
            print(f"Warning: {remaining_count} record(s) still remain after deletion attempt.")

    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Add argument parsing
    parser = argparse.ArgumentParser(description="Clear all IssueAnalysis records from MongoDB.")
    parser.add_argument("--yes", action="store_true", help="Automatically confirm deletion without prompting.")
    args = parser.parse_args()

    if args.yes:
        clear_all_issue_analyses()
    else:
        confirmation = input("Are you sure you want to delete ALL IssueAnalysis records? This cannot be undone. (yes/no): ")
        if confirmation.lower() == 'yes':
            clear_all_issue_analyses()
        else:
            print("Operation cancelled.") 