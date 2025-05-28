#!/usr/bin/env python3
"""
Script to find and fix corrupted IssueAnalysis records in the database.
This addresses the ValidationError where records are missing required fields.
"""

import os
import sys
from datetime import datetime

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import IssueAnalysis, ConnectedRepository
from mongoengine import connect
from mongoengine.errors import ValidationError

def main():
    # Connect to MongoDB (using the same connection as the app)
    # You may need to adjust this based on your MongoDB configuration
    try:
        connect('repopilot')
        print("✓ Connected to MongoDB")
    except Exception as e:
        print(f"✗ Failed to connect to MongoDB: {e}")
        return
    
    print("🔍 Searching for corrupted IssueAnalysis records...")
    
    # Find all IssueAnalysis records
    all_analyses = IssueAnalysis.objects.all()
    total_count = all_analyses.count()
    print(f"📊 Found {total_count} total analysis records")
    
    corrupted_count = 0
    fixed_count = 0
    unfixable_count = 0
    
    for analysis in all_analyses:
        try:
            # Try to validate the record by calling save() in validation-only mode
            analysis.validate()
        except ValidationError as ve:
            corrupted_count += 1
            print(f"\n🔴 Found corrupted record: {analysis.id}")
            print(f"   Repository: {analysis.repository}")
            print(f"   Issue Number: {analysis.issue_number}")
            print(f"   Issue ID: {analysis.issue_id}")
            print(f"   Validation Error: {ve}")
            
            # Attempt to fix the record
            fixed = False
            
            # Try to find the correct repository if missing
            if not analysis.repository and hasattr(analysis, 'logs') and analysis.logs:
                # Look through logs for repository information
                for log in analysis.logs:
                    if 'repository' in log.get('message', '').lower():
                        print(f"   📝 Found repository info in logs: {log.get('message', '')}")
                        break
            
            # If we can't automatically fix it, check if we can delete it safely
            if not analysis.repository or not analysis.issue_number or not analysis.issue_id:
                # Check if this is a recent record or has useful data
                has_useful_data = (
                    analysis.logs and len(analysis.logs) > 2 or
                    analysis.analysis_results or
                    analysis.final_output or
                    analysis.analysis_status in ['completed', 'in_progress']
                )
                
                if has_useful_data:
                    print(f"   ⚠️  Record has useful data but can't be auto-fixed")
                    print(f"      Status: {analysis.analysis_status}")
                    print(f"      Logs: {len(analysis.logs) if analysis.logs else 0}")
                    print(f"      Created: {analysis.created_at}")
                    unfixable_count += 1
                else:
                    print(f"   🗑️  Deleting corrupted record with no useful data")
                    try:
                        analysis.delete()
                        fixed_count += 1
                        print(f"   ✓ Deleted successfully")
                    except Exception as del_e:
                        print(f"   ✗ Failed to delete: {del_e}")
                        unfixable_count += 1
            else:
                unfixable_count += 1
        except Exception as other_error:
            print(f"🔴 Unexpected error checking record {analysis.id}: {other_error}")
    
    print(f"\n📈 Summary:")
    print(f"   Total records: {total_count}")
    print(f"   Corrupted records found: {corrupted_count}")
    print(f"   Records fixed/deleted: {fixed_count}")
    print(f"   Records requiring manual intervention: {unfixable_count}")
    
    if unfixable_count > 0:
        print(f"\n⚠️  {unfixable_count} records require manual intervention.")
        print("   Consider reviewing these records manually or contacting an administrator.")

if __name__ == "__main__":
    main() 