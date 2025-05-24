#!/usr/bin/env python3
import os
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get MongoDB URI from environment or use default
mongodb_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/repopilot')

print(f"Connecting to MongoDB at {mongodb_uri}...")

try:
    # Connect to MongoDB
    client = MongoClient(mongodb_uri)
    db = client.get_database()
    
    # Get the users collection
    users_collection = db.users
    
    # List existing indexes
    print("Existing indexes:")
    indexes = list(users_collection.list_indexes())
    for idx in indexes:
        print(f"  {idx['name']}: {idx['key']}")
    
    # Drop the conflicting index if it exists
    if any(idx['name'] == 'token.token_id_1' for idx in indexes):
        print("Dropping conflicting index 'token.token_id_1'...")
        users_collection.drop_index('token.token_id_1')
        print("Index dropped successfully!")
    else:
        print("No conflicting index found!")
    
    # Verify the indexes after dropping
    print("\nIndexes after update:")
    for idx in users_collection.list_indexes():
        print(f"  {idx['name']}: {idx['key']}")
    
    print("\nScript completed successfully!")
    
except Exception as e:
    print(f"Error: {str(e)}") 