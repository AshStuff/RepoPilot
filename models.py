from mongoengine import *
from datetime import datetime
import json

class Token(EmbeddedDocument):
    token_id = StringField(required=True, unique=True)
    token_hash = StringField(required=True)
    name = StringField(required=True)
    created_at = DateTimeField(default=datetime.utcnow)
    last_used = DateTimeField()

    def to_dict(self):
        return {
            'id': self.token_id,
            'name': self.name,
            'token_hash': self.token_hash,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None
        }

class ConnectedRepository(Document):
    meta = {
        'collection': 'connected_repositories',
        'indexes': [
            ('user', 'github_repo_id'),  # Compound index for user and repo
        ]
    }
    
    user = ReferenceField('User', required=True)
    github_repo_id = StringField(required=True)
    name = StringField(required=True)  # Full repository name (e.g., "owner/repo")
    description = StringField()
    is_private = BooleanField(default=False)
    connected_at = DateTimeField(default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'github_repo_id': self.github_repo_id,
            'name': self.name,
            'description': self.description,
            'is_private': self.is_private,
            'connected_at': self.connected_at.isoformat() if self.connected_at else None
        }

class User(Document):
    meta = {
        'collection': 'users',
        'indexes': [
            'github_id',  # Create index on github_id
            # Modified to ensure we don't get duplicate key errors for null token IDs
            {'fields': ['token.token_id'], 
             'unique': True, 
             'sparse': True, 
             'partialFilterExpression': {'token.token_id': {'$exists': True}},
             'name': 'token_id_partial_index'  # Custom name to avoid conflicts
            }
        ]
    }
    
    github_id = StringField(required=True, unique=True)
    login = StringField(required=True)
    name = StringField()
    avatar_url = StringField()
    created_at = DateTimeField(default=datetime.utcnow)
    token = EmbeddedDocumentField(Token)
    github_access_token = StringField()  # Add this field for GitHub OAuth token

    def to_dict(self):
        return {
            'id': str(self.id),
            'github_id': self.github_id,
            'login': self.login,
            'name': self.name,
            'avatar_url': self.avatar_url,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        
    def get_connected_repositories(self):
        """Get all repositories connected to this user"""
        return ConnectedRepository.objects(user=self)

class IssueAnalysis(Document):
    repository = ReferenceField('ConnectedRepository', required=True)
    issue_number = IntField(required=True)
    issue_id = StringField(required=True)
    issue_title = StringField()
    issue_body = StringField()
    analysis_status = StringField(choices=['pending', 'in_progress', 'completed', 'failed', 'needs_info', 
                                         'llm_processing', 'processing_output', 'llm_output_error', 'llm_failed', 'analysis_complete'], default='pending')
    analysis_results = DictField()  # Store the complete analysis results (can be general LLM output)
    final_output = StringField() # For storing the primary textual output of the analysis for display
    
    # New fields for structured LLM output
    issue_summary = StringField()
    code_analysis_summary = StringField()
    proposed_solutions = ListField(StringField())
    raw_llm_output = StringField() # For debugging if JSON parsing fails
    container_id = StringField() # Store the full Docker container ID

    logs = ListField(DictField())  # Store log entries for real-time streaming
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    error_message = StringField()
    
    meta = {
        'indexes': [
            {'fields': ['repository', 'issue_number'], 'unique': True},
            'analysis_status',
            'created_at'
        ]
    }
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'repository': self.repository.to_dict() if self.repository else None,
            'issue_number': self.issue_number,
            'issue_id': self.issue_id,
            'issue_title': self.issue_title,
            'issue_body': self.issue_body,
            'analysis_status': self.analysis_status,
            'analysis_results': self.analysis_results,
            'final_output': self.final_output,
            'issue_summary': self.issue_summary,
            'code_analysis_summary': self.code_analysis_summary,
            'proposed_solutions': self.proposed_solutions,
            'raw_llm_output': self.raw_llm_output, # For debugging
            'container_id': self.container_id,
            'logs': self.logs,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'error_message': self.error_message
        }
        
    def add_log(self, message, type="info"):
        """Add a log entry to the analysis logs"""
        timestamp = datetime.utcnow().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'message': message,
            'type': type
        }
        
        # Add to logs list
        if not hasattr(self, 'logs') or self.logs is None:
            self.logs = []
        
        self.logs.append(log_entry)
        self.updated_at = datetime.utcnow()
        self.save()
        
        return log_entry

# Initialize MongoDB connection
def init_app(app):
    connect(host=app.config['MONGODB_SETTINGS']['host']) 