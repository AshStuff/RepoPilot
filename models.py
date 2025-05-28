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
    installation_id = StringField() # Store GitHub App installation ID for this repo
    connected_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow, null=True) # Allow null for old docs
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'github_repo_id': self.github_repo_id,
            'name': self.name,
            'description': self.description,
            'is_private': self.is_private,
            'installation_id': self.installation_id,
            'connected_at': self.connected_at.isoformat() if self.connected_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
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
    updated_at = DateTimeField(default=datetime.utcnow, null=True) # Allow null for old docs
    token = EmbeddedDocumentField(Token)
    github_access_token = StringField()  # Add this field for GitHub OAuth token

    def to_dict(self):
        return {
            'id': str(self.id),
            'github_id': self.github_id,
            'login': self.login,
            'name': self.name,
            'avatar_url': self.avatar_url,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
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
    git_changes = DictField()  # Store git diff information from container analysis
    aider_processing_time_seconds = FloatField() # Store Aider processing time
    pr_url = StringField() # URL of the Pull Request created by the agent
    
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
            'git_changes': self.git_changes,
            'aider_processing_time_seconds': self.aider_processing_time_seconds,
            'pr_url': self.pr_url,
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
    
    def clean(self):
        """Custom validation to ensure required fields are present"""
        errors = {}
        
        if not self.repository:
            errors['repository'] = 'Repository is required'
        
        if not self.issue_number:
            errors['issue_number'] = 'Issue number is required'
            
        if not self.issue_id:
            errors['issue_id'] = 'Issue ID is required'
        
        if errors:
            from mongoengine.errors import ValidationError
            raise ValidationError('Missing required fields', errors=errors)
    
    def save(self, *args, **kwargs):
        """Override save to ensure validation runs"""
        self.clean()  # Run custom validation
        return super().save(*args, **kwargs)

class CiPrAnalysis(Document):
    repository = ReferenceField('ConnectedRepository', required=True)
    pr_number = IntField(required=True)
    pr_id = StringField(required=True) # GitHub PR ID
    pr_title = StringField()
    pr_html_url = StringField()
    commit_sha = StringField() # SHA of the commit with the CI failure

    ci_status = StringField(choices=['failed', 'error', 'pending_fix', 'fixed', 'resolved_by_user'], default='failed')
    ci_failure_context = StringField() # e.g., "ci/circleci: build"
    ci_failure_description = StringField()
    ci_target_url = StringField() # Link to the CI job page
    ci_failure_details_list = ListField(StringField()) # Stores a list of specific failure messages

    # Fields for potential automated fix attempts (similar to IssueAnalysis)
    analysis_status = StringField(choices=['not_started', 'in_progress', 'completed', 'failed'], default='not_started')
    analysis_logs = ListField(DictField()) # Logs for fix attempts
    fix_pr_url = StringField() # URL of a PR created by RepoPilot to fix this CI failure
    error_message = StringField() # If RepoPilot fails to fix

    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    meta = {
        'collection': 'ci_pr_analyses',
        'indexes': [
            {'fields': ['repository', 'pr_number'], 'unique': True},
            'ci_status',
            'analysis_status',
            'created_at'
        ]
    }

    def to_dict(self):
        return {
            'id': str(self.id),
            'repository': self.repository.to_dict() if self.repository else None,
            'pr_number': self.pr_number,
            'pr_id': self.pr_id,
            'pr_title': self.pr_title,
            'pr_html_url': self.pr_html_url,
            'commit_sha': self.commit_sha,
            'ci_status': self.ci_status,
            'ci_failure_context': self.ci_failure_context,
            'ci_failure_description': self.ci_failure_description,
            'ci_target_url': self.ci_target_url,
            'ci_failure_details_list': self.ci_failure_details_list,
            'analysis_status': self.analysis_status,
            'analysis_logs': self.analysis_logs,
            'fix_pr_url': self.fix_pr_url,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

    def add_log(self, message, type="info"):
        timestamp = datetime.utcnow().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'message': message,
            'type': type
        }
        if not hasattr(self, 'analysis_logs') or self.analysis_logs is None:
            self.analysis_logs = []
        self.analysis_logs.append(log_entry)
        self.updated_at = datetime.utcnow()
        # self.save() # Avoid double save if called within another save operation

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)

# Initialize MongoDB connection
def init_app(app):
    connect(host=app.config['MONGODB_SETTINGS']['host']) 