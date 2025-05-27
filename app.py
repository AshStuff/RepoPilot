from flask import Flask, render_template, redirect, url_for, session, request, jsonify, make_response, Response, stream_with_context, flash
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os
import requests
import secrets
from werkzeug.utils import secure_filename
import uuid
from flask_session import Session, FileSystemSessionInterface
import tempfile
from datetime import timedelta, datetime
import hashlib
import base64
from models import User, Token, init_app, ConnectedRepository, IssueAnalysis
from mongoengine.errors import NotUniqueError
from bson import ObjectId
import json
import traceback
from github import Github, GithubIntegration
import jwt
import time
import pytz
import markdown
import bleach
from markdown.extensions import fenced_code
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.tables import TableExtension
from agents.issue_analyzer import IssueAnalyzer
from agents.utils import _get_default_requirements
import subprocess
import threading
import asyncio
import hmac
import random

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

load_dotenv()

# Debugging: Check if .env is found and GITHUB_WEBHOOK_SECRET is loaded
print(f"DEBUG: Checking for .env file. Found: {os.path.exists('.env')}")
retrieved_secret = os.getenv('GITHUB_WEBHOOK_SECRET')
print(f"DEBUG: GITHUB_WEBHOOK_SECRET from os.getenv after load_dotenv: '{retrieved_secret if retrieved_secret else 'NOT FOUND - is it in .env?'}'")
# End Debugging

app = Flask(__name__)
app.json_encoder = CustomJSONEncoder
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))

# MongoDB configuration
app.config['MONGODB_SETTINGS'] = {
    'host': os.getenv('MONGODB_URI', 'mongodb://localhost:27017/repopilot')
}
init_app(app)

# Configure server name and scheme
# app.config['SERVER_NAME'] = os.getenv('SERVER_NAME', 'localhost:5001')  # Removing this line as it causes issues
app.config['PREFERRED_URL_SCHEME'] = os.getenv('PREFERRED_URL_SCHEME', 'http')

# Create session directory if it doesn't exist
session_dir = os.path.join(tempfile.gettempdir(), 'flask_session')
os.makedirs(session_dir, exist_ok=True)

# Basic session configuration
app.config.update(
    SESSION_TYPE='filesystem',
    SESSION_FILE_DIR=session_dir,
    SESSION_PERMANENT=True,  # Make sessions permanent so they don't expire too quickly
    PERMANENT_SESSION_LIFETIME=timedelta(days=1),  # Session lasts for 1 day
    SESSION_USE_SIGNER=True,  # Enable session signing for security
    SESSION_FILE_THRESHOLD=500,
    SESSION_KEY_PREFIX='repopilot_'
)

# Custom session interface
class CustomSessionInterface(FileSystemSessionInterface):
    def save_session(self, app, session, response):
        # Convert token to string if it's bytes
        if 'user' in session and 'access_token' in session['user']:
            token = session['user']['access_token']
            if isinstance(token, bytes):
                session['user']['access_token'] = token.decode('utf-8')
                
        # Make sure the session is properly saved
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        
        # Force the session to be saved
        session.modified = True
        
        return super().save_session(app, session, response)
        
# Initialize session with custom interface
Session(app)
app.session_interface = CustomSessionInterface(
    session_dir,
    key_prefix='repopilot_',
    threshold=app.config['SESSION_FILE_THRESHOLD'],
    mode=0o600
)

app.config['UPLOAD_FOLDER'] = 'static/uploads/avatars'

# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# OAuth setup
oauth = OAuth(app)

# Check if GitHub credentials are properly set
github_client_id = os.getenv('GITHUB_CLIENT_ID')
github_client_secret = os.getenv('GITHUB_CLIENT_SECRET')

if not github_client_id or not github_client_secret:
    logger.error("GitHub OAuth credentials are missing! Check your .env file")
    
# Validate that the credentials look correct
if github_client_id and len(github_client_id) < 10:
    logger.warning(f"GitHub client ID appears to be too short: {github_client_id}")
    
if github_client_secret and len(github_client_secret) < 20:
    logger.warning(f"GitHub client secret appears to be too short: {github_client_secret[:5]}...")

logger.info(f"Configuring GitHub OAuth with client ID: {github_client_id[:5] if github_client_id else 'MISSING'}... and callback URL: {os.getenv('GITHUB_CALLBACK_URL', 'http://localhost:5001/callback/github')}")

github = oauth.register(
    name='github',
    client_id=github_client_id,
    client_secret=github_client_secret,
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={
        'scope': 'user:email repo',
        'token_endpoint_auth_method': 'client_secret_post'
    }
)

# Define the callback URL explicitly
GITHUB_CALLBACK_URL = os.getenv('GITHUB_CALLBACK_URL', 'http://localhost:5001/callback/github')

# GitHub App credentials
GITHUB_APP_ID = os.getenv('GITHUB_APP_ID')
GITHUB_APP_PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')
GITHUB_APP_WEBHOOK_SECRET = os.getenv('GITHUB_APP_WEBHOOK_SECRET')

def create_jwt():
    """Create a JWT for GitHub App authentication"""
    now = int(time.time())
    payload = {
        'iat': now,
        'exp': now + (10 * 60),  # JWT valid for 10 minutes
        'iss': GITHUB_APP_ID
    }
    return jwt.encode(payload, GITHUB_APP_PRIVATE_KEY, algorithm='RS256')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def github_api_call(endpoint, token, method='get', data=None, params=None, max_retries=5, initial_retry_delay=2):
    """
    Make a GitHub API call with advanced retry logic for rate limits
    
    Args:
        endpoint: API endpoint (without the base URL)
        token: Access token for authentication
        method: HTTP method ('get' or 'post')
        data: Data for POST requests
        params: Query parameters for GET requests
        max_retries: Maximum number of retries
        initial_retry_delay: Initial delay between retries (increases exponentially)
        
    Returns:
        Response object or None if all retries fail
    """
    for retry in range(max_retries):
        try:
            # Make the API call
            if method.lower() == 'get':
                resp = github.get(endpoint, token={'access_token': token}, params=params)
            elif method.lower() == 'post':
                resp = github.post(endpoint, token={'access_token': token}, json=data, params=params)
            else:
                logger.error(f"Unsupported method: {method}")
                return None
                
            # Check for rate limit errors (403 status code and rate limit message)
            if resp.status_code == 403:
                rate_limited = False
                reset_time = None
                
                # Check if this is a rate limit response
                if 'rate limit exceeded' in resp.text.lower():
                    rate_limited = True
                
                # Try to parse rate limit headers
                if 'X-RateLimit-Remaining' in resp.headers:
                    remaining = int(resp.headers.get('X-RateLimit-Remaining', 0))
                    if remaining == 0:
                        rate_limited = True
                    
                    # Get reset time from headers if available
                    if 'X-RateLimit-Reset' in resp.headers:
                        reset_timestamp = int(resp.headers.get('X-RateLimit-Reset', 0))
                        reset_time = datetime.fromtimestamp(reset_timestamp)
                        now = datetime.now()
                        wait_seconds = max((reset_time - now).total_seconds(), 0)
                        
                        if wait_seconds > 0 and wait_seconds < 300:  # Cap at 5 minutes
                            logger.warning(f"GitHub API rate limit will reset at {reset_time.strftime('%H:%M:%S')}, waiting {wait_seconds:.0f} seconds")
                            time.sleep(wait_seconds + 1)  # Add 1 second buffer
                            continue
                
                if rate_limited:
                    # Use exponential backoff with jitter
                    wait_time = initial_retry_delay * (2 ** retry) + random.uniform(0, 1)
                    wait_time = min(wait_time, 60)  # Cap at 60 seconds
                    logger.warning(f"GitHub API rate limit exceeded. Waiting {wait_time:.1f}s before retry {retry+1}/{max_retries}")
                    time.sleep(wait_time)
                    continue
                    
            # Return the response for successful status codes
            if 200 <= resp.status_code < 300:
                return resp
                
            # For other errors, log and retry with backoff
            if retry < max_retries - 1:
                wait_time = initial_retry_delay * (2 ** retry)
                logger.warning(f"GitHub API returned status {resp.status_code}. Retrying in {wait_time}s (attempt {retry+1}/{max_retries})")
                time.sleep(wait_time)
            else:
                logger.error(f"GitHub API error: Status {resp.status_code} - {resp.text[:200]}")
                return resp  # Return the error response on the last attempt
                
        except Exception as e:
            logger.error(f"GitHub API error: {str(e)}")
            if retry < max_retries - 1:
                wait_time = initial_retry_delay * (2 ** retry)
                logger.warning(f"Retrying in {wait_time}s (attempt {retry+1}/{max_retries})")
                time.sleep(wait_time)
            else:
                logger.error("Maximum retries reached. Giving up.")
                return None
    
    return None

@app.route('/')
@app.route('/login')
def login():
    logger.debug("Login route accessed")
    logger.debug(f"Session contents: {list(session.keys())}")
    logger.debug(f"Cookies: {request.cookies}")
    
    if 'user' in session:
        logger.debug(f"User found in session: {session['user'].get('login')}")
        return redirect(url_for('dashboard'))
    
    # Clear any existing session data but don't clear cookie yet
    session.clear()
    session.modified = True
    
    # Initialize a new session 
    session['initialized'] = True
    session.modified = True
    
    # Create response with proper cookie settings
    response = make_response(render_template('login.html'))
    
    # Set Cache-Control headers to prevent caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    # Make sure the session cookie is sent
    app.session_interface.save_session(app, session, response)
    
    return response

@app.route('/login/github')
def github_login():
    # Generate and store state parameter in session
    session['oauth_state'] = secrets.token_hex(16)
    session.modified = True
    
    # Force session to be saved
    app.session_interface.save_session(app, session, make_response(''))
    
    # Use the explicit callback URL
    logger.info(f"=== GitHub OAuth Configuration ===")
    logger.info(f"Using callback URL: {GITHUB_CALLBACK_URL}")
    logger.info(f"State parameter: {session.get('oauth_state', 'NOT SET')}")
    logger.info(f"================================")
    
    return github.authorize_redirect(
        redirect_uri=GITHUB_CALLBACK_URL,
        state=session['oauth_state']
    )

@app.route('/callback/github')
def github_callback():
    try:
        logger.debug("GitHub callback received")
        logger.debug(f"Request URL: {request.url}")
        logger.debug(f"Request args: {request.args}")
        logger.debug(f"Request headers: {dict(request.headers)}")
        logger.debug(f"Session contents: {list(session.keys())}")
        
        # Get state from request
        request_state = request.args.get('state')
        
        # Check if we need to verify state
        if 'oauth_state' not in session:
            logger.error("No oauth_state in session")
            logger.warning("Proceeding without state verification")
            # Force the authorization to proceed despite missing state
            token_resp = github.fetch_access_token(
                authorization_response=request.url,
                state=request_state
            )
            if 'access_token' in token_resp:
                token = token_resp['access_token']
            else:
                raise ValueError("Failed to obtain access token")
        else:
            # Normal state verification flow
            if not request_state or request_state != session['oauth_state']:
                logger.error(f"State mismatch: {request_state} != {session.get('oauth_state')}")
                raise ValueError("Invalid OAuth state")
            
            # Clear oauth state after verification
            session.pop('oauth_state', None)
            
            # Get the token using standard approach
            token = github.authorize_access_token()
        
        logger.debug("Access token obtained")
        
        # Convert token to string if needed
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        elif hasattr(token, 'token'):
            token = token.token
        elif not isinstance(token, (str, dict)):
            token = str(token)
            
        if isinstance(token, dict):
            token = token.get('access_token', '')
        
        # Get user info from GitHub with enhanced retry logic
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                logger.debug(f"Making GitHub API request for user info with token: {token[:5]}... (attempt {attempt+1}/{max_attempts})")
                
                # Use the retry-enabled API call function with longer initial delay for user info
                resp = github_api_call('user', token, initial_retry_delay=3)
                
                # Check if the response is successful
                if not resp or resp.status_code != 200:
                    error_text = resp.text if resp else "No response"
                    logger.error(f"GitHub API error: {resp.status_code if resp else 'No response'} - {error_text}")
                    
                    if attempt < max_attempts - 1:
                        wait_time = 3 * (2 ** attempt)  # Exponential backoff
                        logger.warning(f"Retrying user info in {wait_time}s (attempt {attempt+1}/{max_attempts})")
                        time.sleep(wait_time)
                        continue
                    else:
                        flash("Failed to connect with GitHub. Please try again.", "error")
                        return redirect(url_for('login'))
                
                # Successfully got user info
                user_info = resp.json()
                logger.debug(f"GitHub user info received: {user_info}")
                break  # Exit the retry loop on success
                
            except Exception as e:
                logger.error(f"Error getting user info from GitHub: {str(e)}")
                logger.error(traceback.format_exc())
                
                if attempt < max_attempts - 1:
                    wait_time = 3 * (2 ** attempt)
                    logger.warning(f"Retrying after error in {wait_time}s (attempt {attempt+1}/{max_attempts})")
                    time.sleep(wait_time)
                else:
                    flash("Failed to retrieve user information from GitHub. Please try again.", "error")
                    return redirect(url_for('login'))
        else:
            # This executes if the for loop completes without a break (all attempts failed)
            flash("GitHub is currently unavailable. Please try again later.", "error")
            return redirect(url_for('login'))
        
        # Log the user info to debug
        logger.debug(f"GitHub user info: {user_info}")
        
        # Check if the required fields are present
        if 'id' not in user_info:
            logger.error(f"Missing 'id' in GitHub user info: {user_info}")
            flash("Invalid user information received from GitHub. Please try again.", "error")
            return redirect(url_for('login'))
            
        if 'login' not in user_info:
            logger.error(f"Missing 'login' in GitHub user info: {user_info}")
            user_info['login'] = f"user_{user_info.get('id', 'unknown')}"
            
        if 'avatar_url' not in user_info:
            logger.error(f"Missing 'avatar_url' in GitHub user info: {user_info}")
            user_info['avatar_url'] = '/static/images/default-avatar.png'
        
        # Create a default avatar image path for safety
        if not user_info['avatar_url'] or user_info['avatar_url'].strip() == '':
            user_info['avatar_url'] = '/static/images/default-avatar.png'
        
        # Find or create user in database
        user = User.objects(github_id=str(user_info['id'])).first()
        if not user:
            user = User(
                github_id=str(user_info['id']),
                login=user_info['login'],
                name=user_info.get('name'),
                avatar_url=user_info['avatar_url']
            )
        
        # Store the GitHub access token in the user model
        user.github_access_token = token
        user.save()
        
        # Update session with user info
        session['user'] = {
            'id': str(user.id),
            'github_id': user.github_id,
            'login': user.login,
            'name': user.name,
            'avatar_url': user.avatar_url,
            'platform': 'github',
            'access_token': token
        }
        
        # Get user's repositories with enhanced fallback behavior
        try:
            logger.debug("Fetching user repositories from GitHub...")
            
            # Use the retry-enabled API call function with increased retry delay
            repos_resp = github_api_call('user/repos', token, initial_retry_delay=3)
            
            # Check for API errors
            if not repos_resp or repos_resp.status_code != 200:
                logger.error(f"GitHub API error fetching repositories: {repos_resp.status_code if repos_resp else 'No response'}")
                # Set empty repositories list if API call fails
                session['repository_ids'] = []
                flash("Unable to fetch your repositories due to GitHub API limits. Some features may be limited.", "warning")
            else:
                # Parse repositories only if the API call was successful
                repos = repos_resp.json()
                if isinstance(repos, list):
                    session['repository_ids'] = [{'id': repo.get('id', 'unknown'), 'name': repo.get('full_name', 'unknown')} for repo in repos]
                else:
                    logger.error(f"Unexpected format for repositories response: {repos}")
                    session['repository_ids'] = []
        except Exception as e:
            logger.error(f"Error fetching repositories: {str(e)}")
            logger.error(traceback.format_exc())
            # Set empty repositories list if there's an exception
            session['repository_ids'] = []
            flash("Unable to fetch your repositories. Some features may be limited.", "warning")
        
        # Log successful authentication
        logger.info(f"User {user_info['login']} (ID: {user_info['id']}) successfully authenticated")
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f"Error during GitHub callback: {str(e)}")
        logger.error(traceback.format_exc())
        session.clear()
        flash("Error during GitHub authentication. Please try again.", "error")
        return redirect(url_for('login'))

@app.route('/connect/repository', methods=['POST'])
def connect_repository():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get repository details from request
        data = request.get_json()
        repo_id = data.get('repo_id')
        repo_name = data.get('name')
        
        if not repo_id or not repo_name:
            logger.error(f"Missing repository data: {data}")
            return jsonify({'error': 'Missing repository ID or name'}), 400
        
        # Get repository details from GitHub
        access_token = session['user']['access_token']
        repo_resp = github_api_call(f'repos/{repo_name}', access_token)
        
        if repo_resp.status_code == 404:
            logger.error(f"Repository not found: {repo_name}")
            return jsonify({'error': 'Repository not found or no access'}), 404
        elif repo_resp.status_code != 200:
            logger.error(f"Failed to fetch repository details: {repo_resp.status_code}")
            return jsonify({'error': 'Failed to fetch repository details'}), 400
        
        repo_data = repo_resp.json()
        
        # Check if repository is already connected
        user = User.objects(id=session['user']['id']).first()
        existing_repo = ConnectedRepository.objects(user=user, github_repo_id=str(repo_id)).first()
        
        if existing_repo:
            logger.info(f"Repository already connected: {repo_name}")
            return jsonify({'error': 'Repository already connected'}), 400
        
        # Create new connected repository
        connected_repo = ConnectedRepository(
            user=user,
            github_repo_id=str(repo_id),
            name=repo_name,
            description=repo_data.get('description', ''),
            is_private=repo_data['private']
        )
        connected_repo.save()
        
        logger.info(f"Successfully connected repository: {repo_name}")
        return jsonify(connected_repo.to_dict()), 201
        
    except Exception as e:
        logger.error(f"Error connecting repository: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to connect repository'}), 500

@app.route('/disconnect/repository/<repo_id>', methods=['POST'])
def disconnect_repository(repo_id):
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user = User.objects(id=session['user']['id']).first()
        repo = ConnectedRepository.objects(user=user, github_repo_id=repo_id).first()
        
        if not repo:
            return jsonify({'error': 'Repository not found'}), 404
        
        repo.delete()
        return jsonify({'message': 'Repository disconnected successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error disconnecting repository: {str(e)}")
        return jsonify({'error': 'Failed to disconnect repository'}), 500

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    try:
        user = User.objects(id=session['user']['id']).first()
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        # Get only connected repositories
        connected_repositories = [repo.to_dict() for repo in user.get_connected_repositories()]
        
        return render_template(
            'dashboard.html',
            user=session['user'],
            connected_repositories=connected_repositories,
            now=datetime.now()
        )
    except Exception as e:
        logger.error(f"Error in dashboard: {str(e)}")
        logger.error(traceback.format_exc())
        return redirect(url_for('login'))

class APIToken:
    def __init__(self, token_id, token_hash, name, created_at, last_used=None):
        self.token_id = token_id
        self.token_hash = token_hash
        self.name = name
        self.created_at = created_at
        self.last_used = last_used

    def to_dict(self):
        return {
            'id': self.token_id,
            'name': self.name,
            'created_at': self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'token_hash': self.token_hash
        }

    @staticmethod
    def from_dict(data):
        return APIToken(
            token_id=data['id'],
            token_hash=data['token_hash'],
            name=data['name'],
            created_at=datetime.fromisoformat(data['created_at']) if isinstance(data['created_at'], str) else data['created_at'],
            last_used=datetime.fromisoformat(data['last_used']) if data.get('last_used') else None
        )

    @staticmethod
    def hash_token(token):
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def generate_token():
        prefix = 'rpt_'
        random_bytes = secrets.token_bytes(32)
        token = prefix + base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
        return token

@app.route('/api/tokens', methods=['GET'])
def list_tokens():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.objects(id=session['user']['id']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify([user.token.to_dict()] if user.token else [])

@app.route('/api/tokens', methods=['POST'])
def create_token():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        token_name = data.get('name', 'API Token')
        
        # Generate new token
        token_value = APIToken.generate_token()
        token_id = str(uuid.uuid4())
        token_hash = APIToken.hash_token(token_value)
        
        user = User.objects(id=session['user']['id']).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Create new token
        new_token = Token(
            token_id=token_id,
            token_hash=token_hash,
            name=token_name,
            created_at=datetime.utcnow()
        )
        
        # Update user with new token
        user.token = new_token
        user.save()
        
        return jsonify({
            'id': token_id,
            'token': token_value,
            'name': token_name,
            'created_at': new_token.created_at.isoformat()
        })
    except Exception as e:
        logger.error(f"Error creating token: {str(e)}")
        return jsonify({'error': 'Failed to create token'}), 500

@app.route('/api/tokens/<token_id>', methods=['DELETE'])
def revoke_token(token_id):
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user = User.objects(id=session['user']['id']).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user.token and user.token.token_id == token_id:
            user.token = None
            user.save()
        
        return jsonify({'message': 'Token revoked successfully'})
    except Exception as e:
        logger.error(f"Error revoking token: {str(e)}")
        return jsonify({'message': 'Token revoked successfully'})

@app.route('/api/verify_token', methods=['POST'])
def verify_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Invalid authorization header'}), 401
    
    token_value = auth_header.split(' ')[1]
    token_hash = APIToken.hash_token(token_value)
    
    user = User.objects(token__token_hash=token_hash).first()
    if user and user.token:
        user.token.last_used = datetime.utcnow()
        user.save()
        return jsonify({
            'valid': True,
            'user_id': str(user.id),
            'token_id': user.token.token_id
        })
    
    return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/generate-token', methods=['POST'])
def generate_token():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        token_name = data.get('name', 'API Token')
        
        # Generate new token
        token = APIToken.generate_token()
        token_id = str(uuid.uuid4())
        token_hash = APIToken.hash_token(token)
        
        # Create token object
        new_token = APIToken(
            token_id=token_id,
            token_hash=token_hash,
            name=token_name,
            created_at=datetime.utcnow()
        )
        
        # Store token in session
        user = session['user']
        if 'api_tokens' not in user:
            user['api_tokens'] = []
        user['api_tokens'].append(new_token)
        session['user'] = user
        session.modified = True
        
        return jsonify({
            'id': token_id,
            'token': token,  # Full token shown only once
            'name': token_name,
            'created_at': new_token.created_at.isoformat()
        })
    except Exception as e:
        logger.error(f"Error generating token: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/profile', methods=['POST'])
def update_profile():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        user = session['user']
        
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{user['login']}_{uuid.uuid4()}.{file.filename.rsplit('.', 1)[1]}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                user['avatar_url'] = url_for('static', filename=f'uploads/avatars/{filename}')

        if 'display_name' in request.form:
            user['name'] = request.form['display_name']

        session['user'] = user
        return jsonify({'success': True, 'user': user})
    except Exception as e:
        logger.error(f"Error updating profile: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logger.debug("Logout route accessed")
    
    # Clear session data
    session.clear()
    session.modified = True
    
    # Create response object
    response = redirect(url_for('login'))
    
    # Clear all session cookies
    response.delete_cookie('session')
    response.delete_cookie('repopilot_session')
    response.delete_cookie('_oauth2_proxy')  # Clear any OAuth related cookies
    
    # Set Cache-Control headers to prevent caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/settings')
def settings():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Fetch user from MongoDB
    user_data = session['user']
    user = User.objects(github_id=user_data['github_id']).first()
    if not user:
        return redirect(url_for('login'))
    
    # Convert user to dictionary for template
    user_dict = user.to_dict()
    user_dict['login'] = user.login
    user_dict['name'] = user.name
    user_dict['avatar_url'] = user.avatar_url
    
    # Add token information if exists
    if user.token:
        user_dict['token'] = user.token.to_dict()
    
    return render_template('settings.html', user=user_dict)

# Add before_request handler to log session state
@app.before_request
def before_request():
    logger.debug(f"Current route: {request.endpoint}")
    logger.debug(f"Session contents: {list(session.keys())}")
    logger.debug(f"Cookies: {request.cookies}")

    # Make sure the session is saved if modified
    if session.modified:
        # app.session_interface.save_session(app, session, make_response(''))
        pass # Add pass if the block becomes empty, or remove the if statement if not needed

@app.route('/install/github')
def install_github_app():
    """Redirect to GitHub App installation page"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    return redirect(f'https://github.com/apps/{os.getenv("GITHUB_APP_NAME")}/installations/new')

@app.route('/github/callback')
def github_app_callback():
    """Handle GitHub App installation callback"""
    installation_id = request.args.get('installation_id')
    setup_action = request.args.get('setup_action')
    
    if not installation_id:
        flash('Installation failed. Please try again.')
        return redirect(url_for('dashboard'))
    
    try:
        # Create a JWT for GitHub App
        jwt_token = create_jwt()
        
        # Create GitHub Integration
        git_integration = GithubIntegration(
            GITHUB_APP_ID,
            GITHUB_APP_PRIVATE_KEY
        )
        
        # Get an access token for this installation
        access_token = git_integration.get_access_token(installation_id)
        
        # Create a GitHub client with the installation token
        g = Github(access_token.token)
        
        # Get the installation
        installation = g.get_app_installation(installation_id)
        
        # Get the user from our database
        user = User.objects(id=session['user']['id']).first()
        
        # Update or create installation record
        user.github_app_installation_id = installation_id
        user.save()
        
        # Get repositories this installation has access to
        for repo in installation.get_repos():
            # Check if repository is already connected
            existing_repo = ConnectedRepository.objects(
                user=user,
                github_repo_id=str(repo.id)
            ).first()
            
            if not existing_repo:
                # Create new connected repository
                connected_repo = ConnectedRepository(
                    user=user,
                    github_repo_id=str(repo.id),
                    name=repo.full_name,
                    description=repo.description or '',
                    is_private=repo.private,
                    installation_id=installation_id
                )
                connected_repo.save()
        
        flash('GitHub repositories connected successfully!')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Error in GitHub App callback: {str(e)}")
        flash('Failed to complete installation. Please try again.')
        return redirect(url_for('dashboard'))

@app.route('/github/webhook', methods=['POST'])
def github_webhook():
    # Verify that the request is from GitHub
    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        return jsonify({'error': 'No signature provided'}), 400
    
    # Get the raw request body
    payload = request.data
    
    # Verify the signature
    secret = os.environ.get('GITHUB_WEBHOOK_SECRET', '').encode()
    if not secret:
        logger.warning("No GitHub webhook secret configured")
        return jsonify({'error': 'No webhook secret configured'}), 500
    
    # Compute the HMAC
    computed_signature = 'sha256=' + hmac.new(
        secret,
        payload,
        hashlib.sha256
    ).hexdigest()
    
    # Compare signatures
    if not hmac.compare_digest(signature, computed_signature):
        logger.warning(f"Invalid webhook signature: {signature}")
        return jsonify({'error': 'Invalid signature'}), 403
    
    # Process the webhook payload
    data = request.json
    event_type = request.headers.get('X-GitHub-Event')
    
    try:
        if event_type == 'ping':
            return jsonify({'message': 'pong'}), 200
        
        elif event_type == 'repository':
            # Handle repository events (created, deleted, etc.)
            action = data.get('action')
            repo = data.get('repository', {})
            
            logger.info(f"Repository event: {action} for {repo.get('full_name')}")
            
            # Implement repository event handling as needed
            
            return jsonify({'message': 'Repository event processed'}), 200
        
        elif event_type == 'issues':
            # Handle issue events (opened, closed, etc.)
            action = data.get('action')
            issue = data.get('issue', {})
            repo = data.get('repository', {})
            
            logger.info(f"Issue event: {action} for issue #{issue.get('number')} in {repo.get('full_name')}")
            
            # Check if this is a new, labeled, or reopened issue
            if (action == 'opened' or action == 'labeled' or action == 'reopened') and issue:
                # Check if the issue has the 'RepoPilot help' label
                has_repopilot_label = False
                for label in issue.get('labels', []):
                    if label.get('name') == 'RepoPilot help':
                        has_repopilot_label = True
                        break
                
                # If it has the RepoPilot help label, trigger analysis
                if has_repopilot_label:
                    logger.info(f"Triggering automatic analysis for 'RepoPilot help' issue #{issue.get('number')} in {repo.get('full_name')}")
                    
                    try:
                        # Find the repository in our database
                        repo_name = repo.get('full_name')
                        issue_number = issue.get('number')
                        repository = ConnectedRepository.objects(name=repo_name).first()
                        
                        if repository:
                            existing_analysis_in_db = IssueAnalysis.objects(
                                repository=repository,
                                issue_number=issue_number
                            ).first()

                            analysis_object_to_pass = None
                            should_trigger_analysis = False

                            if existing_analysis_in_db:
                                logger.info(f"Webhook: Found existing analysis (ID: {existing_analysis_in_db.id}, Status: {existing_analysis_in_db.analysis_status}) in DB for issue #{issue_number}.")
                                if existing_analysis_in_db.analysis_status in ['pending', 'in_progress']:
                                    logger.info(f"Webhook: Analysis for issue #{issue_number} (ID: {existing_analysis_in_db.id}) is already active with status '{existing_analysis_in_db.analysis_status}'. Skipping new trigger.")
                                else: # Status allows re-trigger (e.g., completed, failed, needs_info)
                                    logger.info(f"Webhook: Re-triggering analysis for issue #{issue_number} (ID: {existing_analysis_in_db.id}). Current status: '{existing_analysis_in_db.analysis_status}'. Resetting.")
                                    existing_analysis_in_db.analysis_status = "pending"
                                    existing_analysis_in_db.issue_title = issue.get('title') 
                                    existing_analysis_in_db.issue_body = issue.get('body')
                                    existing_analysis_in_db.updated_at = datetime.utcnow()
                                    existing_analysis_in_db.error_message = None 
                                    existing_analysis_in_db.analysis_results = {}
                                    # Clear previous logs before adding new ones
                                    existing_analysis_in_db.logs = [{
                                        'timestamp': datetime.utcnow().isoformat(),
                                        'message': f"Re-analysis for issue #{issue_number} initiated by webhook ({action}). Previous logs cleared.",
                                        'type': "info"
                                    }]
                                    existing_analysis_in_db.save() # Save cleared logs and new status
                                    analysis_object_to_pass = existing_analysis_in_db
                                    should_trigger_analysis = True
                            else:
                                logger.info(f"Webhook: No analysis in DB for issue #{issue_number}. Preparing new in-memory object to trigger analysis.")
                                analysis_object_to_pass = IssueAnalysis(
                                    repository=repository,
                                    issue_number=issue_number,
                                    issue_id=str(issue.get('id')),
                                    issue_title=issue.get('title'),
                                    issue_body=issue.get('body'),
                                    analysis_status="pending",
                                    # Initial log for new analysis
                                    logs=[{
                                        'timestamp': datetime.utcnow().isoformat(),
                                        'message': f"New analysis for issue #{issue_number} initiated by webhook ({action}).",
                                        'type': "info"
                                    }]
                                )
                                # This new in-memory object will be saved by the analyzer for the first time
                                should_trigger_analysis = True
                            
                            if should_trigger_analysis and analysis_object_to_pass:
                                user = repository.user
                                if user and user.github_access_token:
                                    # If the object came from DB and was reset, initial log is already added.
                                    # If it's a new in-memory object, initial log is already added.
                                    # No further initial log needed here before calling trigger.
                                    asyncio.run(trigger_issue_analysis(
                                        repository=repository,
                                        issue_data=issue,
                                        access_token=user.github_access_token,
                                        initial_analysis_object=analysis_object_to_pass
                                    ))
                                    logger.info(f"Webhook: Called trigger_issue_analysis for issue #{issue_number}.")
                                else:
                                    logger.warning(f"No access token found for repository {repo_name}, cannot trigger analysis for issue #{issue_number}")
                        else:
                            logger.warning(f"Repository {repo_name} not found in database, cannot trigger analysis for issue #{issue_number}")
                            
                    except Exception as e:
                        logger.error(f"Error triggering analysis from webhook for issue #{issue.get('number', '?')}: {str(e)}")
                        logger.error(traceback.format_exc())
            
            # If this is a relevant issue action that would affect the list view
            # (created, closed, reopened, labeled, unlabeled)
            if action in ['opened', 'closed', 'reopened', 'labeled', 'unlabeled']:
                # This will be automatically handled by the SSE connection
                # as the next poll will pick up the changes
                pass
            
            return jsonify({'message': 'Issue event processed'}), 200
            
        elif event_type == 'issue_comment':
            # Handle issue comment events
            action = data.get('action')
            comment = data.get('comment', {})
            issue = data.get('issue', {})
            repo = data.get('repository', {})
            
            logger.info(f"Issue comment event: {action} on issue #{issue.get('number')} in {repo.get('full_name')}")
            
            # This will be automatically handled by the SSE connection
            # as the next poll will pick up the changes
            
            return jsonify({'message': 'Issue comment event processed'}), 200
        
        else:
            # Log unsupported event types
            logger.info(f"Received unsupported webhook event: {event_type}")
            return jsonify({'message': f'Event type {event_type} not processed'}), 200
        
    except Exception as e:
        logger.error(f"Error processing webhook: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Error processing webhook'}), 500

@app.route('/api/github/repositories')
def get_github_repositories():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get user's access token
        access_token = session['user']['access_token']
        
        # Get user's repositories from GitHub
        repos_resp = github.get('user/repos', token={'access_token': access_token})
        if repos_resp.status_code != 200:
            return jsonify({'error': 'Failed to fetch repositories'}), repos_resp.status_code
            
        repos = repos_resp.json()
        
        # Get user's connected repositories
        user = User.objects(id=session['user']['id']).first()
        connected_repos = {repo.github_repo_id for repo in user.get_connected_repositories()}
        
        # Format repository data
        formatted_repos = []
        for repo in repos:
            formatted_repos.append({
                'id': str(repo['id']),
                'name': repo['full_name'],
                'description': repo.get('description', ''),
                'is_private': repo['private'],
                'is_connected': str(repo['id']) in connected_repos
            })
            
        return jsonify(formatted_repos)
        
    except Exception as e:
        logger.error(f"Error fetching repositories: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to fetch repositories'}), 500

@app.route('/api/repository-issues-updates/<path:repo_name>')
def repository_issues_updates(repo_name):
    if 'user' not in session:
        return 'Unauthorized', 401
    
    def generate():
        last_update_time = datetime.now(pytz.UTC)
        last_issues_count = 0
        
        while True:
            if 'user' not in session:
                break
                
            try:
                access_token = session['user']['access_token']
                
                # Query for 'RepoPilot help' issues
                query_params = {
                    'labels': 'RepoPilot help',
                    'per_page': 100  # Increased to get more issues
                }
                
                issues_resp = github.get(f'repos/{repo_name}/issues', 
                                        token={'access_token': access_token}, 
                                        params=query_params)
                
                if issues_resp.status_code != 200:
                    time.sleep(10)  # Wait before retrying
                    continue
                    
                issues = issues_resp.json()
                current_count = len(issues)
                
                # Check if we have any new issues or updates
                newest_update = last_update_time
                for issue in issues:
                    issue_updated = datetime.fromisoformat(issue['updated_at'].replace('Z', '+00:00'))
                    if issue_updated > newest_update:
                        newest_update = issue_updated
                
                if newest_update > last_update_time or current_count != last_issues_count:
                    # Send the updated issues list
                    update_data = {
                        'issues': issues
                    }
                    
                    yield f"data: {json.dumps(update_data)}\n\n"
                    
                    # Update tracking variables
                    last_update_time = newest_update
                    last_issues_count = current_count
                
                time.sleep(5)  # Poll every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in repository issues SSE stream: {str(e)}")
                time.sleep(5)  # Wait before retrying
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        }
    )

@app.route('/repository/<path:repo_name>/issues')
def repository_issues(repo_name):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    try:
        user = User.objects(id=session['user']['id']).first()
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        # Get repository details from GitHub
        access_token = session['user']['access_token']
        repo_resp = github_api_call(f'repos/{repo_name}', access_token)
        
        if not repo_resp or repo_resp.status_code != 200:
            flash('Repository not found or no access', 'error')
            return redirect(url_for('dashboard'))
            
        repo_data = repo_resp.json()
        
        # Always filter by 'RepoPilot help' label
        query_params = {
            'state': 'open',
            'labels': 'RepoPilot help'
        }
            
        # Use our github_api_call function with retry logic
        issues_resp = github_api_call(f'repos/{repo_name}/issues', access_token, params=query_params)
        
        if not issues_resp or issues_resp.status_code != 200:
            flash('Failed to fetch issues', 'error')
            return redirect(url_for('dashboard'))
            
        issues = issues_resp.json()
        
        # Check if this repository is connected
        repository = ConnectedRepository.objects(user=user, name=repo_name).first()
        
        if repository:
            # Get default requirements for this repository
            try:
                requirements = _get_default_requirements(github, repo_name, access_token)
            except:
                requirements = None
        
        return render_template(
            'repository_issues.html',
            user=session['user'],
            repository=repo_data,
            issues=issues
        )
        
    except Exception as e:
        logger.error(f"Error fetching repository issues: {str(e)}")
        logger.error(traceback.format_exc())
        return redirect(url_for('dashboard'))

def get_issue_data(repo_name, issue_number, access_token):
    """Helper function to fetch issue data"""
    try:
        # Get issue details from GitHub with retry logic
        issue_resp = github_api_call(f'repos/{repo_name}/issues/{issue_number}', access_token)
        
        if not issue_resp or issue_resp.status_code != 200:
            return None, None
            
        issue_data = issue_resp.json()
        
        # Get issue comments with retry logic
        comments_resp = github_api_call(f'repos/{repo_name}/issues/{issue_number}/comments', access_token)
        comments = comments_resp.json() if comments_resp and comments_resp.status_code == 200 else []
        
        return issue_data, comments
    except Exception as e:
        logger.error(f"Error fetching issue data: {str(e)}")
        return None, None

@app.route('/api/issue-updates/<path:repo_name>/<int:issue_number>')
def issue_updates(repo_name, issue_number):
    logger.info(f"SSE: New connection request for {repo_name}/{issue_number}")
    logger.info(f"SSE: Session contents: {list(session.keys())}")
    logger.info(f"SSE: User in session: {'user' in session}")
    
    if 'user' not in session:
        logger.warning(f"SSE: Unauthorized access attempt for {repo_name}/{issue_number}")
        return 'Unauthorized', 401
    
    def generate():
        logger.info(f"SSE: Starting stream generator for {repo_name}/{issue_number}")
        last_analysis_state = {}
        heartbeat_counter = 0
        
        # Send initial connection confirmation
        initial_data = {'connected': True, 'timestamp': datetime.utcnow().isoformat()}
        yield f"data: {json.dumps(initial_data, cls=CustomJSONEncoder)}\n\n"
        logger.info(f"SSE: Sent initial connection confirmation for {repo_name}/{issue_number}")
        
        # Get user and repository info once at the start
        try:
            user_id = session['user']['id']
            user = User.objects(id=user_id).first()
            if not user:
                logger.error(f"SSE: User {user_id} not found for {repo_name}/{issue_number}")
                error_data = {'error': 'User not found', 'timestamp': datetime.utcnow().isoformat()}
                yield f"data: {json.dumps(error_data, cls=CustomJSONEncoder)}\n\n"
                return

            repository = ConnectedRepository.objects(user=user, name=repo_name).first()
            if not repository:
                logger.error(f"SSE: Repository {repo_name} not found for user {user.login}")
                error_data = {'error': f'Repository {repo_name} not found', 'timestamp': datetime.utcnow().isoformat()}
                yield f"data: {json.dumps(error_data, cls=CustomJSONEncoder)}\n\n"
                return
            
            logger.info(f"SSE: Successfully found user {user.login} and repository {repo_name}")
        except Exception as e:
            logger.error(f"SSE: Error getting user/repository info: {str(e)}")
            error_data = {'error': f'Setup error: {str(e)}', 'timestamp': datetime.utcnow().isoformat()}
            yield f"data: {json.dumps(error_data, cls=CustomJSONEncoder)}\n\n"
            return
        
        while True:
            try:
                # Ensure user is still in session (session might expire)
                if 'user' not in session:
                    logger.warning(f"SSE: Session expired for {repo_name}/{issue_number}")
                    break
                    
                # Fetch the IssueAnalysis object from MongoDB
                analysis = IssueAnalysis.objects(repository=repository, issue_number=issue_number).first()

                current_analysis_state = {}
                if analysis:
                    current_analysis_state = {
                        'id': str(analysis.id),
                        'analysis_status': analysis.analysis_status,
                        'logs_count': len(analysis.logs or []),
                        'updated_at': analysis.updated_at.isoformat() if hasattr(analysis, 'updated_at') and analysis.updated_at else None
                    }
                    logger.debug(f"SSE: Current analysis state for {repo_name}/{issue_number}: {current_analysis_state}")

                # Check if the analysis state has changed (status or log count)
                if current_analysis_state != last_analysis_state:
                    logger.info(f"SSE: Detected change in analysis for {repo_name}/{issue_number}. Status: {current_analysis_state.get('analysis_status')}, Logs: {current_analysis_state.get('logs_count')}")
                    update_data = {}
                    if analysis: 
                         # Send the whole analysis object, client-side already picks out .logs and .analysis_status
                        analysis_dict = analysis.to_dict()
                        update_data['analysis'] = analysis_dict
                        update_data['timestamp'] = datetime.utcnow().isoformat()
                        logger.debug(f"SSE: Sending analysis update with {len(analysis_dict.get('logs', []))} logs")
                    else:
                        # If analysis is null, send empty analysis
                        update_data['analysis'] = None
                        update_data['timestamp'] = datetime.utcnow().isoformat()
                        logger.info(f"SSE: No analysis found for {repo_name}/{issue_number}, sending null analysis")

                    try:
                        data_json = json.dumps(update_data, cls=CustomJSONEncoder)
                        yield f"data: {data_json}\n\n"
                        logger.info(f"SSE: Successfully sent update for {repo_name}/{issue_number}")
                    except Exception as json_error:
                        logger.error(f"SSE: JSON encoding error for {repo_name}/{issue_number}: {str(json_error)}")
                        # Send a simpler error message
                        error_data = {'error': 'Data encoding error', 'timestamp': datetime.utcnow().isoformat()}
                        yield f"data: {json.dumps(error_data)}\n\n"
                    
                    last_analysis_state = current_analysis_state
                
                # Send heartbeat every 10 iterations (20 seconds with 2-second sleep)
                heartbeat_counter += 1
                if heartbeat_counter >= 10:
                    heartbeat_data = {
                        'heartbeat': True,
                        'timestamp': datetime.utcnow().isoformat(),
                        'status': current_analysis_state.get('analysis_status', 'unknown')
                    }
                    try:
                        yield f"data: {json.dumps(heartbeat_data, cls=CustomJSONEncoder)}\n\n"
                        logger.debug(f"SSE: Sent heartbeat for {repo_name}/{issue_number}")
                    except Exception as heartbeat_error:
                        logger.error(f"SSE: Heartbeat send error for {repo_name}/{issue_number}: {str(heartbeat_error)}")
                    heartbeat_counter = 0
                
                # Dynamic polling frequency based on analysis status
                current_status = current_analysis_state.get('analysis_status', 'unknown')
                if current_status in ['in_progress', 'pending']:
                    # More frequent polling during active analysis
                    time.sleep(1)  # Poll every 1 second during active analysis
                elif current_status in ['completed', 'failed']:
                    # Less frequent polling when analysis is done
                    time.sleep(5)  # Poll every 5 seconds when completed/failed
                else:
                    # Default polling frequency
                    time.sleep(2)  # Poll every 2 seconds (default)
                
            except Exception as e:
                logger.error(f"SSE: Error in stream loop for {repo_name}/{issue_number}: {str(e)}")
                logger.error(traceback.format_exc())
                # Send an error message to the client if possible, then wait before retrying
                try:
                    error_payload = json.dumps({
                        "error": f"SSE stream error: {str(e)}",
                        "timestamp": datetime.utcnow().isoformat()
                    }, cls=CustomJSONEncoder)
                    yield f"data: {error_payload}\n\n"
                except:
                    pass  # If we can't even send the error, just continue
                time.sleep(5) 
        
        logger.info(f"SSE: Stream ended for {repo_name}/{issue_number}")
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Cache-Control'
        }
    )

@app.route('/repository/<path:repo_name>/issues/<int:issue_number>')
def issue_details(repo_name, issue_number):
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        user = User.objects(id=session['user']['id']).first()
        repository = ConnectedRepository.objects(user=user, name=repo_name).first()
        
        if not repository:
            flash('Repository not found or not connected to your account.', 'error')
            return redirect(url_for('dashboard'))
        
        # Get issue data from GitHub
        issue_data, comments_data = get_issue_data(repo_name, issue_number, session['user']['access_token'])
        
        if not issue_data:
            flash('Issue not found.', 'error')
            return redirect(url_for('repository_issues', repo_name=repo_name))
        
        # Get comments using PyGithub for more detailed info
        github_client = Github(session['user']['access_token'])
        repo = github_client.get_repo(repo_name)
        issue = repo.get_issue(issue_number)
        comments = list(issue.get_comments())
        
        analysis = None
        should_trigger_analysis = False
        
        try:
            # Attempt to create a new analysis record. This ensures atomicity for new issues.
            # If an analysis for this repo/issue already exists, a NotUniqueError will be raised due to the unique index.
            analysis = IssueAnalysis.objects.create(
                repository=repository,
                issue_number=issue_number,
                issue_id=str(issue.id),
                issue_title=issue.title,
                issue_body=issue.body,
                analysis_status="pending", # Will be immediately processed
                logs=[{
                    'timestamp': datetime.utcnow().isoformat(),
                    'message': f"New analysis for issue #{issue_number} initiated by page view.",
                    'type': "info"
                }]
            )
            logger.info(f"Issue Details: Created and saved new analysis (ID: {analysis.id}) for issue #{issue_number}. Will trigger.")
            should_trigger_analysis = True
        except NotUniqueError:
            # If NotUniqueError, an analysis already exists. Fetch it.
            logger.info(f"Issue Details: Analysis for issue #{issue_number} already exists. Fetching it.")
            analysis = IssueAnalysis.objects(repository=repository, issue_number=issue_number).first()
            if analysis:
                logger.info(f"Issue Details: Existing analysis (ID: {analysis.id}) for issue #{issue_number} found with status: {analysis.analysis_status}")
                # If user views the page and analysis is active, do nothing to re-trigger from here.
                if analysis.analysis_status in ['pending', 'in_progress']:
                    logger.info(f"Issue Details: Analysis for issue #{issue_number} is already active ({analysis.analysis_status}). Not re-triggering from page view.")
                    should_trigger_analysis = False 
                elif analysis.analysis_status in ['completed', 'failed', 'needs_info']:
                    # If user views the page and analysis is in a terminal state, we don't automatically re-trigger.
                    # Re-analysis should be an explicit user action (e.g., button calling analyze_issue_api).
                    # However, if you WANTED to auto-re-trigger on viewing a failed/completed issue, the logic would go here.
                    # For now, we will NOT re-trigger here, just display the existing terminal state.
                    logger.info(f"Issue Details: Analysis for issue #{issue_number} is in a terminal state ({analysis.analysis_status}). Not automatically re-triggering from page view.")
                    should_trigger_analysis = False
                else:
                    # Unknown or unexpected status, treat as re-triable for safety, clear logs.
                    logger.warning(f"Issue Details: Analysis for issue #{issue_number} has an unexpected status '{analysis.analysis_status}'. Resetting and re-triggering.")
                    analysis.analysis_status = "pending"
                    analysis.issue_title = issue.title
                    analysis.issue_body = issue.body
                    analysis.updated_at = datetime.utcnow()
                    analysis.error_message = None
                    analysis.analysis_results = {}
                    # Clear previous logs before adding new ones
                    analysis.logs = [{
                        'timestamp': datetime.utcnow().isoformat(),
                        'message': f"Re-analysis for issue #{issue_number} initiated by page view due to unexpected status. Previous logs cleared.",
                        'type': "info"
                    }]
                    analysis.save() # Save cleared logs and new status
                    should_trigger_analysis = True
            else:
                # Should not happen if NotUniqueError was raised, but as a fallback:
                logger.error(f"Issue Details: NotUniqueError but failed to fetch existing analysis for issue #{issue_number}.")
                flash('Error retrieving analysis details.', 'error')
                return redirect(url_for('repository_issues', repo_name=repo_name))

        except Exception as e_outer:
            logger.error(f"Issue Details: Outer exception trying to get/create analysis for issue #{issue_number}: {e_outer}")
            logger.error(traceback.format_exc())
            flash('Error preparing analysis details.', 'error')
            return redirect(url_for('repository_issues', repo_name=repo_name))

        if should_trigger_analysis and analysis:
            logger.info(f"Issue Details: Triggering analysis for issue #{issue_number} (ID: {analysis.id}, Status: {analysis.analysis_status}).")
            asyncio.run(trigger_issue_analysis(repository, 
                                             issue_data, 
                                             access_token=session['user']['access_token'], 
                                             initial_analysis_object=analysis))
        
        current_logs = analysis.logs if analysis and hasattr(analysis, 'logs') else []
        
        return render_template('issue_details.html', 
                              repository=repository, 
                              issue=issue_data, 
                              comments=comments, 
                              user=user,
                              analysis=analysis, # Pass the definitive analysis object
                              logs=current_logs)
                              
    except Exception as e:
        logger.error(f"Error in issue_details route: {str(e)}")
        logger.error(traceback.format_exc())
        flash(f'Error loading issue details: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

async def trigger_issue_analysis(repository, issue_data, requirements=None, access_token=None, initial_analysis_object=None):
    """Trigger issue analysis in the background using the IssueAnalyzer"""
    try:
        from agents.issue_analyzer import IssueAnalyzer
        
        # Create an instance of the IssueAnalyzer
        analyzer = IssueAnalyzer()
        
        # Extract required information (issue_body is primary, others for context if new analysis created by analyzer)
        issue_body = issue_data.get('body', '') 
        issue_number_from_data = issue_data.get('number') # Can be derived from initial_analysis_object too
        issue_id_from_data = str(issue_data.get('id')) # Can be derived
        
        # Pass the initial_analysis_object to the analyzer
        analysis, created = await analyzer.get_or_create_analysis(
            issue_body=issue_body, # Still pass body for context
            repository=repository, # Essential for DB query by analyzer
            issue_number=initial_analysis_object.issue_number if initial_analysis_object else issue_number_from_data, # Prefer from object if available
            issue_id=initial_analysis_object.issue_id if initial_analysis_object and hasattr(initial_analysis_object, 'issue_id') and initial_analysis_object.issue_id else issue_id_from_data,
            access_token=access_token,
            requirements_content=requirements,
            initial_analysis_object=initial_analysis_object # Pass the object here
        )
        
        logger.info(f"Trigger: Analysis process initiated by analyzer for issue #{analysis.issue_number if analysis else 'unknown'}. Created by analyzer: {created}")
        return analysis
        
    except Exception as e:
        logger.error(f"Error in trigger_issue_analysis for issue data: {issue_data.get('number', '?')}: {str(e)}")
        logger.error(traceback.format_exc())
        return None

# Add a route for tab fallback
@app.route('/tab-fallback')
def tab_fallback():
    """Serve a fallback page for tab navigation issues"""
    return render_template('tab_fallback.html')

@app.template_filter('datetime')
def format_datetime(value):
    if isinstance(value, str):
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    else:
        dt = value
    
    # Convert to user's timezone (for now using UTC)
    dt = dt.replace(tzinfo=pytz.UTC)
    
    # Format the date
    now = datetime.now(pytz.UTC)
    diff = now - dt
    
    if diff.days == 0:
        if diff.seconds < 60:
            return 'just now'
        elif diff.seconds < 3600:
            minutes = diff.seconds // 60
            return f'{minutes} minute{"s" if minutes != 1 else ""} ago'
        else:
            hours = diff.seconds // 3600
            return f'{hours} hour{"s" if hours != 1 else ""} ago'
    elif diff.days == 1:
        return 'yesterday'
    elif diff.days < 7:
        return f'{diff.days} days ago'
    else:
        return dt.strftime('%b %d, %Y')

@app.template_filter('markdown')
def render_markdown(text):
    if not text:
        return ""
    # Configure allowed HTML tags and attributes
    allowed_tags = [
        'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'br', 'hr',
        'strong', 'em', 'a', 'ul', 'ol', 'li', 'code', 'pre',
        'img', 'blockquote', 'table', 'thead', 'tbody', 'tr',
        'th', 'td', 'span', 'div'
    ]
    allowed_attrs = {
        '*': ['class', 'style'],
        'a': ['href', 'title', 'target'],
        'img': ['src', 'alt', 'title']
    }

    # Convert markdown to HTML with syntax highlighting and other extensions
    html = markdown.markdown(
        text,
        extensions=[
            'fenced_code',
            CodeHiliteExtension(css_class='highlight'),
            'tables',
            'nl2br'
        ]
    )
    
    # Clean the HTML output
    clean_html = bleach.clean(
        html,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip_comments=True
    )
    
    return clean_html

@app.route('/api/analysis-status/<path:repo_name>/<int:issue_number>')
def analysis_status(repo_name, issue_number):
    """Get analysis status and logs for an issue"""
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        user = User.objects(id=session['user']['id']).first()
        repository = ConnectedRepository.objects(user=user, name=repo_name).first()
        
        if not repository:
            return jsonify({'error': 'Repository not found'}), 404
            
        # Get analysis for this issue
        analysis = IssueAnalysis.objects(repository=repository, issue_number=issue_number).first()
        
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
            
        # Return analysis data
        return jsonify({
            'analysis': analysis.to_dict(),
            'status': 'success'
        })
        
    except Exception as e:
        logger.error(f"Error getting analysis status: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': f'Error getting analysis status: {str(e)}'}), 500

@app.route('/api/analyze-issue/<path:repo_name>/<int:issue_number>', methods=['GET', 'POST'])
def analyze_issue_api(repo_name, issue_number):
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        user = User.objects(id=session['user']['id']).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        repository = ConnectedRepository.objects(user=user, name=repo_name).first()
        if not repository:
            return jsonify({'error': 'Repository not found or not connected'}), 404

        # Fetch issue data from GitHub to pass to trigger_issue_analysis
        # This is similar to what issue_details route does
        # Ensure you have PyGithub imported if not already: from github import Github
        try:
            github_client = Github(session['user']['access_token'])
            gh_repo = github_client.get_repo(repo_name)
            gh_issue = gh_repo.get_issue(issue_number)
        except Exception as gh_e:
            logger.error(f"GitHub API error fetching issue {repo_name}/{issue_number}: {str(gh_e)}")
            return jsonify({'error': f'Failed to fetch issue details from GitHub: {str(gh_e)}'}), 500
        
        issue_data_dict = {
            "id": gh_issue.id,
            "number": gh_issue.number,
            "title": gh_issue.title,
            "body": gh_issue.body if gh_issue.body else "",
            "labels": [{"name": label.name} for label in gh_issue.labels] 
            # Add other fields if trigger_issue_analysis expects them from the issue_data payload
        }

        # Prepare the initial_analysis_object (similar to webhook logic)
        existing_analysis_in_db = IssueAnalysis.objects(
            repository=repository,
            issue_number=issue_number
        ).first()

        analysis_object_to_pass = None
        should_trigger_analysis = False

        if existing_analysis_in_db:
            logger.info(f"API analyze-issue: Found existing analysis (ID: {existing_analysis_in_db.id}, Status: {existing_analysis_in_db.analysis_status}) for issue #{issue_number}.")
            if existing_analysis_in_db.analysis_status in ['pending', 'in_progress']:
                logger.info(f"API analyze-issue: Analysis for issue #{issue_number} (ID: {existing_analysis_in_db.id}) is already active with status '{existing_analysis_in_db.analysis_status}'. Skipping new trigger.")
                return jsonify({'status': 'skipped', 'message': f'Analysis for issue #{issue_number} already active ({existing_analysis_in_db.analysis_status})'}), 202
            else: # Status allows re-trigger (e.g., completed, failed, needs_info)
                logger.info(f"API analyze-issue: Re-triggering analysis for issue #{issue_number} (ID: {existing_analysis_in_db.id}). Current status: '{existing_analysis_in_db.analysis_status}'. Resetting.")
                existing_analysis_in_db.analysis_status = "pending"
                existing_analysis_in_db.issue_title = issue_data_dict['title']
                existing_analysis_in_db.issue_body = issue_data_dict['body']
                existing_analysis_in_db.updated_at = datetime.utcnow()
                existing_analysis_in_db.error_message = None
                existing_analysis_in_db.analysis_results = {}
                # Clear previous logs and add a new initial log
                existing_analysis_in_db.logs = [{
                    'timestamp': datetime.utcnow().isoformat(),
                    'message': f"Re-analysis for issue #{issue_number} initiated by API call. Previous logs cleared.",
                    'type': "info"
                }]
                existing_analysis_in_db.save() # Save cleared logs and new status
                analysis_object_to_pass = existing_analysis_in_db
                should_trigger_analysis = True
        else:
            logger.info(f"API analyze-issue: No analysis in DB for issue #{issue_number}. Preparing new in-memory object.")
            analysis_object_to_pass = IssueAnalysis(
                repository=repository,
                issue_number=issue_number,
                issue_id=str(issue_data_dict['id']),
                issue_title=issue_data_dict['title'],
                issue_body=issue_data_dict['body'],
                analysis_status="pending",
                # Initial log for new analysis
                logs=[{
                    'timestamp': datetime.utcnow().isoformat(),
                    'message': f"New analysis for issue #{issue_number} initiated by API call.",
                    'type': "info"
                }]
            )
            # This new in-memory object will be saved by the analyzer for the first time
            should_trigger_analysis = True
        
        if should_trigger_analysis and analysis_object_to_pass:
            # Initial log is already added to analysis_object_to_pass.logs in the blocks above.
            # If it was an in-memory object, analyzer.get_or_create_analysis will save it.
            # If it was an existing DB object, logs were cleared, new log added, and saved.
            asyncio.run(trigger_issue_analysis(
                repository=repository,
                issue_data=issue_data_dict, 
                access_token=session['user']['access_token'],
                initial_analysis_object=analysis_object_to_pass
            ))
            return jsonify({'status': 'success', 'message': f'Analysis triggered for issue #{issue_number}'}), 200
        elif not should_trigger_analysis: # This case implies it was skipped earlier
            # The earlier return jsonify(...) for skipped analysis already handled this.
            # This part might not be strictly necessary if the skip path always returns.
            pass 

        # Fallback if something unexpected happened
        return jsonify({'status': 'error', 'message': 'Analysis trigger condition not met or already active'}), 409

    except Exception as e:
        logger.error(f"Error in /api/analyze-issue endpoint for {repo_name}/{issue_number}: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': f'Failed to trigger analysis: {str(e)}'}), 500

if __name__ == '__main__':
    logger.info("Starting Flask app on http://localhost:5001")
    
    # Properly configure asyncio for clean shutdown
    import signal
    import atexit
    
    # Store running tasks
    running_tasks = set()
    
    def register_task(task):
        running_tasks.add(task)
        task.add_done_callback(lambda t: running_tasks.discard(t))
    
    def cleanup_tasks():
        # Cancel any pending tasks on shutdown
        for task in running_tasks:
            if not task.done():
                task.cancel()
    
    # Register the cleanup function to run during shutdown
    atexit.register(cleanup_tasks)
    
    # Run the Flask app
    app.run(debug=True, port=5001) 