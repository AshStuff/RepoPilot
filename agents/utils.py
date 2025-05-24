import base64
from github import Github
import toml
import re
from typing import Optional, List


def _get_default_requirements(github: Github, repo_name: str, access_token: str) -> Optional[List[str]]:
    """Get Python package dependencies from various dependency files in a repository.
    
    This function attempts to find and parse Python package dependencies from common
    dependency files in the following order:
    1. requirements.txt
    2. pyproject.toml (supports both PEP 621 and Poetry formats)
    3. setup.py
    
    Args:
        repo_name (str): The full repository name (e.g., "owner/repo")
        access_token (str): GitHub access token for API authentication
        
    Returns:
        Optional[List[str]]: A list of package requirements if found, None if no dependencies
        were found or if there was an error parsing the files. Each requirement in the list
        will be in the format "package==version" or "package>=version" etc.
    """
    # Try requirements.txt first
    req_resp = github.get(f'repos/{repo_name}/contents/requirements.txt', token={'access_token': access_token})
    if req_resp.status_code == 200:
        content = base64.b64decode(req_resp.json()['content']).decode('utf-8')
        return [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]
    
    # Try pyproject.toml
    pyproject_resp = github.get(f'repos/{repo_name}/contents/pyproject.toml', token={'access_token': access_token})
    if pyproject_resp.status_code == 200:
        content = base64.b64decode(pyproject_resp.json()['content']).decode('utf-8')
        try:
            data = toml.loads(content)
            # Check for dependencies in different common locations
            dependencies = []
            if 'project' in data and 'dependencies' in data['project']:
                dependencies.extend(data['project']['dependencies'])
            if 'tool' in data and 'poetry' in data['tool'] and 'dependencies' in data['tool']['poetry']:
                deps = data['tool']['poetry']['dependencies']
                for pkg, version in deps.items():
                    if isinstance(version, str):
                        dependencies.append(f"{pkg}{version}")
                    else:
                        dependencies.append(pkg)
            if dependencies:
                return dependencies
        except Exception:
            pass
    
    # Try setup.py
    setup_resp = github.get(f'repos/{repo_name}/contents/setup.py', token={'access_token': access_token})
    if setup_resp.status_code == 200:
        content = base64.b64decode(setup_resp.json()['content']).decode('utf-8')
        # Look for install_requires or setup_requires
        install_requires_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if install_requires_match:
            deps = install_requires_match.group(1)
            # Clean up the dependencies string and split into list
            deps = re.sub(r'[\'"\s]', '', deps)
            return [dep.strip() for dep in deps.split(',') if dep.strip()]
    
    return None