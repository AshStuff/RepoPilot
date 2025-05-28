# Corrected CI checking logic for repository_issues_updates SSE route
def corrected_sse_ci_check():
    # Fetch PRs with failed CircleCI workflows (prioritize CircleCI API over GitHub status)
    if CIRCLECI_API_TOKEN:
        # Use CircleCI API for more accurate and efficient CI failure detection
        failed_ci_prs = asyncio.run(match_circleci_failures_to_prs(repo_name, access_token))
        logger.info(f"SSE: Using CircleCI API: Found {len(failed_ci_prs)} PRs with failed CircleCI workflows")
    else:
        # Fallback to GitHub status API if no CircleCI token
        logger.info("SSE: No CircleCI token configured, falling back to GitHub status API")
        prs_resp = github_api_call(f'repos/{repo_name}/pulls', access_token, params={'state': 'open'})
        failed_ci_prs = []
        
        if prs_resp and prs_resp.status_code == 200:
            prs = prs_resp.json()
            logger.info(f"SSE: Found {len(prs)} open PRs for {repo_name}")
            
            # Only check first 3 PRs to reduce API calls in fallback mode
            for pr in prs[:3]:
                try:
                    # Get the latest commit SHA for the PR
                    head_sha = pr['head']['sha']
                    
                    # Use the enhanced CI status checking
                    has_failed_ci, failure_details = asyncio.run(check_ci_status(repo_name, head_sha, access_token))
                    
                    if has_failed_ci:
                        # Add branch name and other PR details
                        pr_data = {
                            'id': pr['id'],
                            'number': pr['number'],
                            'title': pr['title'],
                            'body': pr.get('body', ''),
                            'state': pr['state'],
                            'user': pr['user'],
                            'created_at': pr['created_at'],
                            'updated_at': pr['updated_at'],
                            'head': pr['head'],
                            'base': pr['base'],
                            'branch_name': pr['head']['ref'],
                            'type': 'pull_request',
                            'html_url': pr['html_url'],
                            'labels': pr.get('labels', []),
                            'ci_failure_details': failure_details
                        }
                        failed_ci_prs.append(pr_data)
                        logger.info(f"SSE: Found failed CI PR #{pr['number']}: {pr['title']} (branch: {pr['head']['ref']}) - {failure_details}")
                    else:
                        logger.debug(f"SSE: PR #{pr['number']} has passing CI: {pr['title']} (branch: {pr['head']['ref']})")
                        
                except Exception as pr_error:
                    logger.error(f"SSE: Error checking CI status for PR #{pr.get('number', '?')} in SSE: {str(pr_error)}")
                    continue

# Corrected CI checking logic for repository_issues main route
def corrected_main_route_ci_check():
    # Fetch PRs with failed CircleCI workflows (prioritize CircleCI API over GitHub status)
    if CIRCLECI_API_TOKEN:
        # Use CircleCI API for more accurate and efficient CI failure detection
        failed_ci_prs = asyncio.run(match_circleci_failures_to_prs(repo_name, access_token))
        logger.info(f"Using CircleCI API: Found {len(failed_ci_prs)} PRs with failed CircleCI workflows")
    else:
        # Fallback to GitHub status API if no CircleCI token
        logger.info("No CircleCI token configured, falling back to GitHub status API")
        prs_resp = github_api_call(f'repos/{repo_name}/pulls', access_token, params={'state': 'open'})
        failed_ci_prs = []
        
        if prs_resp and prs_resp.status_code == 200:
            prs = prs_resp.json()
            logger.info(f"Found {len(prs)} open PRs for {repo_name}")
            
            # Only check first 5 PRs to reduce API calls in fallback mode
            for pr in prs[:5]:
                try:
                    # Get the latest commit SHA for the PR
                    head_sha = pr['head']['sha']
                    
                    # Use the enhanced CI status checking
                    has_failed_ci, failure_details = asyncio.run(check_ci_status(repo_name, head_sha, access_token))
                    
                    if has_failed_ci:
                        # Add branch name and other PR details
                        pr_data = {
                            'id': pr['id'],
                            'number': pr['number'],
                            'title': pr['title'],
                            'body': pr.get('body', ''),
                            'state': pr['state'],
                            'user': pr['user'],
                            'created_at': pr['created_at'],
                            'updated_at': pr['updated_at'],
                            'head': pr['head'],
                            'base': pr['base'],
                            'branch_name': pr['head']['ref'],
                            'type': 'pull_request',
                            'html_url': pr['html_url'],
                            'labels': pr.get('labels', []),
                            'ci_failure_details': failure_details
                        }
                        failed_ci_prs.append(pr_data)
                        logger.info(f"Found failed CI PR #{pr['number']}: {pr['title']} (branch: {pr['head']['ref']}) - {failure_details}")
                        
                    else:
                        logger.debug(f"PR #{pr['number']} has passing CI: {pr['title']} (branch: {pr['head']['ref']})")
                        
                except Exception as pr_error:
                    logger.error(f"Error checking CI status for PR #{pr.get('number', '?')}: {str(pr_error)}")
                    continue
        else:
            logger.warning(f"Failed to fetch PRs for {repo_name}") 