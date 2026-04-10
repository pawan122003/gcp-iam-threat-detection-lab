"""
Trust context validation for GitHub OIDC tokens and CI context.
"""
import json
import os
import requests
from pathlib import Path
from typing import Dict, List, Tuple

from jwt import PyJWKClient, decode


def validate_oidc_token(
    token: str, 
    expected_repository: str, 
    expected_ref: str, 
    expected_audience: str = "https://github.com",
) -> Tuple[bool, List[str]]:
    """
    Validate a GitHub OIDC token.
    
    Args:
        token: The OIDC token to validate.
        expected_repository: The expected repository (e.g., "owner/repo").
        expected_ref: The expected ref (e.g., "refs/heads/main").
        expected_audience: The expected audience (default: "https://github.com").
    
    Returns:
        Tuple of (is_valid, reasons).
    """
    reasons = []
    
    if not token:
        reasons.append("OIDC token is empty.")
        return False, reasons

    try:
        # Fetch JWKS URI
        response = requests.get(
            "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
        )
        response.raise_for_status()
        jwks_uri = response.json()["jwks_uri"]

        # Fetch JWKS
        response = requests.get(jwks_uri)
        response.raise_for_status()
        jwks = response.json()

        # Decode and validate token
        jwk_client = PyJWKClient(jwks_uri)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        claims = decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=expected_audience,
            options={"verify_exp": True},
        )

        # Validate claims
        expected_issuer = "https://token.actions.githubusercontent.com"
        if claims.get("iss") != expected_issuer:
            reasons.append(f"Invalid issuer: {claims.get('iss')}")
        
        if claims.get("repository") != expected_repository:
            reasons.append(f"Invalid repository: {claims.get('repository')}")
        
        if claims.get("ref") != expected_ref:
            reasons.append(f"Invalid ref: {claims.get('ref')}")
        
        if not reasons:
            return True, []
        
    except Exception as e:
        reasons.append(f"OIDC validation error: {str(e)}")
    
    return False, reasons


def is_fork_pr(github_event_path: str) -> bool:
    """
    Check if the current run is from a fork PR.
    
    Args:
        github_event_path: Path to the GitHub event JSON file.
    
    Returns:
        True if the run is from a fork PR, False otherwise.
    """
    if not github_event_path:
        return False
    
    try:
        github_event = json.loads(Path(github_event_path).read_text(encoding="utf-8"))
        repository = github_event.get("repository", "")
        head_repository = github_event.get("pull_request", {}).get("head", {}).get("repo", {}).get("full_name", "")
        return head_repository != repository
    except Exception:
        return False


def validate_ci_context(
    ci_context_path: str, 
    github_event_path: str, 
    expected_repository: str, 
    expected_ref: str,
) -> Dict:
    """
    Validate the CI context for trust and authorization.
    
    Args:
        ci_context_path: Path to the CI context JSON file.
        github_event_path: Path to the GitHub event JSON file.
        expected_repository: The expected repository (e.g., "owner/repo").
        expected_ref: The expected ref (e.g., "refs/heads/main").
    
    Returns:
        Dictionary containing validation results and reasons.
    """
    is_fork = is_fork_pr(github_event_path)
    validation = {
        "valid": True,
        "reasons": [],
        "is_fork_pr": is_fork,
        "oidc_token_valid": False,
        "oidc_validation_reasons": [],
    }
    
    if is_fork:
        validation["reasons"].append("Fork PR detected. Trust validation skipped.")
        return validation
    
    # Validate OIDC token
    oidc_token = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not oidc_token:
        validation["valid"] = False
        validation["reasons"].append("OIDC token not found.")
    else:
        oidc_valid, oidc_reasons = validate_oidc_token(
            oidc_token, 
            expected_repository, 
            expected_ref,
        )
        validation["oidc_token_valid"] = oidc_valid
        validation["oidc_validation_reasons"] = oidc_reasons
        if not oidc_valid:
            validation["valid"] = False
            validation["reasons"].extend(oidc_reasons)
    
    return validation