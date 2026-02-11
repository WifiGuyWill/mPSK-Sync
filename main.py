#!/usr/bin/env python3
"""
FastAPI web application for Aruba Central and Juniper Mist mPSK/PSK integration.
"""

import os
import json
import requests
import base64
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv
import secrets

# Load environment variables
load_dotenv()

app = FastAPI(title="mPSK Integration", version="1.0.0")
templates = Jinja2Templates(directory="templates")

# ============================================================================
# CONFIGURATION (from environment variables only - see .env.example)
# ============================================================================

# Aruba Central Configuration
ARUBA_BASE_URL = os.getenv("ARUBA_BASE_URL", "")
ARUBA_ACCESS_TOKEN = os.getenv("ARUBA_TOKEN", "")
ARUBA_CLIENT_ID = os.getenv("ARUBA_CLIENT_ID", "")
ARUBA_CLIENT_SECRET = os.getenv("ARUBA_CLIENT_SECRET", "")
ARUBA_MPSK_NETWORK_ID = os.getenv("ARUBA_MPSK_NETWORK_ID", "")
ARUBA_USER_ROLE = os.getenv("ARUBA_USER_ROLE", "")

# Juniper Mist Configuration
MIST_BASE_URL = os.getenv("MIST_BASE_URL", "")
MIST_API_TOKEN = os.getenv("MIST_TOKEN", "")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "")

# Network Configuration
SSID = os.getenv("SSID", "")
_vlan = os.getenv("VLAN_ID", "")
VLAN_ID = int(_vlan) if _vlan.strip() else 0

# Application Configuration (web login)
APP_USERNAME = os.getenv("APP_USERNAME", "")
APP_PASSWORD = os.getenv("APP_PASSWORD", "")

# In-memory token storage (simple session management)
active_tokens = {}

# API Endpoints
ARUBA_NAMED_MPSK_ENDPOINT = f"{ARUBA_BASE_URL}/network-config/v1alpha1/cnac-named-mpsk-reg"
MIST_PSK_ENDPOINT = f"{MIST_BASE_URL}/api/v1/orgs/{MIST_ORG_ID}/psks"


# ============================================================================
# TOKEN MANAGEMENT FUNCTIONS
# ============================================================================

def decode_jwt_token(token: str) -> Optional[dict]:
    """Decode a JWT token to extract payload information (without verification)."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None


def check_token_expiration(token: str) -> tuple[bool, Optional[datetime], str]:
    """Check if a JWT token is expired."""
    payload = decode_jwt_token(token)
    if not payload:
        return False, None, "Could not decode token"
    exp = payload.get('exp')
    if not exp:
        return False, None, "Token has no expiration claim"
    expires_at = datetime.fromtimestamp(exp)
    now = datetime.now()
    if now >= expires_at:
        return False, expires_at, f"Token expired at {expires_at}"
    else:
        time_remaining = expires_at - now
        return True, expires_at, f"Token valid until {expires_at} ({time_remaining} remaining)"


def refresh_aruba_token() -> tuple[bool, Optional[str], Optional[str]]:
    """Refresh the Aruba Central access token using client credentials."""
    if not ARUBA_CLIENT_ID or not ARUBA_CLIENT_SECRET:
        return False, None, "ARUBA_CLIENT_ID and ARUBA_CLIENT_SECRET must be set"
    
    token_url = "https://sso.common.cloud.hpe.com/as/token.oauth2"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "grant_type": "client_credentials",
        "client_id": ARUBA_CLIENT_ID,
        "client_secret": ARUBA_CLIENT_SECRET
    }
    try:
        response = requests.post(token_url, headers=headers, data=data, timeout=10)
        if response.status_code == 200:
            token_data = response.json()
            new_token = token_data.get("access_token")
            if new_token:
                return True, new_token, None
            return False, None, "No access_token in response"
        return False, None, f"HTTP {response.status_code}: {response.text[:500]}"
    except Exception as e:
        return False, None, f"Exception: {str(e)}"


def get_valid_aruba_token() -> str:
    """Get a valid Aruba Central token, refreshing if necessary."""
    global ARUBA_ACCESS_TOKEN
    
    # Check if current token is valid
    if ARUBA_ACCESS_TOKEN:
        is_valid, _, message = check_token_expiration(ARUBA_ACCESS_TOKEN)
        if is_valid:
            return ARUBA_ACCESS_TOKEN
        print(f"[Token] Current token expired: {message}")
    
    # Try to refresh
    print("[Token] Attempting to refresh Aruba Central token...")
    success, new_token, error = refresh_aruba_token()
    if success:
        ARUBA_ACCESS_TOKEN = new_token
        print("[Token] Token refreshed successfully!")
        return new_token
    else:
        print(f"[Token] Token refresh failed: {error}")
        # Return the old token anyway - might still work or user needs to update manually
        return ARUBA_ACCESS_TOKEN


# ============================================================================
# AUTHENTICATION FUNCTIONS
# ============================================================================

def verify_password(username: str, password: str) -> bool:
    """Verify username and password."""
    return username == APP_USERNAME and password == APP_PASSWORD


def create_access_token() -> str:
    """Create a simple access token (in-memory session)."""
    token = secrets.token_urlsafe(32)
    active_tokens[token] = datetime.now() + timedelta(hours=24)  # 24 hour expiry
    return token


def verify_token(token: str) -> bool:
    """Verify if token is valid and not expired."""
    if token not in active_tokens:
        return False
    if datetime.now() > active_tokens[token]:
        del active_tokens[token]
        return False
    return True


async def get_current_user(request: Request, access_token: Optional[str] = Cookie(None)):
    """Dependency to get current authenticated user from cookie."""
    if not access_token or not verify_token(access_token):
        # Redirect to login for HTML requests
        if "text/html" in request.headers.get("accept", ""):
            return RedirectResponse(url="/login", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    return {"username": APP_USERNAME}


# ============================================================================
# API FUNCTIONS (extracted from original script)
# ============================================================================

def check_account_exists_aruba(email: str) -> tuple[bool, Optional[dict]]:
    """
    Check if an account with the given email/name already exists in Aruba Central.
    
    Returns:
        tuple: (exists: bool, account_data: dict or None)
    """
    token = get_valid_aruba_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "accept": "application/json"
    }
    
    try:
        response = requests.get(ARUBA_NAMED_MPSK_ENDPOINT, headers=headers, timeout=10)
        
        if response.status_code == 200:
            try:
                data = response.json()
                accounts = data
                if isinstance(data, dict):
                    accounts = data.get("items", data.get("data", data.get("results", data.get("list", []))))
                
                if isinstance(accounts, list):
                    for account in accounts:
                        account_name = (account.get("name") or account.get("email") or 
                                       account.get("identifier") or account.get("user_name"))
                        if account_name and account_name.lower() == email.lower():
                            return True, account
                
                return False, None
            except json.JSONDecodeError:
                return False, None
        else:
            return False, None
            
    except Exception as e:
        print(f"[Aruba Central] Error checking account: {str(e)}")
        return False, None


def create_account_aruba(email: str) -> tuple[bool, Optional[str], Optional[dict]]:
    """
    Create a new mPSK account in Aruba Central.
    The API will auto-generate a PSK for the account.
    
    Returns:
        tuple: (success: bool, psk: str or None, response_data: dict or None)
    """
    token = get_valid_aruba_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "accept": "application/json"
    }
    
    payload = {
        "input": {
            "enable": True,
            "name": email,
            "network": ARUBA_MPSK_NETWORK_ID,
            "passwordPolicy": "ALPHANUMERIC",
            "userRole": ARUBA_USER_ROLE
        }
    }
    
    try:
        response = requests.post(ARUBA_NAMED_MPSK_ENDPOINT, headers=headers, json=payload, timeout=10)
        
        if response.status_code in [200, 201]:
            try:
                data = response.json()
            except json.JSONDecodeError:
                return False, None, None
            
            # Extract PSK from response - look for "mpsk" field first
            psk = None
            if isinstance(data, dict):
                # First, try "mpsk" field (the actual field name from Aruba Central response)
                psk = data.get("mpsk")
                
                # If not found, try nested in "data" object
                if not psk and isinstance(data.get("data"), dict):
                    psk = data["data"].get("mpsk")
                
                # If still not found, try nested in "result" object
                if not psk and isinstance(data.get("result"), dict):
                    psk = data["result"].get("mpsk")
                
                # If still not found, try nested in "input" object
                if not psk and isinstance(data.get("input"), dict):
                    psk = data["input"].get("mpsk")
                
                # Fallback to other common field names
                if not psk:
                    psk = (data.get("psk") or data.get("passphrase") or 
                           data.get("password") or data.get("key"))
            
            if psk:
                return True, psk, data
            else:
                # Account created but PSK not found
                return True, None, data
        else:
            error_text = response.text
            print(f"[Aruba Central] Failed to create account: {response.status_code}")
            print(f"[Aruba Central] Error: {error_text}")
            return False, None, {"error": error_text, "status_code": response.status_code}
            
    except Exception as e:
        error_msg = str(e)
        print(f"[Aruba Central] Exception: {error_msg}")
        return False, None, {"error": error_msg}


def create_psk_mist(email: str, psk: str) -> tuple[bool, Optional[dict], Optional[str]]:
    """
    Create a PSK account in Juniper Mist using the PSK generated by Aruba Central.
    
    Returns:
        tuple: (success: bool, response_data: dict or None, outcome: str)
        outcome can be: "created", "already_exists", or "error"
    """
    headers = {
        "Authorization": f"Token {MIST_API_TOKEN}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "name": email,
        "ssid": SSID,
        "passphrase": psk,
        "vlan_id": VLAN_ID,
        "usage": "multi"
    }
    
    try:
        response = requests.post(MIST_PSK_ENDPOINT, headers=headers, json=payload, timeout=10)
        
        # Check for success (200-299)
        if 200 <= response.status_code < 300:
            try:
                data = response.json()
                return True, data, "created"
            except json.JSONDecodeError:
                return True, {"status": "success", "message": "Account created"}, "created"
        
        # Check for "not unique" error (400-499 with specific detail message)
        elif 400 <= response.status_code < 500:
            try:
                error_data = response.json()
                # Check if it's the "ssid+passphrase not unique" error
                detail = error_data.get("detail", "")
                if isinstance(detail, str) and "ssid+passphrase not unique" in detail.lower():
                    # Treat as success - already exists in Mist
                    return True, error_data, "already_exists"
                else:
                    # Real error
                    error_text = response.text
                    print(f"[Juniper Mist] Failed to create PSK: {response.status_code}")
                    print(f"[Juniper Mist] Error: {error_text}")
                    return False, error_data, "error"
            except json.JSONDecodeError:
                # Can't parse JSON, treat as error
                error_text = response.text
                print(f"[Juniper Mist] Failed to create PSK: {response.status_code}")
                print(f"[Juniper Mist] Error: {error_text}")
                return False, {"error": error_text, "status_code": response.status_code}, "error"
        else:
            # Other status codes (500+, etc.) - real error
            error_text = response.text
            print(f"[Juniper Mist] Failed to create PSK: {response.status_code}")
            print(f"[Juniper Mist] Error: {error_text}")
            try:
                error_data = response.json()
                return False, error_data, "error"
            except:
                return False, {"error": error_text, "status_code": response.status_code}, "error"
            
    except Exception as e:
        error_msg = str(e)
        print(f"[Juniper Mist] Exception: {error_msg}")
        return False, {"error": error_msg}, "error"


def get_psk_from_aruba_response(account_data: dict) -> Optional[str]:
    """Extract PSK from Aruba Central account data."""
    if not isinstance(account_data, dict):
        return None
    
    # Try "mpsk" field first
    psk = account_data.get("mpsk")
    if psk:
        return psk
    
    # Try nested structures
    for key in ["data", "result", "input"]:
        if isinstance(account_data.get(key), dict):
            psk = account_data[key].get("mpsk")
            if psk:
                return psk
    
    # Fallback to other field names
    psk = (account_data.get("psk") or account_data.get("passphrase") or 
           account_data.get("password") or account_data.get("key"))
    
    return psk


# ============================================================================
# ROUTES
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Main page with form."""
    # Check authentication - redirect to login if not authenticated
    access_token = request.cookies.get("access_token")
    if not access_token or not verify_token(access_token):
        return RedirectResponse(url="/login", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "result": None,
        "error": None
    })


@app.post("/", response_class=HTMLResponse)
async def process_psk(request: Request, email: str = Form(...)):
    """Process PSK creation/sync."""
    # Check authentication - redirect to login if not authenticated
    access_token = request.cookies.get("access_token")
    if not access_token or not verify_token(access_token):
        return RedirectResponse(url="/login", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    
    email = email.strip()
    
    if not email:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "result": None,
            "error": "Email cannot be empty."
        })
    
    # Step 1: Check if account exists in Aruba Central
    exists, existing_account = check_account_exists_aruba(email)
    
    result_data = {
        "email": email,
        "psk": None,
        "status": None,
        "message": None,
        "aruba_response": None,
        "mist_response": None,
        "created": False
    }
    
    if exists:
        # Account exists - extract PSK
        psk = get_psk_from_aruba_response(existing_account)
        result_data["psk"] = psk
        result_data["aruba_response"] = existing_account
        
        if not psk:
            return templates.TemplateResponse("index.html", {
                "request": request,
                "result": None,
                "error": "Account exists in Aruba Central but PSK not found in response. Cannot sync to Mist."
            })
        
        # Ensure it exists in Mist (idempotency)
        mist_success, mist_response, mist_outcome = create_psk_mist(email, psk)
        result_data["mist_response"] = mist_response
        
        # Case 1: Account exists in Aruba, Mist returns "already exists" (not unique error)
        if mist_success and mist_outcome == "already_exists":
            result_data["status"] = "exists"
            result_data["message"] = f"The account ({email}) already exists in both Aruba Central and Juniper Mist."
        # Case 3: Account exists in Aruba, Mist creation succeeds (was missing in Mist, now synced)
        elif mist_success and mist_outcome == "created":
            result_data["status"] = "success"
            result_data["message"] = f"Account already exists in Aruba Central but was successfully created in Juniper Mist."
        # Case 4: Real error from Mist
        else:
            result_data["status"] = "partial"
            error_msg = "Unknown error"
            if mist_response and isinstance(mist_response, dict):
                error_msg = mist_response.get('detail') or mist_response.get('error') or mist_response.get('message', 'Unknown error')
            result_data["message"] = f"Account exists in Aruba Central but Mist sync failed: {error_msg}"
    else:
        # Create new account
        success, psk, aruba_response = create_account_aruba(email)
        result_data["aruba_response"] = aruba_response
        
        if not success:
            error_msg = "Unknown error"
            if aruba_response:
                if isinstance(aruba_response, dict):
                    error_msg = aruba_response.get('message') or aruba_response.get('error') or aruba_response.get('errorCode', 'Unknown error')
                    # Check if it's a token error
                    if aruba_response.get('errorCode') == 'HPE_GL_NETWORKING_ERROR_UNAUTHORIZED':
                        error_msg = "Aruba Central authentication failed. The access token may be expired. The system attempted to refresh it automatically. Please check your ARUBA_TOKEN, ARUBA_CLIENT_ID, and ARUBA_CLIENT_SECRET in your .env file."
                else:
                    error_msg = str(aruba_response)
            
            return templates.TemplateResponse("index.html", {
                "request": request,
                "result": None,
                "error": f"Failed to create account in Aruba Central: {error_msg}"
            })
        
        if not psk:
            return templates.TemplateResponse("index.html", {
                "request": request,
                "result": None,
                "error": "Account created in Aruba Central but PSK not found in response. Cannot sync to Mist."
            })
        
        result_data["psk"] = psk
        result_data["created"] = True
        
        # Create in Mist
        mist_success, mist_response, mist_outcome = create_psk_mist(email, psk)
        result_data["mist_response"] = mist_response
        
        # Case 2: Account did not exist in Aruba → successfully created in Aruba and successfully created in Mist
        if mist_success and mist_outcome == "created":
            result_data["status"] = "success"
            result_data["message"] = f"Successfully created account ({email}) in Aruba Central and Juniper Mist."
        # Case 4: Real error from Mist
        else:
            result_data["status"] = "partial"
            error_msg = "Unknown error"
            if mist_response and isinstance(mist_response, dict):
                error_msg = mist_response.get('detail') or mist_response.get('error') or mist_response.get('message', 'Unknown error')
            result_data["message"] = f"Created in Aruba Central but Mist sync failed: {error_msg}"
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "result": result_data,
        "error": None
    })


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page."""
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(None), password: str = Form(None)):
    """Handle login form submission."""
    # Handle case where form data might not be present (e.g., JSON request)
    if username is None or password is None:
        # Try to get from form data
        try:
            form_data = await request.form()
            username = form_data.get("username", "")
            password = form_data.get("password", "")
        except:
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Please provide username and password"
            })
    
    if not username or not password:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Username and password are required"
        })
    
    if not verify_password(username, password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password"
        })
    
    token = create_access_token()
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="access_token", value=token, httponly=True, max_age=86400, samesite="lax")
    return response


# Cleanup expired tokens periodically (simple approach)
@app.on_event("startup")
async def startup_event():
    """Cleanup expired tokens on startup."""
    now = datetime.now()
    expired = [token for token, expiry in active_tokens.items() if now > expiry]
    for token in expired:
        del active_tokens[token]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

