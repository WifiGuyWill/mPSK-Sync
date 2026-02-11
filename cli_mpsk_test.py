#!/usr/bin/env python3
"""
Script to test integration between Aruba Central and Juniper Mist APIs
for creating mPSK/PSK accounts.

This script:
1. Checks if an account exists in Aruba Central (by email/name)
2. If not exists, creates it in Aruba Central (which auto-generates a PSK)
3. Creates the PSK account in Juniper Mist using the generated PSK
"""

import os
import requests
import json
import sys
import base64
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ============================================================================
# CONFIGURABLE PARAMETERS (from environment variables)
# ============================================================================

# Aruba Central Configuration
ARUBA_BASE_URL = os.getenv("ARUBA_BASE_URL", "https://internal.api.central.arubanetworks.com")
ARUBA_ACCESS_TOKEN = os.getenv("ARUBA_TOKEN", "")
ARUBA_CLIENT_ID = os.getenv("ARUBA_CLIENT_ID", "")
ARUBA_CLIENT_SECRET = os.getenv("ARUBA_CLIENT_SECRET", "")
ARUBA_MPSK_NETWORK_ID = os.getenv("ARUBA_MPSK_NETWORK_ID", "mPSK")
ARUBA_USER_ROLE = os.getenv("ARUBA_USER_ROLE", "mPSK")

# Juniper Mist Configuration
MIST_BASE_URL = os.getenv("MIST_BASE_URL", "https://api.ac2.mist.com")
MIST_API_TOKEN = os.getenv("MIST_TOKEN", "")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "")

# Network Configuration
SSID = os.getenv("SSID", "mPSK")
VLAN_ID = int(os.getenv("VLAN_ID", "1"))  # Integer, not string - Mist API expects integer

# ============================================================================
# API ENDPOINTS
# ============================================================================

ARUBA_NAMED_MPSK_ENDPOINT = f"{ARUBA_BASE_URL}/network-config/v1alpha1/cnac-named-mpsk-reg"
MIST_PSK_ENDPOINT = f"{MIST_BASE_URL}/api/v1/orgs/{MIST_ORG_ID}/psks"


# ============================================================================
# TOKEN MANAGEMENT FUNCTIONS
# ============================================================================

def decode_jwt_token(token):
    """
    Decode a JWT token to extract payload information (without verification).
    
    Args:
        token: JWT token string
    
    Returns:
        dict: Decoded token payload or None if decoding fails
    """
    try:
        # JWT tokens have 3 parts separated by dots: header.payload.signature
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        # Decode the payload (second part)
        payload = parts[1]
        # Add padding if needed
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        print(f"[Token] Error decoding token: {str(e)}")
        return None


def check_token_expiration(token):
    """
    Check if a JWT token is expired.
    
    Args:
        token: JWT token string
    
    Returns:
        tuple: (is_valid: bool, expires_at: datetime or None, message: str)
    """
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


def refresh_aruba_token():
    """
    Refresh the Aruba Central access token using client credentials.
    Note: Aruba Central tokens are valid for 2 hours. This attempts to get a new token.
    
    Returns:
        tuple: (success: bool, new_token: str or None, error_message: str or None)
    """
    # Try the common OAuth2 token endpoint
    # Note: The actual endpoint may vary based on your Aruba Central setup
    token_url = "https://sso.common.cloud.hpe.com/as/token.oauth2"
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    data = {
        "grant_type": "client_credentials",
        "client_id": ARUBA_CLIENT_ID,
        "client_secret": ARUBA_CLIENT_SECRET
    }
    
    try:
        print(f"\n[Aruba Central] Attempting to refresh access token...")
        print(f"[Aruba Central] Using endpoint: {token_url}")
        response = requests.post(token_url, headers=headers, data=data, timeout=10)
        
        print(f"[Aruba Central] Token refresh response status: {response.status_code}")
        
        if response.status_code == 200:
            try:
                token_data = response.json()
                new_token = token_data.get("access_token")
                if new_token:
                    print(f"[Aruba Central] Token refreshed successfully!")
                    # Check expiration of new token
                    is_valid, expires_at, msg = check_token_expiration(new_token)
                    print(f"[Aruba Central] New token: {msg}")
                    return True, new_token, None
                else:
                    return False, None, f"No access_token in response. Response: {token_data}"
            except json.JSONDecodeError:
                return False, None, f"Response is not JSON: {response.text[:200]}"
        else:
            error_msg = f"HTTP {response.status_code}: {response.text[:500]}"
            print(f"[Aruba Central] Token refresh failed: {error_msg}")
            print(f"\n[Aruba Central] Manual token refresh instructions:")
            print(f"  1. Visit: https://developer.arubanetworks.com/new-central/docs/generating-and-managing-access-tokens")
            print(f"  2. Use your Client ID: {ARUBA_CLIENT_ID}")
            print(f"  3. Generate a new access token")
            print(f"  4. Update ARUBA_ACCESS_TOKEN in this script")
            return False, None, error_msg
            
    except requests.exceptions.Timeout:
        error_msg = "Token refresh request timed out"
        print(f"[Aruba Central] {error_msg}")
        return False, None, error_msg
    except Exception as e:
        error_msg = f"Exception during token refresh: {str(e)}"
        print(f"[Aruba Central] {error_msg}")
        return False, None, error_msg


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def check_account_exists_aruba(email, token=None):
    """
    Check if an account with the given email/name already exists in Aruba Central.
    
    Args:
        email: The email address to check (used as account name/identifier)
        token: Optional token to use (defaults to ARUBA_ACCESS_TOKEN)
    
    Returns:
        tuple: (exists: bool, response_data: dict or None)
    """
    if token is None:
        token = ARUBA_ACCESS_TOKEN
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "accept": "application/json"
    }
    
    try:
        print(f"\n[Aruba Central] Checking if account '{email}' exists...")
        
        # Try with query parameter to filter by name if API supports it
        # Also try without query params as fallback
        params = {"name": email} if ARUBA_MPSK_NETWORK_ID else {}
        
        response = requests.get(ARUBA_NAMED_MPSK_ENDPOINT, headers=headers, params=params)
        
        print(f"[Aruba Central] Response Status: {response.status_code}")
        print(f"[Aruba Central] Request URL: {response.url}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"[Aruba Central] Response: {json.dumps(data, indent=2)}")
                
                # Check if the email exists in the list of accounts
                # The response might be a list or an object with a list property
                accounts = data
                if isinstance(data, dict):
                    # Try common property names that might contain the list
                    accounts = data.get("items", data.get("data", data.get("results", data.get("list", []))))
                
                if isinstance(accounts, list):
                    for account in accounts:
                        # Check various possible field names for the account name/identifier
                        account_name = (account.get("name") or account.get("email") or 
                                       account.get("identifier") or account.get("user_name"))
                        if account_name and account_name.lower() == email.lower():
                            print(f"[Aruba Central] Account '{email}' found!")
                            return True, account
                
                print(f"[Aruba Central] Account '{email}' not found in existing accounts.")
                return False, None
            except json.JSONDecodeError:
                # Response might not be JSON
                print(f"[Aruba Central] Response is not JSON: {response.text[:200]}")
                return False, None
        elif response.status_code == 401:
            # 401 Unauthorized - token issue
            print(f"[Aruba Central] Authentication failed (401) - Token may be expired or invalid")
            print(f"[Aruba Central] Response: {response.text}")
            return False, None
        elif response.status_code == 403:
            # 403 Forbidden - token may be valid but lacks permissions
            print(f"[Aruba Central] Access forbidden (403) - Token may lack required permissions")
            print(f"[Aruba Central] Response: {response.text}")
            return False, None
        elif response.status_code == 404:
            # 404 might mean endpoint doesn't exist or no accounts found
            print(f"[Aruba Central] No accounts found or endpoint not found (404)")
            return False, None
        else:
            print(f"[Aruba Central] Error checking account: {response.status_code}")
            print(f"[Aruba Central] Response: {response.text}")
            return False, None
            
    except requests.exceptions.RequestException as e:
        print(f"[Aruba Central] Request exception: {str(e)}")
        return False, None
    except Exception as e:
        print(f"[Aruba Central] Unexpected error: {str(e)}")
        return False, None


def create_account_aruba(email, token=None):
    """
    Create a new mPSK account in Aruba Central.
    The API will auto-generate a PSK for the account.
    
    Args:
        email: The email address to use as the account name/identifier
        token: Optional token to use (defaults to ARUBA_ACCESS_TOKEN)
    
    Returns:
        tuple: (success: bool, psk: str or None, response_data: dict or None)
    """
    if token is None:
        token = ARUBA_ACCESS_TOKEN
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "accept": "application/json"
    }
    
    # Request body - based on working curl command structure
    # The API requires the payload to be wrapped in an "input" object
    payload = {
        "input": {
            "enable": True,
            "name": email,
            "network": ARUBA_MPSK_NETWORK_ID if ARUBA_MPSK_NETWORK_ID != "placeholder_value" else "mPSK",
            "passwordPolicy": "ALPHANUMERIC",
            "userRole": ARUBA_USER_ROLE
        }
    }
    
    try:
        print(f"\n[Aruba Central] Creating account '{email}' with role '{ARUBA_USER_ROLE}'...")
        print(f"[Aruba Central] Payload: {json.dumps(payload, indent=2)}")
        
        response = requests.post(ARUBA_NAMED_MPSK_ENDPOINT, headers=headers, json=payload)
        
        print(f"[Aruba Central] Response Status: {response.status_code}")
        print(f"[Aruba Central] Request URL: {response.url}")
        print(f"[Aruba Central] Response: {response.text}")
        
        if response.status_code in [200, 201]:
            try:
                data = response.json()
            except json.JSONDecodeError:
                print(f"[Aruba Central] Response is not JSON: {response.text[:200]}")
                return False, None, None
            
            # Extract PSK from response - look for "mpsk" field first (as specified by user)
            # Then try other common field names as fallback
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
                
                # Fallback to other common field names if "mpsk" not found
                if not psk:
                    psk = (data.get("psk") or data.get("passphrase") or 
                           data.get("password") or data.get("key") or
                           data.get("wlan_passphrase") or data.get("wpa_key"))
                    
                    # Try nested structures for fallback fields
                    if not psk and isinstance(data.get("data"), dict):
                        psk = (data["data"].get("psk") or data["data"].get("passphrase") or 
                               data["data"].get("password") or data["data"].get("key"))
                    
                    if not psk and isinstance(data.get("result"), dict):
                        psk = (data["result"].get("psk") or data["result"].get("passphrase") or 
                               data["result"].get("password") or data["result"].get("key"))
                    
                    if not psk and isinstance(data.get("input"), dict):
                        psk = (data["input"].get("psk") or data["input"].get("passphrase") or 
                               data["input"].get("password") or data["input"].get("key"))
            
            if psk:
                print(f"[Aruba Central] Account created successfully!")
                print(f"[Aruba Central] Generated PSK: {psk}")
                return True, psk, data
            else:
                print(f"[Aruba Central] Account created but PSK not found in response.")
                print(f"[Aruba Central] Full response: {json.dumps(data, indent=2)}")
                # Still return success=True since account was created, even if PSK extraction failed
                return True, None, data
        elif response.status_code == 400:
            # 400 Bad Request - detailed error handling
            print(f"\n[Aruba Central] Bad Request (400) - Request format may be incorrect")
            print(f"[Aruba Central] Common causes:")
            print(f"  - Missing required fields")
            print(f"  - Incorrect field names or data types")
            print(f"  - mpsk_id may need to be in URL path or query params")
            print(f"  - Endpoint may require different structure")
            
            # Try to extract detailed error information
            try:
                error_data = response.json()
                if isinstance(error_data, dict):
                    # Look for validation errors or field-specific errors
                    validation_errors = error_data.get("errors") or error_data.get("validation_errors")
                    if validation_errors:
                        print(f"\n[Aruba Central] Validation errors:")
                        print(f"{json.dumps(validation_errors, indent=2)}")
                    
                    # Check for field-specific messages
                    for key in ["message", "error", "detail", "error_description"]:
                        if key in error_data:
                            print(f"\n[Aruba Central] {key}: {error_data[key]}")
            except:
                pass
            
            print(f"\n[Aruba Central] Full error response:")
            print(f"{response.text}")
            return False, None, None
        elif response.status_code == 401:
            # 401 Unauthorized - token issue
            print(f"[Aruba Central] Authentication failed (401) - Token may be expired or invalid")
            print(f"[Aruba Central] Response: {response.text}")
            return False, None, None
        elif response.status_code == 403:
            # 403 Forbidden - token may be valid but lacks permissions
            print(f"[Aruba Central] Access forbidden (403) - Token may lack required permissions")
            print(f"[Aruba Central] Response: {response.text}")
            return False, None, None
        else:
            print(f"[Aruba Central] Failed to create account: {response.status_code}")
            print(f"[Aruba Central] Error response: {response.text}")
            return False, None, None
            
    except requests.exceptions.RequestException as e:
        print(f"[Aruba Central] Request exception: {str(e)}")
        return False, None, None
    except json.JSONDecodeError as e:
        print(f"[Aruba Central] JSON decode error: {str(e)}")
        print(f"[Aruba Central] Response text: {response.text}")
        return False, None, None


def create_psk_mist(email, psk, ssid, vlan_id):
    """
    Create a PSK account in Juniper Mist using the PSK generated by Aruba Central.
    
    Args:
        email: The email address to use as the account name
        psk: The PSK/passphrase generated by Aruba Central
        ssid: The SSID name
        vlan_id: The VLAN ID
    
    Returns:
        tuple: (success: bool, response_data: dict or None)
    """
    headers = {
        "Authorization": f"Token {MIST_API_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # Request body - adjust fields based on actual API requirements
    # Ensure vlan_id is an integer
    vlan_id_int = int(vlan_id) if isinstance(vlan_id, str) else vlan_id
    
    payload = {
        "name": email,
        "ssid": ssid,
        "passphrase": psk,
        "vlan_id": vlan_id_int,
        "usage": "multi"
    }
    
    # Some Mist API versions might need different field names
    # Alternative: payload["vlan"] = vlan_id_int
    
    try:
        print(f"\n[Juniper Mist] Creating PSK account '{email}'...")
        print(f"[Juniper Mist] Payload: {json.dumps(payload, indent=2)}")
        
        response = requests.post(MIST_PSK_ENDPOINT, headers=headers, json=payload)
        
        print(f"[Juniper Mist] Response Status: {response.status_code}")
        print(f"[Juniper Mist] Response: {response.text}")
        
        if response.status_code in [200, 201]:
            try:
                data = response.json()
                print(f"[Juniper Mist] PSK account created successfully!")
                return True, data
            except json.JSONDecodeError:
                # Some APIs return empty body on success
                print(f"[Juniper Mist] PSK account created successfully! (No JSON response)")
                return True, {"status": "success", "message": "Account created"}
        else:
            print(f"[Juniper Mist] Failed to create PSK account: {response.status_code}")
            print(f"[Juniper Mist] Error response: {response.text}")
            
            # Try to parse error message for better debugging
            try:
                error_data = response.json()
                if isinstance(error_data, dict):
                    error_msg = error_data.get("detail") or error_data.get("message") or error_data.get("error")
                    if error_msg:
                        print(f"[Juniper Mist] Error detail: {error_msg}")
            except:
                pass
            
            return False, None
            
    except requests.exceptions.RequestException as e:
        print(f"[Juniper Mist] Request exception: {str(e)}")
        return False, None
    except json.JSONDecodeError as e:
        print(f"[Juniper Mist] JSON decode error: {str(e)}")
        if 'response' in locals():
            print(f"[Juniper Mist] Response text: {response.text}")
        return False, None
    except Exception as e:
        print(f"[Juniper Mist] Unexpected error: {str(e)}")
        return False, None


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """
    Main function to orchestrate the mPSK account creation process.
    """
    print("=" * 70)
    print("Aruba Central & Juniper Mist mPSK Integration Test")
    print("=" * 70)
    
    # Validate required environment variables
    required_vars = {
        "ARUBA_TOKEN": ARUBA_ACCESS_TOKEN,
        "ARUBA_CLIENT_ID": ARUBA_CLIENT_ID,
        "ARUBA_CLIENT_SECRET": ARUBA_CLIENT_SECRET,
        "MIST_TOKEN": MIST_API_TOKEN,
        "MIST_ORG_ID": MIST_ORG_ID
    }
    
    missing_vars = [var for var, value in required_vars.items() if not value]
    if missing_vars:
        print("\n[ERROR] Missing required environment variables:")
        for var in missing_vars:
            print(f"  - {var}")
        print("\nPlease create a .env file with these variables.")
        print("See .env.example for a template.")
        sys.exit(1)
    
    # Check token expiration before proceeding
    print("\n[Token Validation] Checking Aruba Central token...")
    is_valid, expires_at, message = check_token_expiration(ARUBA_ACCESS_TOKEN)
    print(f"[Token Validation] {message}")
    
    # Use a variable to hold the active token (may be refreshed)
    active_token = ARUBA_ACCESS_TOKEN
    
    if not is_valid:
        print(f"\n[Token Validation] WARNING: Token is expired or invalid!")
        print(f"[Token Validation] Attempting to refresh token...")
        
        success, new_token, error = refresh_aruba_token()
        if success:
            print(f"[Token Validation] Token refreshed successfully! Using new token for this session.")
            active_token = new_token
            # Also show the token for manual update
            print(f"\n[Token Validation] To update script permanently, set ARUBA_ACCESS_TOKEN to:")
            print(f"[Token Validation] {new_token}")
        else:
            print(f"[Token Validation] Token refresh failed: {error}")
            print(f"[Token Validation] Please manually refresh your token and update ARUBA_ACCESS_TOKEN")
            print(f"[Token Validation] See: https://developer.arubanetworks.com/new-central/docs/generating-and-managing-access-tokens")
            response = input("\nContinue anyway with expired token? (y/n): ").strip().lower()
            if response != 'y':
                print("Exiting...")
                sys.exit(1)
    
    # Get user input
    print("\nPlease provide the following information:")
    email = input("Account Email (unique identifier): ").strip()
    if not email:
        print("Error: Email cannot be empty.")
        sys.exit(1)
    
    print(f"\nConfiguration:")
    print(f"  Email: {email}")
    print(f"  Role: {ARUBA_USER_ROLE} (configured)")
    print(f"  SSID: {SSID}")
    print(f"  VLAN ID: {VLAN_ID}")
    print(f"  Aruba MPSK Network ID: {ARUBA_MPSK_NETWORK_ID}")
    print(f"  Mist Org ID: {MIST_ORG_ID}")
    
    # Step 1: Check if account exists in Aruba Central
    exists, existing_account = check_account_exists_aruba(email, token=active_token)
    
    if exists:
        print(f"\n{'=' * 70}")
        print("RESULT: Account already exists in Aruba Central.")
        print(f"{'=' * 70}")
        if existing_account:
            print(f"Existing account details: {json.dumps(existing_account, indent=2)}")
        return
    
    # Step 2: Create account in Aruba Central
    success, psk, aruba_response = create_account_aruba(email, token=active_token)
    
    if not success:
        print(f"\n{'=' * 70}")
        print("RESULT: Failed to create account in Aruba Central.")
        print(f"{'=' * 70}")
        return
    
    if not psk:
        print(f"\n{'=' * 70}")
        print("RESULT: Account created in Aruba Central but PSK not found in response.")
        print("Cannot proceed to create Mist PSK without the generated PSK.")
        print(f"{'=' * 70}")
        if aruba_response:
            print(f"\nAruba Central response for manual inspection:")
            print(json.dumps(aruba_response, indent=2))
        return
    
    # Step 3: Create PSK in Juniper Mist
    mist_success, mist_response = create_psk_mist(email, psk, SSID, VLAN_ID)
    
    # Final summary
    print(f"\n{'=' * 70}")
    if mist_success:
        print("RESULT: SUCCESS - Account created in both Aruba Central and Juniper Mist!")
    else:
        print("RESULT: PARTIAL SUCCESS - Account created in Aruba Central but failed in Juniper Mist.")
    print(f"{'=' * 70}")
    
    if mist_response:
        print(f"\nJuniper Mist response:")
        print(json.dumps(mist_response, indent=2))


if __name__ == "__main__":
    main()

