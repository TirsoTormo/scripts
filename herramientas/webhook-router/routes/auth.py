import secrets
from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from database import db_manager, hash_password, verify_password
from config import settings

router = APIRouter(prefix="/api/auth", tags=["Authentication & RBAC"])

# ======================================================================
# PYDANTIC SCHEMAS
# ======================================================================
class SetupRequest(BaseModel):
    gateway_token: str = Field(..., description="Master gateway token to verify ownership")
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)

class LoginRequest(BaseModel):
    username: str = Field(...)
    password: str = Field(...)

class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    role: str = Field("viewer", description="viewer, operator, or admin")

class RoleUpdateRequest(BaseModel):
    role: str = Field(..., description="viewer, operator, or admin")

class PasswordUpdateRequest(BaseModel):
    password: str = Field(..., min_length=6)

# ======================================================================
# FASTAPI SECURITY DEPENDENCIES (RBAC)
# ======================================================================
def get_current_user(x_session_token: Optional[str] = Header(None)):
    """Verifies session token from header and yields current authenticated user details."""
    if not x_session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing session token. Please authenticate."
        )
    session = db_manager.get_session(x_session_token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or is invalid. Please sign in again."
        )
    return session

class RoleChecker:
    """Class-based dependency to gate active endpoints by specific role credentials."""
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = [r.lower() for r in allowed_roles]

    def __call__(self, current_user = Depends(get_current_user)):
        user_role = current_user.get("role", "viewer").lower()
        if user_role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied. Required rank: {self.allowed_roles}. Your rank: {user_role}."
            )
        return current_user

# Helper roles dependencies
require_admin = Depends(RoleChecker(["admin"]))
require_operator = Depends(RoleChecker(["admin", "operator"]))
require_viewer = Depends(RoleChecker(["admin", "operator", "viewer"]))

# ======================================================================
# API ROUTE HANDLERS
# ======================================================================
@router.get("/status")
def get_auth_status():
    """Checks if the system has been initialized with at least one administrator user."""
    return {"initialized": db_manager.has_users()}

@router.post("/setup")
def perform_first_run_setup(req: SetupRequest):
    """Initializes the gateway and registers the first Administrator user."""
    if db_manager.has_users():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CodeTir Gateway is already initialized."
        )
    
    # Verify master gateway token
    if req.gateway_token != settings.GATEWAY_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid master Gateway Token. Setup verification failed."
        )
    
    # Hash password and create initial Admin
    p_hash = hash_password(req.password)
    success = db_manager.create_user(req.username, p_hash, "admin")
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register administrator account."
        )
        
    return {"message": "CodeTir Gateway initialized successfully! You can now sign in."}

@router.post("/login")
def login_session(req: LoginRequest):
    """Authenticates credentials and returns a secure session token."""
    user = db_manager.get_user(req.username)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password credentials."
        )
    
    # Generate secure 32-byte hexadecimal session token
    session_token = secrets.token_hex(32)
    # Expires in 24 hours (86400 seconds)
    db_manager.create_session(session_token, user["username"], 86400)
    
    return {
        "session_token": session_token,
        "username": user["username"],
        "role": user["role"]
    }

@router.post("/logout")
def logout_session(x_session_token: Optional[str] = Header(None)):
    """Terminates active session token."""
    if x_session_token:
        db_manager.delete_session(x_session_token)
    return {"message": "Logged out successfully."}

@router.get("/me")
def get_current_user_profile(current_user = Depends(get_current_user)):
    """Returns profile context for currently authenticated session."""
    return {
        "username": current_user["username"],
        "role": current_user["role"]
    }

# ======================================================================
# ADMIN USER REGISTRY ACTIONS (REQUIRES ADMIN ROLE)
# ======================================================================
@router.get("/users", dependencies=[require_admin])
def list_registered_users():
    """Lists all users registered in the cluster."""
    return db_manager.get_all_users()

@router.post("/users", dependencies=[require_admin])
def register_new_user(req: UserCreateRequest):
    """Registers a new administrative or operational user."""
    # Ensure role is valid
    role = req.role.lower().strip()
    if role not in ["admin", "operator", "viewer"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be: admin, operator, or viewer."
        )
        
    # Check if user already exists
    if db_manager.get_user(req.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{req.username}' is already registered."
        )
        
    p_hash = hash_password(req.password)
    success = db_manager.create_user(req.username, p_hash, role)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record user into database registry."
        )
        
    return {"message": f"Successfully registered user '{req.username}' as '{role}'."}

@router.put("/users/{username}/role", dependencies=[require_admin])
def change_user_rank(username: str, req: RoleUpdateRequest, current_user = Depends(get_current_user)):
    """Updates the authorization role for a given user."""
    username = username.lower().strip()
    role = req.role.lower().strip()
    
    if role not in ["admin", "operator", "viewer"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be: admin, operator, or viewer."
        )
        
    user = db_manager.get_user(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found."
        )
        
    # Prevent self-downgrading
    if username == current_user["username"].lower() and role != "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot downgrade your own administrator rank."
        )
        
    db_manager.update_user_role(username, role)
    return {"message": f"User '{username}' role changed to '{role}'."}

@router.put("/users/{username}/password")
def change_user_pass(username: str, req: PasswordUpdateRequest, current_user = Depends(get_current_user)):
    """Changes password. Users can change their own password, admins can change any password."""
    username = username.lower().strip()
    
    # Check authorization
    if current_user["role"].lower() != "admin" and current_user["username"].lower() != username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to update passwords for other users."
        )
        
    user = db_manager.get_user(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found."
        )
        
    p_hash = hash_password(req.password)
    db_manager.update_user_password(username, p_hash)
    return {"message": f"Successfully updated password for '{username}'."}

@router.delete("/users/{username}", dependencies=[require_admin])
def delete_user_account(username: str, current_user = Depends(get_current_user)):
    """Removes a user account and invalidates all their active login sessions."""
    username = username.lower().strip()
    
    user = db_manager.get_user(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found."
        )
        
    # Prevent deleting oneself
    if username == current_user["username"].lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own logged-in administrator account."
        )
        
    db_manager.delete_user(username)
    return {"message": f"Successfully deleted user account '{username}'."}
