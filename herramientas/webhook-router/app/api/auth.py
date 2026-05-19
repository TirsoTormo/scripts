import secrets
import time
from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from app.core.database import db_manager
from app.core.security import hash_password, verify_password, create_access_token, decode_token
from app.core.config import settings

router = APIRouter(tags=["Identity & Access Management"])

# ======================================================================
# PYDANTIC SCHEMAS
# ======================================================================
class SetupRequest(BaseModel):
    gateway_token: str
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = Field(default="viewer", pattern="^(admin|operator|viewer)$")

class RoleUpdateRequest(BaseModel):
    role: str = Field(pattern="^(admin|operator|viewer)$")

# ======================================================================
# ACCESS CONTROL DEPENDENCIES (RBAC)
# ======================================================================
async def get_current_user(x_session_token: Optional[str] = Header(None, alias="X-Session-Token")):
    """Dependency that authenticates the user using their session token."""
    if not x_session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token required in headers (X-Session-Token)."
        )
    
    session = await db_manager.get_session(x_session_token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or active session token not found."
        )
    
    # Check session expiration
    if session["expires_at"] < time.time():
        await db_manager.delete_session(x_session_token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired. Please log in again."
        )
        
    user = await db_manager.get_user(session["username"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with this session no longer exists."
        )
        
    return user

class RoleChecker:
    """Dependency that restricts endpoints based on user privileges."""
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: dict = Depends(get_current_user)):
        if current_user["role"] not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Insufficient role permissions."
            )
        return current_user

# Pre-defined dependencies for route gating
require_admin = Depends(RoleChecker(["admin"]))
require_operator = Depends(RoleChecker(["admin", "operator"]))
require_viewer = Depends(RoleChecker(["admin", "operator", "viewer"]))

# ======================================================================
# CONTROLLERS
# ======================================================================
@router.get("/api/auth/status", status_code=status.HTTP_200_OK)
async def check_setup_status():
    """Checks if the system has been initialized (admin user created)."""
    has_users = await db_manager.has_users()
    return {"initialized": has_users}

@router.post("/api/auth/setup", status_code=status.HTTP_200_OK)
async def setup_first_user(payload: SetupRequest):
    """Initializes the database admin user during first-time gateway launch."""
    # Prevent setup if user directory already exists
    if await db_manager.has_users():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Forbidden: The gateway has already been initialized."
        )
    
    # Authenticate setup request using master gateway token
    if not secrets.compare_digest(payload.gateway_token, settings.GATEWAY_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid master gateway token."
        )
        
    hashed_pwd = hash_password(payload.password)
    success = await db_manager.create_user(
        username=payload.username,
        password_hash=hashed_pwd,
        role="admin"
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register admin profile."
        )
        
    return {"status": "success", "message": "Gateway initialized successfully. Admin user registered."}

@router.post("/api/auth/login", status_code=status.HTTP_200_OK)
async def login(payload: LoginRequest):
    """Authenticates username/password and provisions an active session token."""
    user = await db_manager.get_user(payload.username)
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials."
        )
        
    # Generate a cryptographically secure session token
    session_token = secrets.token_hex(32)
    # Session lifespan: 24 hours
    expires_at = time.time() + (24 * 3600)
    
    success = await db_manager.create_session(
        token=session_token,
        username=user["username"],
        expires_at=expires_at
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record session state."
        )
        
    return {
        "status": "success",
        "session_token": session_token,
        "username": user["username"],
        "role": user["role"]
    }

@router.post("/api/auth/logout", status_code=status.HTTP_200_OK)
async def logout(x_session_token: Optional[str] = Header(None, alias="X-Session-Token")):
    """Revokes active user session."""
    if x_session_token:
        await db_manager.delete_session(x_session_token)
    return {"status": "success", "message": "Logged out successfully."}

@router.get("/api/auth/me", status_code=status.HTTP_200_OK)
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    """Returns the authenticated user details."""
    return {
        "username": current_user["username"],
        "role": current_user["role"]
    }

# ======================================================================
# USER DIRECTORY MANAGEMENT (ADMIN ONLY)
# ======================================================================
@router.post("/api/auth/users", status_code=status.HTTP_200_OK, dependencies=[require_admin])
async def register_new_user(payload: UserCreateRequest):
    """Admin Endpoint: Registers a new user into the gateway database."""
    # Check if username exists
    existing = await db_manager.get_user(payload.username)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{payload.username}' is already registered."
        )
        
    hashed_pwd = hash_password(payload.password)
    success = await db_manager.create_user(
        username=payload.username,
        password_hash=hashed_pwd,
        role=payload.role
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist user profile."
        )
        
    return {"status": "success", "message": f"User '{payload.username}' registered as '{payload.role}'."}

@router.get("/api/auth/users", status_code=status.HTTP_200_OK, dependencies=[require_admin])
async def list_registered_users():
    """Admin Endpoint: Lists all registered users (excluding hashes)."""
    users = await db_manager.get_all_users()
    return users

@router.put("/api/auth/users/{username}/role", status_code=status.HTTP_200_OK, dependencies=[require_admin])
async def change_user_role(username: str, payload: RoleUpdateRequest):
    """Admin Endpoint: Promotes or demotes user role privileges."""
    target_user = await db_manager.get_user(username)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found."
        )
        
    success = await db_manager.update_user_role(username, payload.role)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update database record."
        )
        
    return {"status": "success", "message": f"User '{username}' role changed to '{payload.role}'."}
