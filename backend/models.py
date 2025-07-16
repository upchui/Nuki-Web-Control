from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

# User Models
class UserBase(BaseModel):
    username: str

class UserCreate(BaseModel):
    username: str
    password: str
    is_admin: Optional[bool] = False

class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    is_admin: Optional[bool] = None

class UserResponse(BaseModel):
    id: int
    username: str
    is_admin: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# Permission Models
class SmartlockPermission(BaseModel):
    smartlock_id: int
    can_view: bool = True

class AuthPermissions(BaseModel):
    can_create_auth: bool = False
    can_edit_auth: bool = False
    can_delete_auth: bool = False

class SpecificAuthAccess(BaseModel):
    auth_id: str
    can_edit: bool = False
    can_delete: bool = False
    can_not_edit: bool = False

class UserPermissions(BaseModel):
    smartlock_permissions: List[SmartlockPermission] = []
    auth_permissions: AuthPermissions
    specific_auth_access: List[SpecificAuthAccess] = []

class UserPermissionsUpdate(BaseModel):
    smartlock_permissions: Optional[List[SmartlockPermission]] = None
    auth_permissions: Optional[AuthPermissions] = None
    specific_auth_access: Optional[List[SpecificAuthAccess]] = None

# Response Models
class UserWithPermissions(BaseModel):
    user: UserResponse
    permissions: UserPermissions
    
    class Config:
        from_attributes = True

class AdminStatusUpdate(BaseModel):
    is_admin: bool

# Current User Info
class CurrentUserInfo(BaseModel):
    username: str
    is_admin: bool
    permissions: UserPermissions
