import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator, model_validator
from typing import Any, Dict, List, Optional, Union
from enum import Enum
import firebase_admin
from firebase_admin import auth as firebase_auth
from db.firebase_db import db  # Ensure this is the correct Firebase DB instance

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security dependency using HTTPBearer
security = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        decoded_token = firebase_auth.verify_id_token(token)
        user_id = decoded_token.get("uid")
        if not user_id:
            raise ValueError("uid not found in token")
        return user_id
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

class FunctionScope(str, Enum):
    USER = "USER"
    GLOBAL = "GLOBAL"

class FunctionType(str, Enum):
    """HTTP method types for API functions"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class AuthType(str, Enum):
    """Authentication types supported by the function executor"""
    NONE = "none"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    OAUTH2 = "oauth2"


class ParameterLocation(str, Enum):
    """Locations where parameters can be placed in a request"""
    QUERY = "query"
    PATH = "path"
    BODY = "body"
    HEADER = "header"


class ParameterType(str, Enum):
    """Data types for parameters"""
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"


class Parameter(BaseModel):
    """Model defining a parameter for a function"""
    name: str
    type: ParameterType
    description: str = ""
    required: bool = True
    location: ParameterLocation = ParameterLocation.QUERY
    default: Optional[Any] = None
    enum_values: Optional[List[Any]] = None  # Possible values for the parameter

    @validator('default')
    def validate_default_value(cls, v, values):
        """Validate that default values match the parameter type"""
        if v is None:
            return v

        param_type = values.get('type')
        if param_type == ParameterType.STRING and not isinstance(v, str):
            raise ValueError(f"Default value for string must be a string")
        elif param_type == ParameterType.INTEGER and not isinstance(v, int):
            raise ValueError(f"Default value for integer must be an integer")
        elif param_type == ParameterType.BOOLEAN and not isinstance(v, bool):
            raise ValueError(f"Default value for boolean must be a boolean")
        return v


class ResponseMapping(BaseModel):
    """Model defining how to extract and transform API responses"""
    path: str = ""  # JSONPath or key to extract from response
    transform: Optional[str] = None  # Optional transformation script
    error_path: Optional[str] = None  # Path to error message in response


class RateLimiting(BaseModel):
    """Configuration for rate limiting function calls"""
    max_calls: int = 0  # 0 means no limit
    time_window: int = 60  # Time window in seconds
    strategy: str = "fixed"  # "fixed" or "sliding"


class AuthConfig(BaseModel):
    """Authentication configuration for API calls"""
    auth_type: AuthType = AuthType.NONE
    api_key: Optional[str] = None
    api_key_name: Optional[str] = None  # Name of the API key parameter
    api_key_location: Optional[str] = None  # "header", "query", etc.
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    oauth_config: Optional[Dict[str, str]] = None


class FunctionDefinition(BaseModel):
    name: str
    description: str
    type: FunctionType
    endpoint: str
    auth_required: bool = False
    auth_config: Optional[AuthConfig] = None
    parameters: List[Parameter] = Field(default_factory=list)
    response_mapping: Optional[ResponseMapping] = None
    rate_limiting: Optional[RateLimiting] = None
    cache_ttl: int = 0
    timeout: int = 30
    retry_config: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    function_scope: FunctionScope = FunctionScope.GLOBAL  # <-- Add this field

    @model_validator(mode='after')
    def validate_auth(self):
        if self.auth_required and (self.auth_config is None or self.auth_config.auth_type == AuthType.NONE):
            raise ValueError("Auth config required when auth_required is True")
        return self


router = APIRouter()

# @router.post("/api/functions")
# def register_function(function: FunctionDefinition, auth_token: Optional[str] = None):
#     """
#     Register a function in Firestore. 
#     - "global" functions are available to all users.
#     - "user" functions are private and tied to the user's account.
#     """
#     try:
#         function_data = function.dict()
        
#         # Validate function scope
#         if function.function_scope == FunctionScope.USER:
#             if not auth_token:
#                 raise HTTPException(status_code=401, detail="User authentication required")
#             user_id = get_current_user(auth_token)
#             function_data["owner_id"] = user_id  # Assign function to the user

#         elif function.function_scope == FunctionScope.GLOBAL:
#             function_data["owner_id"] = "global"  # Global functions are owned by the system
        
#         # Store function in Firestore
#         functions_ref = db.collection("functions")
#         new_function_ref = functions_ref.add(function_data)

#         return {"message": "Function registered successfully", "id": new_function_ref[1].id}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Error registering function: {str(e)}")

@router.post("/api/functions")
def register_function(function: FunctionDefinition, auth_token: Optional[str] = None):
    """
    Register a function in Firestore.
    - "global" functions are available to all users.
    - "user" functions are private and tied to the user's account.
    """
    try:
        function_data = function.dict()
        
        # Validate function scope and assign owner_id accordingly
        if function.function_scope == FunctionScope.USER:
            if not auth_token:
                raise HTTPException(status_code=401, detail="User authentication required")
            user_id = get_current_user(auth_token)
            function_data["owner_id"] = user_id  # Tie function to the authenticated user
        elif function.function_scope == FunctionScope.GLOBAL:
            function_data["owner_id"] = "global"  # Global functions are owned by the system

        # Store function in Firestore
        functions_ref = db.collection("functions")
        new_function_ref = functions_ref.add(function_data)
        new_function_id = new_function_ref[1].id
        logger.info(f"Function registered successfully with ID: {new_function_id}")

        return {"message": "Function registered successfully", "id": new_function_id}
    except Exception as e:
        logger.error(f"Error registering function: {e}")
        raise HTTPException(status_code=500, detail=f"Error registering function: {str(e)}")


@router.get("/api/functions")
def list_functions(auth_token: Optional[str] = None):
    try:
        owner_id = None
        if auth_token:
            # Wrap the token in a HTTPAuthorizationCredentials instance
            fake_credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=auth_token)
            owner_id = get_current_user(fake_credentials)
        
        functions_ref = db.collection("functions")
        if owner_id:
            query = functions_ref.where("owner_id", "in", [owner_id, "global"])
        else:
            query = functions_ref.where("owner_id", "==", "global")
        
        docs = query.stream()
        functions_list = []
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            functions_list.append(data)
        
        logger.info(f"Retrieved {len(functions_list)} functions from Firestore")
        return functions_list
    except Exception as e:
        logger.error(f"Error retrieving functions: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving functions: {str(e)}")

@router.get("/api/function/{function_id}")
def get_function(function_id: str, auth_token: Optional[str] = None):
    """
    Retrieve a single function from Firestore based on its document ID.
    - If auth_token is provided: returns the function if it is global or owned by the authenticated user.
    - If auth_token is not provided: returns the function only if it's global.
    """
    try:
        owner_id = None
        if auth_token:
            # Wrap token string into HTTPAuthorizationCredentials before verification
            fake_credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=auth_token)
            owner_id = get_current_user(fake_credentials)
        
        # Retrieve the function document by its ID
        function_ref = db.collection("functions").document(function_id)
        doc = function_ref.get()
        if not doc.exists:
            raise HTTPException(status_code=404, detail="Function not found")
        
        function_data = doc.to_dict()
        
        # Check access permissions: authenticated users can view their own functions or global ones.
        # Unauthenticated users can only view global functions.
        if owner_id:
            if function_data.get("owner_id") not in [owner_id, "global"]:
                raise HTTPException(status_code=403, detail="Not authorized to view this function")
        else:
            if function_data.get("owner_id") != "global":
                raise HTTPException(status_code=403, detail="Not authorized to view this function")
        
        function_data["id"] = doc.id
        return function_data

    except Exception as e:
        logger.error(f"Error retrieving function: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving function: {str(e)}")


@router.delete("/api/functions/{function_id}")
def delete_function(function_id: str, auth_token: str):
    """
    Delete a function from Firestore. Only the owner of the function can delete it,
    unless the function is global and you want to allow deletion by any user.
    """
    try:
        fake_credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=auth_token)
        user_id = get_current_user(fake_credentials)
        
        function_ref = db.collection("functions").document(function_id)
        doc = function_ref.get()
        if not doc.exists:
            raise HTTPException(status_code=404, detail="Function not found")
        
        function_data = doc.to_dict()
        owner_id = function_data.get("owner_id")
        
        # If the function is global, you might allow deletion by any authenticated user:
        if owner_id == "global":
            # Uncomment the next line if you want to restrict deletion even for global functions.
            # raise HTTPException(status_code=403, detail="Not authorized to delete a global function")
            pass
        elif owner_id != user_id:
            raise HTTPException(status_code=403, detail="Not authorized to delete this function")
        
        function_ref.delete()
        logger.info(f"Function {function_id} deleted successfully by user {user_id}")
        return {"message": "Function deleted successfully"}
    
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error deleting function: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting function: {str(e)}")


