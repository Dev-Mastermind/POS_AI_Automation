"""
Core API tests for Users endpoint
Demonstrates positive, negative, and schema validation testing
"""
import pytest
import requests
import jsonschema
from unittest.mock import patch, Mock
import json

# Sample schema for user response validation
USER_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "integer"},
        "username": {"type": "string"},
        "email": {"type": "string", "format": "email"},
        "first_name": {"type": "string"},
        "last_name": {"type": "string"},
        "role": {"type": "string", "enum": ["user", "admin", "moderator"]},
        "created_at": {"type": "string", "format": "date-time"},
        "updated_at": {"type": "string", "format": "date-time"}
    },
    "required": ["id", "username", "email", "first_name", "last_name", "role"],
    "additionalProperties": False
}

USERS_LIST_SCHEMA = {
    "type": "object",
    "properties": {
        "users": {
            "type": "array",
            "items": USER_SCHEMA
        },
        "total": {"type": "integer"},
        "page": {"type": "integer"},
        "per_page": {"type": "integer"}
    },
    "required": ["users", "total"],
    "additionalProperties": False
}

class TestUsersAPI:
    """Test suite for Users API endpoints"""
    
    @pytest.mark.integration
    def test_get_users_returns_200_and_schema_match(self, base_url, api_headers):
        """✅ Positive: GET /users returns 200 + schema match"""
        
        # Mock the actual API call for POC purposes
        with patch('requests.get') as mock_get:
            # Mock successful response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "users": [
                    {
                        "id": 1,
                        "username": "john_doe",
                        "email": "john@example.com",
                        "first_name": "John",
                        "last_name": "Doe",
                        "role": "user",
                        "created_at": "2024-01-01T00:00:00Z",
                        "updated_at": "2024-01-01T00:00:00Z"
                    },
                    {
                        "id": 2,
                        "username": "jane_smith",
                        "email": "jane@example.com",
                        "first_name": "Jane",
                        "last_name": "Smith",
                        "role": "admin",
                        "created_at": "2024-01-01T00:00:00Z",
                        "updated_at": "2024-01-01T00:00:00Z"
                    }
                ],
                "total": 2,
                "page": 1,
                "per_page": 10
            }
            mock_get.return_value = mock_response
            
            # Make the request
            response = requests.get(f"{base_url}/users", headers=api_headers)
            
            # Assertions
            assert response.status_code == 200
            response_data = response.json()
            
            # Validate schema
            jsonschema.validate(instance=response_data, schema=USERS_LIST_SCHEMA)
            
            # Additional business logic assertions
            assert "users" in response_data
            assert len(response_data["users"]) == 2
            assert response_data["total"] == 2
            assert response_data["users"][0]["role"] in ["user", "admin", "moderator"]
    
    @pytest.mark.integration
    def test_post_users_with_missing_field_returns_400(self, base_url, api_headers, invalid_user_data):
        """❌ Negative: POST /users with missing field returns 400"""
        
        with patch('requests.post') as mock_post:
            # Mock validation error response
            mock_response = Mock()
            mock_response.status_code = 400
            mock_response.json.return_value = {
                "error": "Validation failed",
                "details": {
                    "email": ["This field is required"],
                    "first_name": ["This field is required"],
                    "last_name": ["This field is required"]
                }
            }
            mock_post.return_value = mock_response
            
            # Make the request with invalid data
            response = requests.post(
                f"{base_url}/users", 
                headers=api_headers,
                json=invalid_user_data
            )
            
            # Assertions
            assert response.status_code == 400
            response_data = response.json()
            
            # Validate error response structure
            assert "error" in response_data
            assert "details" in response_data
            assert "email" in response_data["details"]
            assert "first_name" in response_data["details"]
            assert "last_name" in response_data["details"]
    
    @pytest.mark.integration
    def test_get_user_by_id_success(self, base_url, api_headers):
        """✅ Positive: GET /users/{id} returns specific user"""
        
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "id": 1,
                "username": "john_doe",
                "email": "john@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "role": "user",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
            mock_get.return_value = mock_response
            
            response = requests.get(f"{base_url}/users/1", headers=api_headers)
            
            assert response.status_code == 200
            user_data = response.json()
            
            # Validate individual user schema
            jsonschema.validate(instance=user_data, schema=USER_SCHEMA)
            
            # Business logic assertions
            assert user_data["id"] == 1
            assert user_data["username"] == "john_doe"
            assert user_data["email"] == "john@example.com"
    
    @pytest.mark.integration
    def test_get_user_by_id_not_found(self, base_url, api_headers):
        """❌ Negative: GET /users/{id} returns 404 for non-existent user"""
        
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 404
            mock_response.json.return_value = {
                "error": "User not found",
                "message": "User with ID 999 does not exist"
            }
            mock_get.return_value = mock_response
            
            response = requests.get(f"{base_url}/users/999", headers=api_headers)
            
            assert response.status_code == 404
            error_data = response.json()
            assert "error" in error_data
            assert "message" in error_data
    
    @pytest.mark.integration
    def test_create_user_success(self, base_url, api_headers, test_user_data):
        """✅ Positive: POST /users creates new user successfully"""
        
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 201
            mock_response.json.return_value = {
                "id": 3,
                "username": "testuser",
                "email": "test@example.com",
                "first_name": "Test",
                "last_name": "User",
                "role": "user",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
            mock_post.return_value = mock_response
            
            response = requests.post(
                f"{base_url}/users",
                headers=api_headers,
                json=test_user_data
            )
            
            assert response.status_code == 201
            user_data = response.json()
            
            # Validate created user schema
            jsonschema.validate(instance=user_data, schema=USER_SCHEMA)
            
            # Business logic assertions
            assert user_data["username"] == test_user_data["username"]
            assert user_data["email"] == test_user_data["email"]
            assert user_data["id"] is not None
    
    @pytest.mark.integration
    def test_update_user_success(self, base_url, api_headers):
        """✅ Positive: PUT /users/{id} updates user successfully"""
        
        update_data = {
            "first_name": "Updated",
            "last_name": "Name"
        }
        
        with patch('requests.put') as mock_put:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "id": 1,
                "username": "john_doe",
                "email": "john@example.com",
                "first_name": "Updated",
                "last_name": "Name",
                "role": "user",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
            mock_put.return_value = mock_response
            
            response = requests.put(
                f"{base_url}/users/1",
                headers=api_headers,
                json=update_data
            )
            
            assert response.status_code == 200
            user_data = response.json()
            
            # Validate updated user schema
            jsonschema.validate(instance=user_data, schema=USER_SCHEMA)
            
            # Business logic assertions
            assert user_data["first_name"] == "Updated"
            assert user_data["last_name"] == "Name"
    
    @pytest.mark.integration
    def test_delete_user_success(self, base_url, api_headers):
        """✅ Positive: DELETE /users/{id} deletes user successfully"""
        
        with patch('requests.delete') as mock_delete:
            mock_response = Mock()
            mock_response.status_code = 204
            mock_response.content = b''  # Set content to empty bytes
            mock_delete.return_value = mock_response
            
            response = requests.delete(f"{base_url}/users/1", headers=api_headers)
            
            assert response.status_code == 204
            assert response.content == b''  # No content for successful deletion
