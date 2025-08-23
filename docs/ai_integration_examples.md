# AI Integration Examples for API Testing

This document demonstrates practical examples of using AI tools to enhance API testing automation.

## 🚀 Postman Postbot Integration

### Example 1: Generate Test for GET /users Endpoint

**Prompt to Postbot:**
```
Generate a PyTest test for the GET /users endpoint that:
- Tests successful response (200)
- Validates response schema
- Checks pagination parameters
- Includes error handling for 400/401 responses
```

**AI-Generated Test (Postbot Output):**
```python
import pytest
import requests
from jsonschema import validate

def test_get_users_endpoint():
    """Test GET /users endpoint with Postbot-generated test"""
    
    # Test successful response
    response = requests.get("https://api.hanwha-vision.com/users")
    assert response.status_code == 200
    
    # Validate response schema
    schema = {
        "type": "object",
        "properties": {
            "users": {"type": "array"},
            "total": {"type": "integer"},
            "page": {"type": "integer"},
            "per_page": {"type": "integer"}
        },
        "required": ["users", "total"]
    }
    
    data = response.json()
    validate(instance=data, schema=schema)
    
    # Test pagination
    response = requests.get("https://api.hanwha-vision.com/users?page=2&per_page=5")
    assert response.status_code == 200
    
    # Test error responses
    response = requests.get("https://api.hanwha-vision.com/users?page=invalid")
    assert response.status_code == 400
    
    response = requests.get("https://api.hanwha-vision.com/users", headers={})
    assert response.status_code == 401
```

**Engineer Validation & Enhancement:**
```python
import pytest
import requests
import jsonschema
from unittest.mock import patch, Mock

class TestUsersEndpoint:
    """Enhanced test suite for GET /users endpoint"""
    
    @pytest.fixture
    def api_headers(self):
        return {
            "Authorization": "Bearer test_token",
            "Content-Type": "application/json"
        }
    
    def test_get_users_success(self, api_headers):
        """Test successful GET /users response"""
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "users": [{"id": 1, "name": "Test User"}],
                "total": 1,
                "page": 1,
                "per_page": 10
            }
            mock_get.return_value = mock_response
            
            response = requests.get("https://api.hanwha-vision.com/users", headers=api_headers)
            
            assert response.status_code == 200
            data = response.json()
            assert "users" in data
            assert "total" in data
            assert len(data["users"]) == 1
    
    def test_get_users_pagination(self, api_headers):
        """Test pagination functionality"""
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "users": [],
                "total": 25,
                "page": 2,
                "per_page": 5
            }
            mock_get.return_value = mock_response
            
            response = requests.get(
                "https://api.hanwha-vision.com/users",
                params={"page": 2, "per_page": 5},
                headers=api_headers
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["page"] == 2
            assert data["per_page"] == 5
            assert data["total"] == 25
    
    def test_get_users_validation_error(self, api_headers):
        """Test validation error handling"""
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 400
            mock_response.json.return_value = {
                "error": "Invalid pagination parameters",
                "code": "VALIDATION_ERROR"
            }
            mock_get.return_value = mock_response
            
            response = requests.get(
                "https://api.hanwha-vision.com/users",
                params={"page": "invalid"},
                headers=api_headers
            )
            
            assert response.status_code == 400
            data = response.json()
            assert "error" in data
            assert data["code"] == "VALIDATION_ERROR"
```

## 🤖 Cursor AI Integration

### Example 2: Scaffold Test Function with Cursor

**User Request in Cursor:**
```
Create a PyTest test function for testing user creation (POST /users) that includes:
- Valid user data validation
- Invalid data handling
- Response schema validation
- Error code verification
```

**Cursor AI Suggestion:**
```python
def test_create_user_endpoint():
    """Test POST /users endpoint for user creation"""
    
    # Test data
    valid_user = {
        "username": "testuser",
        "email": "test@example.com",
        "first_name": "Test",
        "last_name": "User",
        "role": "user"
    }
    
    # Test successful creation
    response = requests.post("https://api.hanwha-vision.com/users", json=valid_user)
    assert response.status_code == 201
    
    # Validate response schema
    user_schema = {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "username": {"type": "string"},
            "email": {"type": "string"},
            "first_name": {"type": "string"},
            "last_name": {"type": "string"},
            "role": {"type": "string"},
            "created_at": {"type": "string"},
            "updated_at": {"type": "string"}
        },
        "required": ["id", "username", "email", "first_name", "last_name", "role"]
    }
    
    user_data = response.json()
    jsonschema.validate(instance=user_data, schema=user_schema)
    
    # Test validation errors
    invalid_user = {"username": "testuser"}  # Missing required fields
    
    response = requests.post("https://api.hanwha-vision.com/users", json=invalid_user)
    assert response.status_code == 400
    
    error_data = response.json()
    assert "error" in error_data
    assert "details" in error_data
```

**Engineer Enhancement:**
```python
import pytest
import requests
import jsonschema
from unittest.mock import patch, Mock

class TestUserCreation:
    """Enhanced test suite for user creation"""
    
    @pytest.fixture
    def valid_user_data(self):
        return {
            "username": "testuser",
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "role": "user"
        }
    
    @pytest.fixture
    def api_headers(self):
        return {
            "Authorization": "Bearer test_token",
            "Content-Type": "application/json"
        }
    
    def test_create_user_success(self, valid_user_data, api_headers):
        """Test successful user creation"""
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 201
            mock_response.json.return_value = {
                "id": 999,
                "username": valid_user_data["username"],
                "email": valid_user_data["email"],
                "first_name": valid_user_data["first_name"],
                "last_name": valid_user_data["last_name"],
                "role": valid_user_data["role"],
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
            mock_post.return_value = mock_response
            
            response = requests.post(
                "https://api.hanwha-vision.com/users",
                json=valid_user_data,
                headers=api_headers
            )
            
            assert response.status_code == 201
            user_data = response.json()
            
            # Validate response schema
            user_schema = {
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
                "required": ["id", "username", "email", "first_name", "last_name", "role", "created_at", "updated_at"],
                "additionalProperties": False
            }
            
            jsonschema.validate(instance=user_data, schema=user_schema)
            
            # Business logic assertions
            assert user_data["username"] == valid_user_data["username"]
            assert user_data["email"] == valid_user_data["email"]
            assert user_data["id"] is not None
            assert user_data["created_at"] is not None
    
    def test_create_user_validation_error(self, api_headers):
        """Test validation error handling"""
        invalid_user = {"username": "testuser"}  # Missing required fields
        
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 400
            mock_response.json.return_value = {
                "error": "Validation failed",
                "code": "VALIDATION_ERROR",
                "details": {
                    "email": ["This field is required"],
                    "first_name": ["This field is required"],
                    "last_name": ["This field is required"]
                }
            }
            mock_post.return_value = mock_response
            
            response = requests.post(
                "https://api.hanwha-vision.com/users",
                json=invalid_user,
                headers=api_headers
            )
            
            assert response.status_code == 400
            error_data = response.json()
            
            # Validate error response structure
            assert "error" in error_data
            assert "code" in error_data
            assert "details" in error_data
            
            # Check specific validation errors
            assert "email" in error_data["details"]
            assert "first_name" in error_data["details"]
            assert "last_name" in error_data["details"]
    
    def test_create_user_duplicate_username(self, valid_user_data, api_headers):
        """Test duplicate username handling"""
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 409
            mock_response.json.return_value = {
                "error": "Username already exists",
                "code": "DUPLICATE_USERNAME",
                "message": "A user with this username already exists"
            }
            mock_post.return_value = mock_response
            
            response = requests.post(
                "https://api.hanwha-vision.com/users",
                json=valid_user_data,
                headers=api_headers
            )
            
            assert response.status_code == 409
            error_data = response.json()
            assert error_data["code"] == "DUPLICATE_USERNAME"
```

## 🧠 GitHub Copilot Integration

### Example 3: Generate Security Test with Copilot

**User Comment in Code:**
```python
# TODO: Generate security test for SQL injection prevention
# Test various SQL injection payloads and ensure they are rejected
```

**Copilot Suggestion:**
```python
def test_sql_injection_prevention():
    """Test SQL injection prevention in user search"""
    
    sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "admin'--",
        "1' OR '1' = '1' LIMIT 1--"
    ]
    
    for payload in sql_payloads:
        response = requests.get(
            "https://api.hanwha-vision.com/users",
            params={"search": payload}
        )
        
        # Should reject SQL injection attempts
        assert response.status_code == 400
        
        error_data = response.json()
        assert "error" in error_data
        assert "Invalid input" in error_data.get("message", "")
```

**Engineer Enhancement:**
```python
import pytest
import requests
from unittest.mock import patch, Mock

class TestSecurityValidation:
    """Enhanced security test suite"""
    
    @pytest.fixture
    def api_headers(self):
        return {
            "Authorization": "Bearer test_token",
            "Content-Type": "application/json"
        }
    
    def test_sql_injection_prevention(self, api_headers):
        """Test SQL injection prevention in user search"""
        
        sql_injection_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "admin'--",
            "1' OR '1' = '1' LIMIT 1--",
            "' OR 'x'='x",
            "'; EXEC xp_cmdshell('dir'); --"
        ]
        
        for payload in sql_injection_payloads:
            with patch('requests.get') as mock_get:
                # Mock the API to reject SQL injection attempts
                mock_response = Mock()
                mock_response.status_code = 400
                mock_response.json.return_value = {
                    "error": "Invalid input",
                    "message": "Query parameter contains invalid characters",
                    "code": "INVALID_INPUT",
                    "request_id": f"req_{hash(payload) % 10000}"
                }
                mock_get.return_value = mock_response
                
                response = requests.get(
                    "https://api.hanwha-vision.com/users",
                    params={"search": payload},
                    headers=api_headers
                )
                
                # Assertions - API should reject SQL injection attempts
                assert response.status_code == 400, f"Failed to reject SQL injection: {payload}"
                
                response_data = response.json()
                assert "error" in response_data
                assert "INVALID_INPUT" in response_data.get("code", "")
                
                # Verify no sensitive data is exposed
                assert "users" not in response_data
                assert "password" not in str(response_data).lower()
    
    def test_xss_prevention(self, api_headers):
        """Test XSS prevention in user input"""
        
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//"
        ]
        
        for payload in xss_payloads:
            with patch('requests.post') as mock_post:
                mock_response = Mock()
                mock_response.status_code = 400
                mock_response.json.return_value = {
                    "error": "Invalid input",
                    "message": "Input contains potentially dangerous content",
                    "code": "XSS_DETECTED"
                }
                mock_post.return_value = mock_response
                
                test_data = {
                    "username": "testuser",
                    "email": "test@example.com",
                    "first_name": payload,  # XSS payload here
                    "last_name": "User",
                    "role": "user"
                }
                
                response = requests.post(
                    "https://api.hanwha-vision.com/users",
                    json=test_data,
                    headers=api_headers
                )
                
                assert response.status_code == 400, f"Failed to reject XSS: {payload}"
                response_data = response.json()
                assert "error" in response_data
                assert "XSS_DETECTED" in response_data.get("code", "")
```

## 📊 AI Integration Workflow

### 1. AI Suggestion Phase
- **Postman Postbot**: Generate initial test structure
- **Cursor AI**: Scaffold test functions and assertions
- **GitHub Copilot**: Suggest security test patterns

### 2. Engineer Validation Phase
- Review AI-generated code for correctness
- Enhance with proper mocking and fixtures
- Add comprehensive assertions and edge cases
- Ensure test maintainability and readability

### 3. Integration Phase
- Merge validated tests into test suite
- Run tests to verify functionality
- Update documentation and examples
- Share learnings with team

## 🎯 Best Practices for AI-Assisted Testing

1. **Start with Clear Prompts**: Be specific about requirements and expected outcomes
2. **Validate All Suggestions**: Never use AI-generated code without review
3. **Enhance and Extend**: Use AI as a starting point, not the final solution
4. **Maintain Consistency**: Ensure AI-generated tests follow team patterns
5. **Document Patterns**: Share successful AI prompts with the team
6. **Iterate and Improve**: Refine prompts based on output quality

## 🚀 Next Steps

- Integrate AI tools into CI/CD pipeline
- Create AI prompt templates for common test patterns
- Build AI-powered test generation workflows
- Measure AI tool effectiveness and ROI
- Train team on effective AI tool usage
