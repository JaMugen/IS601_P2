"""
End-to-End Tests for Calculations Application
Christopher Gaudious 12/3/2025 10:22 am
This module contains comprehensive API tests for the calculations application,
including user registration, login, and all calculation operations (addition,
subtraction, multiplication, division).

Note: These tests use the Docker container running on localhost:8000
Make sure the application is running before executing these tests.
"""
import pytest
import time
import requests


# ======================================================================================
# Helper Functions
# ======================================================================================
def register_user_api(base_url: str, username: str, email: str, password: str, first_name: str = "Test", last_name: str = "User"):
    """Helper function to register a new user via API."""
    response = requests.post(
        f"{base_url}auth/register",
        json={
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password,
            "first_name": first_name,
            "last_name": last_name
        }
    )
    return response.status_code == 201, response


def login_user_api(base_url: str, username: str, password: str) -> str:
    """Helper function to log in via API and return access token."""
    response = requests.post(
        f"{base_url}auth/token",
        data={
            "username": username,
            "password": password
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        return data.get("access_token")
    return None


def create_calculation_api(base_url: str, token: str, operation: str, numbers: list):
    """
    Helper function to create a calculation via API.
    
    Args:
        base_url: Base URL of the application
        token: Authentication token
        operation: One of 'addition', 'subtraction', 'multiplication', 'division'
        numbers: List of numbers to calculate
    
    Returns:
        Response object
    """
    response = requests.post(
        f"{base_url}calculations",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={
            "type": operation,
            "inputs": numbers
        }
    )
    return response


def get_calculations_api(base_url: str, token: str):
    """Helper function to get all calculations via API."""
    response = requests.get(
        f"{base_url}calculations",
        headers={"Authorization": f"Bearer {token}"}
    )
    return response


# ======================================================================================
# Test Fixtures
# ======================================================================================
@pytest.fixture
def test_user_credentials():
    """Provide unique test user credentials for each test."""
    timestamp = int(time.time() * 1000)
    return {
        "username": f"testuser_{timestamp}",
        "email": f"testuser_{timestamp}@example.com",
        "password": "TestPass123!",
        "first_name": "Test",
        "last_name": "User"
    }


@pytest.fixture
def authenticated_user(fastapi_server, test_user_credentials):
    """Provide an authenticated user with access token."""
    # Register user
    success, response = register_user_api(
        fastapi_server,
        test_user_credentials["username"],
        test_user_credentials["email"],
        test_user_credentials["password"],
        test_user_credentials["first_name"],
        test_user_credentials["last_name"]
    )
    
    if not success:
        pytest.skip(f"Could not register user: {response.text}")
    
    # Login and get token
    token = login_user_api(fastapi_server, test_user_credentials["username"], test_user_credentials["password"])
    
    if not token:
        pytest.skip("Could not authenticate user")
    
    return {
        "token": token,
        "username": test_user_credentials["username"],
        "email": test_user_credentials["email"],
        "base_url": fastapi_server
    }


# ======================================================================================
# Registration and Login Tests
# ======================================================================================
@pytest.mark.e2e
def test_user_registration(fastapi_server, test_user_credentials):
    """Test that a user can successfully register via API."""
    success, response = register_user_api(
        fastapi_server,
        test_user_credentials["username"],
        test_user_credentials["email"],
        test_user_credentials["password"],
        test_user_credentials["first_name"],
        test_user_credentials["last_name"]
    )
    assert success, f"User registration failed: {response.text}"
    assert response.status_code == 201


@pytest.mark.e2e
def test_user_login(fastapi_server, test_user_credentials):
    """Test that a registered user can log in successfully via API."""
    # First register the user
    register_user_api(
        fastapi_server,
        test_user_credentials["username"],
        test_user_credentials["email"],
        test_user_credentials["password"],
        test_user_credentials["first_name"],
        test_user_credentials["last_name"]
    )
    
    # Then login
    token = login_user_api(fastapi_server, test_user_credentials["username"], test_user_credentials["password"])
    assert token is not None, "Login failed"
    assert len(token) > 0


# ======================================================================================
# Addition Tests
# ======================================================================================
@pytest.mark.e2e
def test_addition_two_numbers(authenticated_user):
    """Test addition of two numbers via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "addition",
        [10, 5]
    )
    
    assert response.status_code == 201, f"Failed to create calculation: {response.text}"
    
    data = response.json()
    assert data["type"] == "addition"
    assert data["inputs"] == [10, 5]
    assert data["result"] == 15.0 or data["result"] == 15


@pytest.mark.e2e
def test_addition_multiple_numbers(authenticated_user):
    """Test addition of multiple numbers via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "addition",
        [5, 10, 15, 20]
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["result"] == 50.0 or data["result"] == 50


@pytest.mark.e2e
def test_addition_with_decimals(authenticated_user):
    """Test addition with decimal numbers via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "addition",
        [10.5, 5.3]
    )
    
    assert response.status_code == 201
    data = response.json()
    assert abs(data["result"] - 15.8) < 0.01  # Allow for floating point precision


# ======================================================================================
# Subtraction Tests
# ======================================================================================
@pytest.mark.e2e
def test_subtraction_two_numbers(authenticated_user):
    """Test subtraction of two numbers via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "subtraction",
        [20, 8]
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["type"] == "subtraction"
    assert data["result"] == 12.0 or data["result"] == 12


@pytest.mark.e2e
def test_subtraction_multiple_numbers(authenticated_user):
    """Test subtraction of multiple numbers (left to right) via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "subtraction",
        [100, 20, 10, 5]
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["result"] == 65.0 or data["result"] == 65


@pytest.mark.e2e
def test_subtraction_negative_result(authenticated_user):
    """Test subtraction resulting in a negative number via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "subtraction",
        [10, 25]
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["result"] == -15.0 or data["result"] == -15


# ======================================================================================
# Multiplication Tests
# ======================================================================================
@pytest.mark.e2e
def test_multiplication_two_numbers(authenticated_user):
    """Test multiplication of two numbers via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "multiplication",
        [6, 7]
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["type"] == "multiplication"
    assert data["result"] == 42.0 or data["result"] == 42


@pytest.mark.e2e
def test_multiplication_multiple_numbers(authenticated_user):
    """Test multiplication of multiple numbers via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "multiplication",
        [2, 3, 4]
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["result"] == 24.0 or data["result"] == 24


@pytest.mark.e2e
def test_multiplication_with_zero(authenticated_user):
    """Test multiplication with zero via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "multiplication",
        [5, 0]
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["result"] == 0.0 or data["result"] == 0


# ======================================================================================
# Division Tests
# ======================================================================================
@pytest.mark.e2e
def test_division_two_numbers(authenticated_user):
    """Test division of two numbers via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "division",
        [20, 4]
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["type"] == "division"
    assert data["result"] == 5.0 or data["result"] == 5


@pytest.mark.e2e
def test_division_multiple_numbers(authenticated_user):
    """Test division of multiple numbers (left to right) via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "division",
        [100, 5, 2]
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["result"] == 10.0 or data["result"] == 10


@pytest.mark.e2e
def test_division_with_decimals(authenticated_user):
    """Test division resulting in decimal via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "division",
        [10, 3]
    )
    
    assert response.status_code == 201
    data = response.json()
    # 10 / 3 = 3.333...
    assert abs(data["result"] - 3.333333) < 0.01


@pytest.mark.e2e
def test_division_by_zero_error(authenticated_user):
    """Test that division by zero returns an error via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "division",
        [10, 0]
    )
    
    # Should return a 400 or 422 error
    assert response.status_code >= 400, f"Expected error status, got {response.status_code}"
    # Error response should mention the issue
    error_data = response.json()
    assert "detail" in error_data

# ======================================================================================
# Exponential Tests
# ======================================================================================
@pytest.mark.e2e
def test_exponent_two_numbers(authenticated_user):
    """Test exponentiation of two numbers via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "exponent",
        [2, 3]
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["type"] == "exponent"
    assert data["result"] == 8.0 or data["result"] == 8

@pytest.mark.e2e
def test_exponent_multiple_numbers(authenticated_user):
    """Test exponentiation of multiple numbers via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "exponent",
        [2, 3, 2]  # (2^3)^2 = 64
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["result"] == 64.0 or data["result"] == 64

@pytest.mark.e2e
def test_exponent_with_zero_exponent(authenticated_user):
    """Test exponentiation with zero exponent via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "exponent",
        [5, 0]
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["result"] == 1.0 or data["result"] == 1
# ======================================================================================
# Modulus Tests
# ======================================================================================
@pytest.mark.e2e
def test_modulus_two_numbers(authenticated_user):
    """Test modulus of two numbers via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "modulus",
        [10, 3]
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["type"] == "modulus"
    assert data["result"] == 1.0 or data["result"] == 1
@pytest.mark.e2e
def test_modulus_multiple_numbers(authenticated_user):
    """Test modulus of multiple numbers via API."""
    response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "modulus",
        [100, 30, 4]  # ((100 % 30) % 4) = 2
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["result"] == 2.0 or data["result"] == 2
# ======================================================================================
# Multiple Operations Test
# ======================================================================================
@pytest.mark.e2e
def test_multiple_calculations_history(authenticated_user):
    """Test that multiple calculations can be created and retrieved via API."""
    # Perform multiple calculations
    create_calculation_api(authenticated_user["base_url"], authenticated_user["token"], "addition", [5, 3])
    create_calculation_api(authenticated_user["base_url"], authenticated_user["token"], "multiplication", [4, 6])
    create_calculation_api(authenticated_user["base_url"], authenticated_user["token"], "subtraction", [20, 7])
    
    # Get all calculations
    response = get_calculations_api(authenticated_user["base_url"], authenticated_user["token"])
    
    assert response.status_code == 200
    calculations = response.json()
    
    # Should have at least 3 calculations
    assert len(calculations) >= 3, f"Expected at least 3 calculations, found {len(calculations)}"
    
    # Verify the calculations
    types = [calc["type"] for calc in calculations]
    assert "addition" in types
    assert "multiplication" in types
    assert "subtraction" in types


# ======================================================================================
# Calculation Retrieval Tests
# ======================================================================================
@pytest.mark.e2e
def test_get_single_calculation(authenticated_user):
    """Test retrieving a single calculation by ID via API."""
    # Create a calculation
    create_response = create_calculation_api(
        authenticated_user["base_url"],
        authenticated_user["token"],
        "addition",
        [100, 200]
    )
    
    assert create_response.status_code == 201
    calc_data = create_response.json()
    calc_id = calc_data["id"]
    
    # Get the specific calculation
    get_response = requests.get(
        f"{authenticated_user['base_url']}calculations/{calc_id}",
        headers={"Authorization": f"Bearer {authenticated_user['token']}"}
    )
    
    assert get_response.status_code == 200
    retrieved_calc = get_response.json()
    assert retrieved_calc["id"] == calc_id
    assert retrieved_calc["result"] == 300.0 or retrieved_calc["result"] == 300
