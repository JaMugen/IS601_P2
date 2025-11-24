from click import confirm
import pytest

from pydantic import ValidationError
from app.models.user import User
from app.schemas.user import PasswordUpdate, UserCreate


def test_password_update_mismatch_raises_validation_error():
    """Creating PasswordUpdate with non-matching new/confirm should fail."""
    with pytest.raises(Exception) as excinfo:
        PasswordUpdate(
            current_password="OldPass123!",
            new_password="NewPass123!",
            confirm_new_password="Different123!",
        )

    # The validator raises a ValueError which Pydantic wraps; check message
    msg = str(excinfo.value).lower()
    assert "do not match" in msg or "must be different" in msg

def test_password_update_same_as_current_raises_validation_error():
    """Creating PasswordUpdate with new password same as current should fail."""
    with pytest.raises(Exception) as excinfo:
        PasswordUpdate(
            current_password="SamePass123!",
            new_password="SamePass123!",
            confirm_new_password="SamePass123!",
        )

    # The validator raises a ValueError which Pydantic wraps; check message
    msg = str(excinfo.value).lower()
    assert "must be different" in msg

def test_password_update_valid():
    """Creating PasswordUpdate with valid data should succeed."""
    pwd_update = PasswordUpdate(
        current_password="OldPass123!",
        new_password="NewPass123!",
        confirm_new_password="NewPass123!",
    )
    assert pwd_update.current_password == "OldPass123!"
    assert pwd_update.new_password == "NewPass123!"
    assert pwd_update.confirm_new_password == "NewPass123!"


def test_verify_password_match_invalid():
    """Creating UserCreate with mismatched password/confirm should fail."""
    with pytest.raises(Exception) as excinfo:
        UserCreate(
            first_name="John",
            last_name="Doe",
            email="john.doe@example.com",
            username="johndoe",
            password="ValidPass123",
            confirm_password="NotValidPass123",
        )

    msg = str(excinfo.value).lower()
    assert "passwords do not match" in msg or "do not match" in msg

def test_verify_password_match_valid():
    """Creating UserCreate with valid matching password/confirm should succeed."""
    user_create = UserCreate(
        first_name="John",
        last_name="Doe",
        email="john.doe@example.com",
        username="johndoe",
        password="!ValidPass123",
        confirm_password="!ValidPass123",
    )
    assert user_create.password == "!ValidPass123"
    assert user_create.confirm_password == "!ValidPass123"

 
def base_user_data():
    return {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "username": "johndoe",
    }


def test_usercreate_valid_password():
    data = base_user_data()
    data.update({"password": "GoodPass1!", "confirm_password": "GoodPass1!"})
    u = UserCreate(**data)
    assert u.password == "GoodPass1!"


def test_usercreate_password_too_short():
    data = base_user_data()
    data.update({"password": "Shor1!", "confirm_password": "Shor1!"})
    with pytest.raises(ValidationError, match="String should have at least 8 characters"):
        UserCreate(**data)


def test_usercreate_password_no_uppercase():
    data = base_user_data()
    data.update({"password": "lowercase1!", "confirm_password": "lowercase1!"})
    with pytest.raises(ValidationError, match="Password must contain at least one uppercase letter"):
        UserCreate(**data)


def test_usercreate_password_no_lowercase():
    data = base_user_data()
    data.update({"password": "UPPERCASE1!", "confirm_password": "UPPERCASE1!"})
    with pytest.raises(ValidationError, match="Password must contain at least one lowercase letter"):
        UserCreate(**data)


def test_usercreate_password_no_digit():
    data = base_user_data()
    data.update({"password": "NoDigits!", "confirm_password": "NoDigits!"})
    with pytest.raises(ValidationError, match="Password must contain at least one digit"):
        UserCreate(**data)


def test_usercreate_password_no_special():
    data = base_user_data()
    data.update({"password": "NoSpecial1", "confirm_password": "NoSpecial1"})
    with pytest.raises(ValidationError, match="Password must contain at least one special character"):
        UserCreate(**data)


def test_usercreate_password_mismatch():
    data = base_user_data()
    data.update({"password": "GoodPass1!", "confirm_password": "Different1!"})
    with pytest.raises(ValidationError, match="Passwords do not match"):
        UserCreate(**data)