import pytest
import pytest_mock

from app.core.config import config
from app.user.models import User


def test_set_password_hash_works():
    """Setting password hashes the password"""
    user = User(nickname="test", email="test@email.com")
    user.set_password("password123!")
    assert user.hashed_password != "password123!"


def test_password_must_be_greater_than_min_length_config(
    mocker: pytest_mock.MockFixture,
):
    """Password must be at least 8 characters"""
    mocker.patch.object(config, "password_min_length", 10)

    user = User(nickname="test", email="test@email.com")
    with pytest.raises(AssertionError):
        user.set_password("short123!")  # 9 characters


def test_password_must_contain_numer_alphabet_and_special_characters(
    mocker: pytest_mock.MockFixture,
):
    """Password must contain special characters"""
    mocker.patch.object(config, "password_min_length", 10)

    user = User(nickname="test", email="test@email.com")
    with pytest.raises(AssertionError):
        user.set_password("password123")

    with pytest.raises(AssertionError):
        user.set_password("password!!!!")


def test_cannot_read_password():
    """Password is not readable"""
    user = User(nickname="test", email="test@email.com")
    with pytest.raises(AttributeError):
        user.password


def test_verify_password():
    """Verify password works"""
    user = User(nickname="test", email="test@email.com")
    user.set_password("password123!")
    assert user.verify_password("password123!")


def test_verify_password_fails():
    """Verify password fails"""
    user = User(nickname="test", email="test@email.com")
    user.set_password("password123!")
    assert not user.verify_password("notpassword123!")


def test_set_unusable_password():
    """Unusable password works"""
    user = User(nickname="test", email="test@email.com")
    user.set_unusable_password()
    assert user.hashed_password is None


def test_validate_email():
    """Cannot create user with invalid email"""
    with pytest.raises(AssertionError):
        User(nickname="test", email="wrongemail")


def test_anonymous_user():
    """Anonymous user works"""
    user = User.anonymous()
    assert user.is_anonymous
