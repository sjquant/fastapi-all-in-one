import pytest
import pytest_mock

from app.core.config import config
from app.core.errors import ValidationError
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
    with pytest.raises(ValidationError) as e:
        user.set_password("short123!")  # 9 characters

    assert e.value.error_code == "PASSWORD_TOO_SHORT"
    assert e.value.message == "Password must be at least 10 characters long."


def test_password_must_contain_numer_alphabet_and_special_characters(
    mocker: pytest_mock.MockFixture,
):
    """Password must contain special characters"""
    mocker.patch.object(config, "password_min_length", 10)

    user = User(nickname="test", email="test@email.com")
    with pytest.raises(ValidationError) as e:
        user.set_password("password123")

    assert e.value.error_code == "PASSWORD_TOO_SIMPLE"
    assert (
        e.value.message
        == "Password must contain at least one letter, one number, and one special character."
    )

    with pytest.raises(ValidationError) as e:
        user.set_password("password!!!!")

    assert e.value.error_code == "PASSWORD_TOO_SIMPLE"
    assert (
        e.value.message
        == "Password must contain at least one letter, one number, and one special character."
    )


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
    assert not user.verify_password("cannotverify")


def test_validate_email():
    """Cannot create user with invalid email"""
    with pytest.raises(ValidationError) as e:
        User(nickname="test", email="wrongemail")

    assert e.value.error_code == "INVALID_EMAIL"
    assert e.value.message == "Provided email is invalid."


def test_anonymous_user():
    """Anonymous user works"""
    user = User.anonymous()
    assert user.is_anonymous
