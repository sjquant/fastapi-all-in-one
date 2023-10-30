from app.core.constants import BaseErrorEnum


class ErrorEnum(BaseErrorEnum):
    INVALID_EMAIL = ("INVALID_EMAIL", "Provided email is invalid.")
    PASSWORD_TOO_SHORT = (
        "PASSWORD_TOO_SHORT",
        "Password must be at least {length} characters long.",
    )
    PASSWORD_TOO_SIMPLE = (
        "PASSWORD_TOO_SIMPLE",
        "Password must contain at least one letter, one number, and one special character.",
    )
