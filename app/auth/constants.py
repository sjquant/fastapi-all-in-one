from app.core.constants import BaseErrorEnum


class ErrorEnum(BaseErrorEnum):
    INVALID_CREDENTIALS = (
        "INVALID_CREDENTIALS",
        "Provided credentials are invalid.",
    )
    PASSWORD_DOES_NOT_MATCH = (
        "PASSWORD_DOES_NOT_MATCH",
        "Provided password does not match.",
    )
    USER_NOT_FOUND = ("USER_NOT_FOUND", "Specified user does not exist.")
    USER_ALREADY_EXISTS = ("USER_ALREADY_EXISTS", "Specified user already exists.")
