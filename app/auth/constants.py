from app.core.constants import BaseErrorEnum


class ErrorEnum(BaseErrorEnum):
    INVALID_CREDENTIALS = (
        "INVALID_CREDENTIALS",
        "Provided credentials are invalid.",
    )
    USER_NOT_AUTHENTICATED = (
        "USER_NOT_AUTHENTICATED",
        "User is not authenticated.",
    )
    PASSWORD_DOES_NOT_MATCH = (
        "PASSWORD_DOES_NOT_MATCH",
        "Provided password does not match.",
    )
    USER_NOT_FOUND = ("USER_NOT_FOUND", "Specified user does not exist.")
    USER_ALREADY_EXISTS = ("USER_ALREADY_EXISTS", "Specified user already exists.")
    NO_REFRESH_TOKEN = (
        "REFRESH_TOKEN_NOT_FOUND",
        "No refresh token was provided.",
    )
    INVALID_REFRESH_TOKEN = (
        "INVALID_REFRESH_TOKEN",
        "Provided refresh token is invalid.",
    )
