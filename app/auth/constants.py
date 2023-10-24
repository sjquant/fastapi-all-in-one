from app.core.constants import BaseErrorEnum


class ErrorEnum(BaseErrorEnum):
    INVALID_CREDENTIALS = (
        "INVALID_CREDENTIALS",
        "잘못된 인증정보로 로그인을 시도하였습니다.",
    )
    PASSWORD_DOES_NOT_MATCH = (
        "PASSWORD_DOES_NOT_MATCH",
        "비밀번호가 일치하지 않습니다.",
    )
    USER_NOT_FOUND = ("USER_NOT_FOUND", "해당 사용자를 찾을 수 없습니다.")
