from app.core.constants import BaseErrorEnum


class HttpError(Exception):
    def __init__(self, error: BaseErrorEnum, *, status_code: int | None = None) -> None:
        self._message = error.message
        self._error_code = error.code
        self._status_code = status_code

    @property
    def message(self) -> str:
        return self._message

    @property
    def error_code(self) -> str:
        return self._error_code

    @property
    def status_code(self) -> int:
        if self._status_code is None:
            raise NotImplementedError(
                "status_code property must be implemented in subclasses, or passed as an argument."
            )
        return self._status_code


class UnauthorizedError(HttpError):
    def __init__(self, error: BaseErrorEnum) -> None:
        super().__init__(error)

    @property
    def status_code(self) -> int:
        return 401


class PermissionDenied(HttpError):
    def __init__(self, error: BaseErrorEnum) -> None:
        super().__init__(error)

    @property
    def status_code(self) -> int:
        return 403


class NotFoundError(HttpError):
    def __init__(self, error: BaseErrorEnum) -> None:
        super().__init__(error)

    @property
    def status_code(self) -> int:
        return 404


class ValidationError(HttpError):
    def __init__(self, error: BaseErrorEnum) -> None:
        super().__init__(error)

    @property
    def status_code(self) -> int:
        return 409
