from enum import Enum
from typing import Self

MINUTE = 60
HOUR = 60 * MINUTE
DAY = 24 * MINUTE


class BaseErrorEnum(Enum):
    """
    Base class for error enums.
    """

    def __init__(self, code: str, message: str) -> None:
        self._code = code
        self._message = message
        self._daynamic_message: str | None = None

    @property
    def code(self) -> str:
        return self._code

    @property
    def message(self) -> str:
        if self._daynamic_message:
            return self._daynamic_message
        else:
            return self._message

    def dynamic_message(self, **kwargs: str) -> Self:
        # In order for dynamic messages to work in test code, it should be used as follows:
        self._daynamic_message = self._message.format(**kwargs)
        return self
