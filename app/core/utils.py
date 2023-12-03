import re


def is_valid_email(email: str) -> bool:
    """Check if the email is valid or not."""
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))
