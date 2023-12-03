import abc
import asyncio
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.utils import is_valid_email


class EmailBackendBase(abc.ABC):
    @abc.abstractmethod
    async def send(
        self,
        *,
        sender: str,
        recipients: list[str],
        subject: str,
        body_plain: str,
        body_html: str | None = None,
    ) -> None: ...


class SMTPEmailBackend(EmailBackendBase):
    def __init__(self, *, host: str, port: int, username: str, password: str, use_tls: bool = True):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls

    async def send(
        self,
        *,
        sender: str,
        recipients: list[str],
        subject: str,
        body_plain: str,
        body_html: str | None = None,
    ):
        if not is_valid_email(sender):
            raise InvalidEmail(f"Invalid email address: {sender}")

        for recipient in recipients:
            if not is_valid_email(recipient):
                raise InvalidEmail(f"Invalid email address: {recipient}")

        message = create_message(
            sender=sender,
            recipients=recipients,
            subject=subject,
            body_plain=body_plain,
            body_html=body_html,
        )

        loop = asyncio.get_event_loop()
        # Send the email in a separate thread to avoid blocking the event loop
        await loop.run_in_executor(None, self._send, sender, recipients, message)

    def _send(self, sender: str, recipients: list[str], message: MIMEMultipart):
        if self.use_tls:
            server = smtplib.SMTP_SSL(self.host, self.port)
        else:
            server = smtplib.SMTP(self.host, self.port)

        try:
            server.login(self.username, self.password)
            server.sendmail(sender, recipients, message.as_string())
        except Exception as e:
            raise EmailSendFailed(str(e))
        finally:
            server.quit()


class DebugEmailBackend(EmailBackendBase):
    async def send(
        self,
        *,
        sender: str,
        recipients: list[str],
        subject: str,
        body_plain: str,
        body_html: str | None = None,
    ):
        print(f"Sender: {sender}")
        print(f"Recipients: {recipients}")
        print(f"Subject: {subject}")
        print(f"Body (plain): {body_plain}")
        print(f"Body (HTML): {body_html}")


def create_message(
    *,
    sender: str,
    recipients: list[str],
    subject: str,
    body_plain: str,
    body_html: str | None = None,
) -> MIMEMultipart:
    """
    Creates a MIME message with plain text and HTML content

    sender: the email address of the sender
    recipients: a list of email addresses of the recipients
    subject: the subject of the message
    body_plain: the plain text content of the message
    body_html: the HTML content of the message
    """
    message = MIMEMultipart()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = ", ".join(recipients)

    # Attach the body
    message.attach(MIMEText(body_plain, "plain"))
    if body_html:
        message.attach(MIMEText(body_html, "html"))

    return message


class EmailException(Exception):
    """Base class for email exceptions."""

    ...


class InvalidEmail(EmailException):
    """Raised when an email address is invalid."""

    ...


class EmailSendFailed(EmailException):
    """Raised when an email fails to send."""

    ...
