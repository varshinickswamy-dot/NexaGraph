import os
import smtplib
import logging
from html import escape
from email.message import EmailMessage

logger = logging.getLogger(__name__)


def send_invitation_email(
    recipient_email: str,
    invitation_code: str,
    organization_name: str,
    assigned_role: str,
    expires_at: str,
) -> bool:
    """
    Send an organization invitation email using Gmail SMTP.
    Returns True when the SMTP server accepts the message.
    """

    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    sender_email = os.getenv("SMTP_FROM_EMAIL", smtp_username)
    sender_name = os.getenv("SMTP_FROM_NAME", "NexaGraph AI")

    if not all([smtp_host, smtp_username, smtp_password, sender_email]):
        logger.error("Email configuration is incomplete.")
        return False

    code = escape(invitation_code)
    organization = escape(organization_name)
    role = escape(assigned_role)
    expiry = escape(expires_at)

    message = EmailMessage()
    message["Subject"] = f"You're invited to join {organization} on NexaGraph AI"
    message["From"] = f"{sender_name} <{sender_email}>"
    message["To"] = recipient_email

    message.set_content(
        f"""
Hello,

You have been invited to join {organization} on NexaGraph AI.

Your assigned role: {assigned_role}

Your invitation code:
{invitation_code}

Invitation expiry: {expires_at}

Use this invitation code on the NexaGraph AI registration page
to create your account.

If you were not expecting this invitation, you can ignore this email.

Regards,
NexaGraph AI Team
"""
    )

    message.add_alternative(
        f"""
        <!DOCTYPE html>
        <html>
        <body style="margin:0;padding:30px;background:#101525;
                     font-family:Arial,sans-serif;color:#f8fafc;">
          <div style="max-width:560px;margin:auto;background:#192238;
                      padding:32px;border-radius:14px;">
            <h1 style="color:#38bdf8;">NexaGraph AI</h1>

            <h2>You're invited!</h2>

            <p>You have been invited to join
               <strong>{organization}</strong>.</p>

            <p><strong>Assigned role:</strong> {role}</p>

            <div style="background:#0b1020;padding:22px;
                        border-radius:10px;text-align:center;">
              <p style="color:#94a3b8;">YOUR INVITATION CODE</p>
              <h2 style="color:#38bdf8;letter-spacing:2px;">
                {code}
              </h2>
            </div>

            <p><strong>Expires:</strong> {expiry}</p>

            <p>Enter this code on the NexaGraph AI registration
               page to create your account.</p>

            <hr style="border-color:#334155;">

            <p style="color:#94a3b8;font-size:12px;">
              If you were not expecting this invitation,
              you can safely ignore this email.
            </p>

            <p>Regards,<br>NexaGraph AI Team</p>
          </div>
        </body>
        </html>
        """,
        subtype="html",
    )

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(smtp_username, smtp_password)
            server.send_message(message)

        logger.info("Invitation email accepted for delivery.")
        return True

    except (smtplib.SMTPException, OSError, ValueError):
        logger.exception("Invitation email delivery failed.")
        return False