import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from html import escape


logger = logging.getLogger(__name__)


def send_invitation_email(
    recipient_email: str,
    invitation_code: str,
    organization_name: str,
    assigned_role: str,
    expires_at: str,
) -> bool:
    """
    Send an organization invitation using the SMTP settings configured on Render.

    Supports Gmail SMTP with STARTTLS (port 587) and implicit TLS (port 465).
    No third-party email API or purchased sending domain is required.
    """

    host = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "").strip()
    from_email = (
        os.getenv("SMTP_FROM_EMAIL", "").strip()
        or username
    )
    from_name = (
        os.getenv("SMTP_FROM_NAME", "").strip()
        or "NexaGraph AI"
    )

    try:
        port = int(os.getenv("SMTP_PORT", "587").strip())
    except (TypeError, ValueError):
        logger.error("SMTP_PORT must be a valid integer.")
        return False

    if not all((host, username, password, from_email, recipient_email)):
        logger.error(
            "SMTP configuration is incomplete. Required: SMTP_HOST, "
            "SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD and SMTP_FROM_EMAIL "
            "(SMTP_FROM_EMAIL may fall back to SMTP_USERNAME)."
        )
        return False

    message = EmailMessage()
    message["Subject"] = (
        f"You're invited to join {organization_name} on NexaGraph AI"
    )
    message["From"] = f"{from_name} <{from_email}>"
    message["To"] = recipient_email

    message.set_content(f"""Hello,

You have been invited to join {organization_name} on NexaGraph AI.

Your assigned role: {assigned_role}

Your invitation code:
{invitation_code}

Invitation expiry: {expires_at}

Use this invitation code on the NexaGraph AI registration page
to create your account.

If you were not expecting this invitation, you can ignore this email.

Regards,
NexaGraph AI Team
""")

    code = escape(invitation_code)
    organization = escape(organization_name)
    role = escape(assigned_role)
    expiry = escape(expires_at)
    safe_from_name = escape(from_name)

    message.add_alternative(f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NexaGraph AI Invitation</title>
</head>
<body style="margin:0;padding:30px;background:#101525;font-family:Arial,sans-serif;color:#f8fafc;">
  <div style="max-width:560px;margin:auto;background:#192238;padding:32px;border-radius:14px;">
    <h1 style="color:#38bdf8;">NexaGraph AI</h1>
    <h2>You're invited!</h2>
    <p>You have been invited to join <strong>{organization}</strong>.</p>
    <p><strong>Assigned role:</strong> {role}</p>
    <div style="background:#0b1020;padding:22px;border-radius:10px;text-align:center;">
      <p style="color:#94a3b8;">YOUR INVITATION CODE</p>
      <h2 style="color:#38bdf8;letter-spacing:2px;word-break:break-all;">{code}</h2>
    </div>
    <p><strong>Expires:</strong> {expiry}</p>
    <p>Enter this invitation code on the NexaGraph AI registration page to create your account.</p>
    <hr style="border-color:#334155;">
    <p style="color:#94a3b8;font-size:12px;">If you were not expecting this invitation, you can safely ignore this email.</p>
    <p>Regards,<br>{safe_from_name} Team</p>
  </div>
</body>
</html>
""", subtype="html")

    try:
        context = ssl.create_default_context()
        timeout = 20

        if port == 465:
            with smtplib.SMTP_SSL(
                host, port, context=context, timeout=timeout
            ) as server:
                server.login(username, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(username, password)
                server.send_message(message)

        logger.info(
            "Invitation email sent successfully to %s via SMTP host %s.",
            recipient_email,
            host,
        )
        return True

    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        logger.exception(
            "SMTP invitation email failed for recipient %s via %s: %s",
            recipient_email,
            host,
            exc,
        )
        return False
