import os
import logging
from html import escape

import resend

logger = logging.getLogger(__name__)


def send_invitation_email(
    recipient_email: str,
    invitation_code: str,
    organization_name: str,
    assigned_role: str,
    expires_at: str,
) -> bool:
    """
    Send an organization invitation email using the Resend API.

    Returns True when Resend accepts the email request.
    Returns False when email delivery cannot be initiated.
    """

    api_key = os.getenv("RESEND_API_KEY")

    if not api_key:
        logger.error("RESEND_API_KEY is not configured.")
        return False

    sender_email = os.getenv(
        "RESEND_FROM_EMAIL",
        "onboarding@resend.dev",
    )

    sender_name = os.getenv(
        "RESEND_FROM_NAME",
        "NexaGraph AI",
    )

    if not recipient_email or not sender_email:
        logger.error("Email recipient or sender configuration is missing.")
        return False

    # Escape dynamic values before inserting them into HTML.
    code = escape(invitation_code)
    organization = escape(organization_name)
    role = escape(assigned_role)
    expiry = escape(expires_at)

    message = {
        "from": f"{sender_name} <{sender_email}>",
        "to": [recipient_email],
        "subject": (
            f"You're invited to join "
            f"{organization_name} on NexaGraph AI"
        ),
        "text": f"""
Hello,

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
""",
        "html": f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NexaGraph AI Invitation</title>
</head>

<body style="
    margin:0;
    padding:30px;
    background:#101525;
    font-family:Arial,sans-serif;
    color:#f8fafc;
">
    <div style="
        max-width:560px;
        margin:auto;
        background:#192238;
        padding:32px;
        border-radius:14px;
    ">

        <h1 style="color:#38bdf8;">
            NexaGraph AI
        </h1>

        <h2>You're invited!</h2>

        <p>
            You have been invited to join
            <strong>{organization}</strong>.
        </p>

        <p>
            <strong>Assigned role:</strong> {role}
        </p>

        <div style="
            background:#0b1020;
            padding:22px;
            border-radius:10px;
            text-align:center;
        ">
            <p style="color:#94a3b8;">
                YOUR INVITATION CODE
            </p>

            <h2 style="
                color:#38bdf8;
                letter-spacing:2px;
                word-break:break-all;
            ">
                {code}
            </h2>
        </div>

        <p>
            <strong>Expires:</strong> {expiry}
        </p>

        <p>
            Enter this invitation code on the NexaGraph AI
            registration page to create your account.
        </p>

        <hr style="border-color:#334155;">

        <p style="
            color:#94a3b8;
            font-size:12px;
        ">
            If you were not expecting this invitation,
            you can safely ignore this email.
        </p>

        <p>
            Regards,<br>
            NexaGraph AI Team
        </p>

    </div>
</body>
</html>
""",
    }

    try:
        # Configure Resend API authentication.
        resend.api_key = api_key

        # Submit the email through the Resend HTTPS API.
        response = resend.Emails.send(message)

        # Extract the Resend email ID for logging.
        email_id = (
            response.get("id")
            if isinstance(response, dict)
            else getattr(response, "id", None)
        )

        if not email_id:
            logger.error(
                "Resend returned no email ID. Response: %s",
                response,
            )
            return False

        logger.info(
            "Invitation email accepted by Resend. Email ID: %s",
            email_id,
        )

        return True

    except Exception:
        logger.exception("Resend invitation email failed.")
        return False