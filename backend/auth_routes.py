import os
import base64
import binascii
import hashlib
import hmac
import secrets

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt

from dotenv import load_dotenv
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    status,
)
from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials,
)
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.email_service import send_invitation_email

import logging

from backend.organization_provisioning import (
    provision_organization_demo_data,
)

logger = logging.getLogger(__name__)

# =====================================================
# CONFIGURATION
# =====================================================

load_dotenv()

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

security = HTTPBearer(auto_error=False)

JWT_SECRET = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
)

if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError(
        "JWT_SECRET_KEY is missing or too short. "
        "Configure a strong secret in the .env file."
    )

if JWT_ALGORITHM != "HS256":
    raise RuntimeError(
        "This authentication implementation supports HS256 only."
    )

if not 1 <= TOKEN_EXPIRE_MINUTES <= 1440:
    raise RuntimeError(
        "ACCESS_TOKEN_EXPIRE_MINUTES must be between 1 and 1440."
    )
def sync_registered_organization(organization_id: str):
    """
    Synchronize a newly registered organization with Neo4j.
    PostgreSQL registration remains successful if Neo4j is unavailable.
    """

    try:
        from backend.sync_engine import run_unified_sync

        report = run_unified_sync(
            organization_id=organization_id
        )

        if report.get("status") != "success":
            logger.error(
                "Organization Neo4j synchronization was not fully successful. "
                "Organization: %s | Report: %s",
                organization_id,
                report,
            )

    except Exception:
        logger.exception(
            "Background Neo4j synchronization failed for organization %s",
            organization_id,
        )

# =====================================================
# PASSWORD SECURITY - PBKDF2 SHA256
# No native DLL dependency
# =====================================================

PBKDF2_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    """
    Generate a salted PBKDF2-SHA256 password hash.
    """

    salt = secrets.token_bytes(16)

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )

    salt_encoded = base64.b64encode(salt).decode("ascii")
    hash_encoded = base64.b64encode(derived_key).decode("ascii")

    return (
        f"pbkdf2_sha256${PBKDF2_ITERATIONS}"
        f"${salt_encoded}${hash_encoded}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a password against its stored PBKDF2 hash.
    """

    try:
        algorithm, iterations_text, salt_encoded, hash_encoded = (
            stored_hash.split("$")
        )

        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations_text)

        # Prevent unreasonable iteration counts.
        if not 100_000 <= iterations <= 1_000_000:
            return False

        salt = base64.b64decode(
            salt_encoded,
            validate=True,
        )

        expected_hash = base64.b64decode(
            hash_encoded,
            validate=True,
        )

        if len(salt) != 16 or len(expected_hash) != 32:
            return False

        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )

        return hmac.compare_digest(
            actual_hash,
            expected_hash,
        )

    except (
        ValueError,
        TypeError,
        AttributeError,
        binascii.Error,
    ):
        return False


# =====================================================
# REQUEST SCHEMAS
# =====================================================

class RegisterRequest(BaseModel):

    full_name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

    # Defaults to create for compatibility with the existing frontend.
    organization_mode: str = Field(default="create", max_length=20)
    organization_name: str | None = Field(default=None, min_length=2, max_length=200)
    invitation_code: str | None = Field(default=None, min_length=20, max_length=200)


class CreateInvitationRequest(BaseModel):
    organization_id: str | None = None
    email: EmailStr
    role: str = Field(default="VIEWER", min_length=5, max_length=50)
    expires_in_days: int = Field(default=7, ge=1, le=30)


class LoginRequest(BaseModel):

    email: EmailStr

    password: str = Field(
        min_length=1,
        max_length=128,
    )


# =====================================================
# TOKEN HELPERS
# =====================================================

def hash_token(token: str) -> str:
    """
    Store only the SHA256 digest of the access token.
    """

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def create_access_token(
    user_id: str,
    session_id: str,
) -> str:

    now = datetime.now(timezone.utc)

    payload = {
        "sub": user_id,
        "sid": session_id,
        "iat": now,
        "exp": now + timedelta(
            minutes=TOKEN_EXPIRE_MINUTES
        ),
        "jti": secrets.token_urlsafe(16),
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


# =====================================================
# DATABASE HELPERS
# =====================================================

def get_user_by_email(
    db: Session,
    email: str,
):

    return db.execute(
        text("""
            SELECT
                u.id,
                u.full_name,
                u.email,
                u.password_hash,
                u.organization_id,
                u.is_active,
                r.name AS role

            FROM users u

            JOIN roles r
                ON r.id = u.role_id

            WHERE LOWER(u.email) = LOWER(:email)

            LIMIT 1
        """),
        {
            "email": email,
        },
    ).mappings().first()


# =====================================================
# REGISTRATION
# =====================================================

@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
)
def register(
    request: RegisterRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    email = request.email.lower().strip()
    full_name = request.full_name.strip()
    organization_mode = request.organization_mode.strip().lower()
    organization_name = (request.organization_name or "").strip()
    invitation_code = (request.invitation_code or "").strip()

    if not full_name:
        raise HTTPException(status_code=400, detail="Name cannot be blank.")

    if organization_mode not in {"create", "join"}:
        raise HTTPException(
            status_code=400,
            detail="Organization mode must be 'create' or 'join'.",
        )

    if organization_mode == "create" and not organization_name:
        raise HTTPException(
            status_code=400,
            detail="Organization name is required when creating an organization.",
        )

    if organization_mode == "join" and not invitation_code:
        raise HTTPException(
            status_code=400,
            detail="A valid organization invitation code is required.",
        )

    existing_user = get_user_by_email(db, email)
    db.rollback()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists.",
        )

    try:
        with db.begin():
            if organization_mode == "create":
                assigned_role = db.execute(
                    text("""
                        SELECT id, name
                        FROM roles
                        WHERE name = 'ORG_ADMIN'
                        LIMIT 1
                    """)
                ).mappings().first()

                if not assigned_role:
                    raise HTTPException(
                        status_code=500,
                        detail="Organization administrator role is unavailable.",
                    )

                organization_id = db.execute(
                    text("""
                        INSERT INTO organizations (name)
                        VALUES (:name)
                        RETURNING id
                    """),
                    {"name": organization_name},
                ).scalar_one()
            else:
                invitation = db.execute(
                    text("""
                        SELECT i.id, i.organization_id, i.role_id, r.name AS role
                        FROM organization_invitations i
                        JOIN roles r ON r.id = i.role_id
                        WHERE i.code_hash = :code_hash
                          AND LOWER(i.email) = LOWER(:email)
                          AND i.accepted_at IS NULL
                          AND i.revoked_at IS NULL
                          AND i.expires_at > NOW()
                        LIMIT 1
                        FOR UPDATE OF i
                    """),
                    {
                        "code_hash": hash_token(invitation_code),
                        "email": email,
                    },
                ).mappings().first()

                if not invitation:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Invitation code is invalid, expired, revoked, "
                            "or assigned to another email."
                        ),
                    )

                assigned_role = {
                    "id": invitation["role_id"],
                    "name": invitation["role"],
                }
                organization_id = invitation["organization_id"]

                if assigned_role["name"] not in {
                    ROLE_ORG_ADMIN,
                    ROLE_SECURITY_ANALYST,
                    ROLE_VIEWER,
                }:
                    raise HTTPException(
                        status_code=403,
                        detail="This invitation contains an unsupported role.",
                    )

            user_id = db.execute(
                text("""
                    INSERT INTO users (
                        organization_id, role_id, full_name, email,
                        password_hash, is_active
                    )
                    VALUES (
                        :organization_id, :role_id, :full_name, :email,
                        :password_hash, TRUE
                    )
                    RETURNING id
                """),
                {
                    "organization_id": organization_id,
                    "role_id": assigned_role["id"],
                    "full_name": full_name,
                    "email": email,
                    "password_hash": hash_password(request.password),
                },
            ).scalar_one()

            # Provision demo data only for a newly created organization.
            # Invitation-based users join the existing organization and must
            # not trigger another provisioning run.
            if organization_mode == "create":
                provision_result = provision_organization_demo_data(
                    db=db,
                    organization_id=str(organization_id),
                    admin_user_id=str(user_id),
                )
                logger.info(
                    "Organization demo data provisioned for %s: %s",
                    organization_id,
                    provision_result,
                )

            if organization_mode == "join":
                db.execute(
                    text("""
                        UPDATE organization_invitations
                        SET accepted_by = :user_id, accepted_at = NOW()
                        WHERE id = :invitation_id
                          AND accepted_at IS NULL
                          AND revoked_at IS NULL
                    """),
                    {
                        "user_id": user_id,
                        "invitation_id": invitation["id"],
                    },
                )

            db.execute(
                text("""
                    INSERT INTO audit_logs (
                        organization_id, user_id, action,
                        entity_type, entity_id, details
                    )
                    VALUES (
                        :organization_id, :user_id, :action,
                        'USER', :entity_id, CAST(:details AS JSONB)
                    )
                """),
                {
                    "organization_id": organization_id,
                    "user_id": user_id,
                    "action": (
                        "ORGANIZATION_CREATED"
                        if organization_mode == "create"
                        else "ORGANIZATION_INVITATION_ACCEPTED"
                    ),
                    "entity_id": str(user_id),
                    "details": '{"role":"' + assigned_role["name"] + '"}',
                },
            )

        # The PostgreSQL transaction has committed at this point. Run the
        # organization-scoped Neo4j sync in the background so a Neo4j outage
        # cannot roll back or invalidate a successful registration.
        if organization_mode == "create":
            background_tasks.add_task(
                sync_registered_organization,
                str(organization_id),
            )

        return {
            "success": True,
            "message": (
                "Organization and administrator account created successfully."
                if organization_mode == "create"
                else "You have successfully joined the organization."
            ),
            "user_id": str(user_id),
            "organization_id": str(organization_id),
            "role": assigned_role["name"],
        }

    except HTTPException:
        db.rollback()
        raise
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                "An account with this email already exists or the invitation "
                "is no longer available."
            ),
        ) from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Registration could not be completed.",
        ) from exc


# =====================================================
# LOGIN
# =====================================================

@router.post("/login")
def login(
    request: LoginRequest,
    db: Session = Depends(get_db),
):

    email = request.email.lower().strip()

    user = get_user_by_email(
        db,
        email,
    )

    # Close the read transaction before creating a session.
    db.rollback()

    if not user or not user["is_active"]:

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    if not verify_password(
        request.password,
        user["password_hash"],
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    session_id = str(uuid4())

    access_token = create_access_token(
        str(user["id"]),
        session_id,
    )

    token_digest = hash_token(access_token)

    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=TOKEN_EXPIRE_MINUTES
    )

    try:

        with db.begin():

            # Create database-backed session.
            db.execute(
                text("""
                    INSERT INTO user_sessions (
                        id,
                        user_id,
                        token_hash,
                        expires_at
                    )
                    VALUES (
                        :id,
                        :user_id,
                        :token_hash,
                        :expires_at
                    )
                """),
                {
                    "id": session_id,
                    "user_id": user["id"],
                    "token_hash": token_digest,
                    "expires_at": expires_at,
                },
            )

            # Update last login.
            db.execute(
                text("""
                    UPDATE users
                    SET last_login = NOW()
                    WHERE id = :user_id
                """),
                {
                    "user_id": user["id"],
                },
            )

        return {
            "success": True,
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": TOKEN_EXPIRE_MINUTES * 60,
            "user": {
                "id": str(user["id"]),
                "full_name": user["full_name"],
                "email": user["email"],
                "organization_id": (
                    str(user["organization_id"])
                    if user["organization_id"]
                    else None
                ),
                "role": user["role"],
            },
        }

    except Exception as exc:

        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Login could not be completed.",
        ) from exc


# =====================================================
# CURRENT USER AUTHENTICATION
# =====================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):

    if not credentials:

        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    token = credentials.credentials

    # Verify JWT.
    try:

        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={
                "require": ["sub", "sid", "exp", "iat", "jti"],
            },
        )

        user_id = payload.get("sub")
        session_id = payload.get("sid")

        if not user_id or not session_id:
            raise ValueError("Missing token claims.")

    except (
        jwt.InvalidTokenError,
        ValueError,
        TypeError,
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    # Verify database-backed session.
    session = db.execute(
        text("""
            SELECT id

            FROM user_sessions

            WHERE id = :session_id
              AND user_id = :user_id
              AND token_hash = :token_hash
              AND revoked_at IS NULL
              AND expires_at > NOW()

            LIMIT 1
        """),
        {
            "session_id": session_id,
            "user_id": user_id,
            "token_hash": hash_token(token),
        },
    ).first()

    if not session:

        raise HTTPException(
            status_code=401,
            detail="Session expired or revoked.",
        )

    # Always retrieve the current role and organization
    # from PostgreSQL rather than trusting JWT claims.
    user = db.execute(
        text("""
            SELECT
                u.id,
                u.full_name,
                u.email,
                u.organization_id,
                u.is_active,
                r.name AS role

            FROM users u

            JOIN roles r
                ON r.id = u.role_id

            WHERE u.id = :user_id

            LIMIT 1
        """),
        {
            "user_id": user_id,
        },
    ).mappings().first()

    if not user or not user["is_active"]:

        raise HTTPException(
            status_code=401,
            detail="User account is inactive.",
        )

    return {
        "id": str(user["id"]),
        "full_name": user["full_name"],
        "email": user["email"],
        "organization_id": (
            str(user["organization_id"])
            if user["organization_id"]
            else None
        ),
        "role": user["role"],
        "session_id": session_id,
    }


# =====================================================
# CURRENT USER ENDPOINT
# =====================================================

@router.get("/me")
def get_me(
    current_user=Depends(get_current_user),
):

    return {
        "success": True,
        "user": current_user,
    }


# =====================================================
# LOGOUT
# =====================================================

@router.post("/logout")
def logout(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):

    try:

        db.execute(
            text("""
                UPDATE user_sessions

                SET revoked_at = NOW()

                WHERE id = :session_id
                  AND user_id = :user_id
                  AND revoked_at IS NULL
            """),
            {
                "session_id": current_user["session_id"],
                "user_id": current_user["id"],
            },
        )

        db.commit()

        return {
            "success": True,
            "message": "Logged out successfully.",
        }

    except Exception as exc:

        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Logout could not be completed.",
        ) from exc


# =====================================================
# ROLE-BASED ACCESS CONTROL
# =====================================================

# Keep role names aligned with the existing PostgreSQL roles table.
ROLE_SUPER_ADMIN = "SUPER_ADMIN"
ROLE_ORG_ADMIN = "ORG_ADMIN"
ROLE_SECURITY_ANALYST = "SECURITY_ANALYST"
ROLE_VIEWER = "VIEWER"

VALID_ROLES = {
    ROLE_SUPER_ADMIN,
    ROLE_ORG_ADMIN,
    ROLE_SECURITY_ANALYST,
    ROLE_VIEWER,
}


def require_roles(*allowed_roles: str):
    """
    FastAPI dependency factory for server-side role authorization.

    Example:
        @router.delete("/users/{user_id}")
        def delete_user(
            current_user=Depends(require_roles("SUPER_ADMIN", "ORG_ADMIN"))
        ):
            ...

    SUPER_ADMIN is not implicitly granted access to every endpoint.
    Include it explicitly in allowed_roles when intended.
    """

    normalized_roles = {
        role.strip().upper()
        for role in allowed_roles
        if isinstance(role, str) and role.strip()
    }

    unknown_roles = normalized_roles - VALID_ROLES
    if not normalized_roles:
        raise ValueError("require_roles needs at least one valid role.")

    if unknown_roles:
        raise ValueError(
            "Unknown role(s): " + ", ".join(sorted(unknown_roles))
        )

    def role_checker(
        current_user=Depends(get_current_user),
    ):
        current_role = str(current_user.get("role", "")).upper()

        if current_role not in normalized_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource.",
            )

        return current_user

    return role_checker


def ensure_organization_access(
    current_user: dict,
    organization_id: str,
) -> None:
    """
    Enforce organization scope inside an API endpoint.

    Call this after obtaining current_user from get_current_user and before
    reading or changing organization-owned records.

    SUPER_ADMIN may access any organization. Other roles are restricted
    to the organization_id on their authenticated database user record.
    """

    if str(current_user.get("role", "")).upper() == ROLE_SUPER_ADMIN:
        return

    user_organization_id = current_user.get("organization_id")

    if (
        not user_organization_id
        or str(user_organization_id) != str(organization_id)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this organization.",
        )

# =====================================================
# ORGANIZATION INVITATIONS
# =====================================================

@router.post(
    "/invitations",
    status_code=status.HTTP_201_CREATED,
)
def create_organization_invitation(
    request: CreateInvitationRequest,
    current_user=Depends(require_roles(ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN)),
    db: Session = Depends(get_db),
):
    """Create a single-use, email-bound organization invitation."""

    current_role = str(current_user.get("role", "")).upper()
    requested_role = request.role.strip().upper()

    allowed_roles = {ROLE_VIEWER, ROLE_SECURITY_ANALYST}
    if current_role == ROLE_SUPER_ADMIN:
        allowed_roles.add(ROLE_ORG_ADMIN)

    if requested_role not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="You are not allowed to assign the requested invitation role.",
        )

    target_organization_id = (
        request.organization_id
        if current_role == ROLE_SUPER_ADMIN
        else current_user.get("organization_id")
    )

    if not target_organization_id:
        raise HTTPException(
            status_code=400,
            detail="An organization must be selected before creating an invitation.",
        )

    if (
        current_role != ROLE_SUPER_ADMIN
        and request.organization_id
        and str(request.organization_id) != str(current_user.get("organization_id"))
    ):
        raise HTTPException(
            status_code=403,
            detail="Organization administrators can only invite users to their own organization.",
        )

    invitation_code = secrets.token_urlsafe(32)
    code_hash = hash_token(invitation_code)
    invitation_email = request.email.lower().strip()
    expires_at = datetime.now(timezone.utc) + timedelta(
        days=request.expires_in_days
    )

    organization_name = None

    try:
        db.rollback()
        with db.begin():
            organization_record = db.execute(
                text("""
                    SELECT id, name
                    FROM organizations
                    WHERE id = :organization_id
                    LIMIT 1
                """),
                {"organization_id": target_organization_id},
            ).mappings().first()

            if not organization_record:
                raise HTTPException(status_code=404, detail="Organization not found.")

            organization_name = organization_record["name"]

            role_id = db.execute(
                text("""
                    SELECT id FROM roles
                    WHERE name = :role
                    LIMIT 1
                """),
                {"role": requested_role},
            ).scalar_one_or_none()

            if not role_id:
                raise HTTPException(
                    status_code=500,
                    detail="The requested role is not configured.",
                )

            invitation_id = db.execute(
                text("""
                    INSERT INTO organization_invitations (
                        organization_id, email, code_hash, role_id,
                        created_by, expires_at
                    )
                    VALUES (
                        :organization_id, :email, :code_hash, :role_id,
                        :created_by, :expires_at
                    )
                    RETURNING id
                """),
                {
                    "organization_id": target_organization_id,
                    "email": invitation_email,
                    "code_hash": code_hash,
                    "role_id": role_id,
                    "created_by": current_user["id"],
                    "expires_at": expires_at,
                },
            ).scalar_one()

            db.execute(
                text("""
                    INSERT INTO audit_logs (
                        organization_id, user_id, action,
                        entity_type, entity_id, details
                    )
                    VALUES (
                        :organization_id, :user_id,
                        'ORGANIZATION_INVITATION_CREATED',
                        'ORGANIZATION_INVITATION', :entity_id,
                        CAST(:details AS JSONB)
                    )
                """),
                {
                    "organization_id": target_organization_id,
                    "user_id": current_user["id"],
                    "entity_id": str(invitation_id),
                    "details": (
                        '{"email":"' + invitation_email
                        + '","role":"' + requested_role + '"}'
                    ),
                },
            )

        # The database transaction has committed before attempting email delivery.
        # If SMTP fails, keep the invitation valid for a later delivery retry.
        email_sent = send_invitation_email(
            recipient_email=invitation_email,
            invitation_code=invitation_code,
            organization_name=organization_name or "your organization",
            assigned_role=requested_role.replace("_", " ").title(),
            expires_at=expires_at.isoformat(),
        )

        return {
            "success": True,
            "message": (
                "Invitation created and the email was sent successfully."
                if email_sent
                else "Invitation created, but SMTP could not send the email. "
                     "The invitation remains valid; check the SMTP settings and retry."
            ),
            "invitation_id": str(invitation_id),
            "organization_id": str(target_organization_id),
            "email": invitation_email,
            "role": requested_role,
            "invitation_code": invitation_code,
            "expires_at": expires_at.isoformat(),
            "email_sent": email_sent,
            "email_status": "sent" if email_sent else "failed",
        }

    except HTTPException:
        db.rollback()
        raise
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="An invitation could not be created.",
        ) from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Invitation could not be created.",
        ) from exc

