from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.auth_routes import get_current_user
from backend.security_intelligence import analyze_security_events

router = APIRouter(
    prefix="/security-intelligence",
    tags=["Security Intelligence"],
)


def resolve_organization_id(
    requested_org_id: UUID,
    current_user: dict,
) -> str:
    """Restrict intelligence analysis to the authenticated user's tenant."""
    role = str(current_user.get("role", "")).upper()
    own_org_id = current_user.get("organization_id")

    if role == "SUPER_ADMIN":
        return str(requested_org_id)

    if not own_org_id or str(own_org_id) != str(requested_org_id):
        # Avoid disclosing whether another organization's data exists.
        raise HTTPException(
            status_code=404,
            detail="Security intelligence data not found",
        )

    return str(own_org_id)


@router.get("/analyze")
def analyze_organization_security(
    organization_id: UUID,
    hours: int = Query(default=24, ge=1, le=168),
    current_user: dict = Depends(get_current_user),
):
    org_id = resolve_organization_id(organization_id, current_user)

    try:
        return analyze_security_events(
            organization_id=org_id,
            hours=hours,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception:
        # Avoid exposing internal database or analysis details to clients.
        raise HTTPException(
            status_code=500,
            detail="Security intelligence analysis failed.",
        ) from None
