"""
NexaGraph AI
Unified PostgreSQL-to-Neo4j Synchronization Engine

PostgreSQL = Source of Truth
Neo4j = Graph Representation

Features:
- Global synchronization
- Organization-specific synchronization
- Tenant isolation
- Module-level error handling
- JSON reports
- Execution timing
"""

import json
import logging
import time

from datetime import datetime
from pathlib import Path
from uuid import UUID

from backend.sync_assets import synchronize_assets
from backend.sync_network_relationships import (
    synchronize_network_relationships
)
from backend.sync_vulnerabilities import (
    synchronize_vulnerabilities
)
from backend.sync_incidents import synchronize_incidents
from backend.sync_security_events import synchronize_security_events


# ==========================================================
# LOGGING CONFIGURATION
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"

LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(
            LOG_DIR / "sync_engine.log",
            encoding="utf-8"
        ),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("NexaGraphSync")


# ==========================================================
# SYNCHRONIZATION MODULES
# ==========================================================

SYNC_MODULES = [
    ("assets", synchronize_assets),
    ("network_relationships", synchronize_network_relationships),
    ("vulnerabilities", synchronize_vulnerabilities),
    ("incidents", synchronize_incidents),
    ("security_events", synchronize_security_events),
]


# ==========================================================
# ORGANIZATION VALIDATION
# ==========================================================

def validate_organization_id(organization_id=None):
    """
    Validate organization UUID.

    None means global synchronization.
    """

    if organization_id is None:
        return None

    try:
        return str(UUID(str(organization_id)))

    except (ValueError, TypeError, AttributeError):
        raise ValueError(
            f"Invalid organization UUID: {organization_id}"
        )


# ==========================================================
# RESULT NORMALIZATION
# ==========================================================

def normalize_result(result):
    """Convert module results into a consistent dictionary."""

    if isinstance(result, dict):
        return result

    return {
        "status": "success",
        "result": str(result)
    }


def determine_status(result):
    """Determine synchronization module status."""

    status = str(
        result.get("status", "success")
    ).lower()

    if status in ("error", "failed", "failure"):
        return "failed"

    if status in ("partial_success", "partial"):
        return "partial_success"

    return "success"


# ==========================================================
# UNIFIED SYNCHRONIZATION
# ==========================================================

def run_unified_sync(organization_id=None):
    """
    Execute all synchronization modules.

    Global:
        run_unified_sync()

    Organization-specific:
        run_unified_sync(organization_id="UUID")
    """

    organization_id = validate_organization_id(
        organization_id
    )

    start_time = time.perf_counter()

    timestamp = datetime.now().astimezone().isoformat()

    logger.info("=" * 70)
    logger.info("NEXAGRAPH AI UNIFIED SYNCHRONIZATION STARTED")
    logger.info("Organization: %s", organization_id or "ALL")
    logger.info("=" * 70)

    module_results = []

    # ======================================================
    # EXECUTE MODULES
    # ======================================================

    for module_name, sync_function in SYNC_MODULES:

        module_start = time.perf_counter()

        logger.info(
            "Starting synchronization module: %s",
            module_name
        )

        try:

            result = normalize_result(
                sync_function(
                    organization_id=organization_id
                )
            )

            module_status = determine_status(result)

            duration = round(
                time.perf_counter() - module_start,
                3
            )

            module_results.append({

                "module": module_name,

                "status": module_status,

                "duration_seconds": duration,

                "details": result

            })

            logger.info(
                "Module %s completed: %s",
                module_name,
                module_status
            )

        except Exception as error:

            duration = round(
                time.perf_counter() - module_start,
                3
            )

            logger.exception(
                "Synchronization failed: %s",
                module_name
            )

            module_results.append({

                "module": module_name,

                "status": "failed",

                "duration_seconds": duration,

                "error": str(error)

            })

            # Continue with remaining modules.
            continue

    # ======================================================
    # OVERALL STATUS
    # ======================================================

    total_duration = round(
        time.perf_counter() - start_time,
        3
    )

    successful_modules = [
        item["module"]
        for item in module_results
        if item["status"] == "success"
    ]

    failed_modules = [
        item["module"]
        for item in module_results
        if item["status"] == "failed"
    ]

    partial_modules = [
        item["module"]
        for item in module_results
        if item["status"] == "partial_success"
    ]

    if failed_modules and not successful_modules and not partial_modules:
        overall_status = "failed"

    elif failed_modules or partial_modules:
        overall_status = "partial_success"

    else:
        overall_status = "success"

    # ======================================================
    # FINAL REPORT
    # ======================================================

    report = {

        "platform": "NexaGraph AI",

        "operation": (
            "Unified PostgreSQL-Neo4j Synchronization"
        ),

        "timestamp": timestamp,

        "organization_id": organization_id,

        "synchronization_scope": (
            "organization"
            if organization_id
            else "global"
        ),

        "status": overall_status,

        "total_modules": len(SYNC_MODULES),

        "successful_modules": len(successful_modules),

        "failed_modules": failed_modules,

        "partial_modules": partial_modules,

        "duration_seconds": total_duration,

        "modules": module_results

    }

    # ======================================================
    # SAVE JSON REPORT
    # ======================================================

    report_filename = (
        f"sync_report_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
    )

    report_path = LOG_DIR / report_filename

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as report_file:

        json.dump(
            report,
            report_file,
            indent=4,
            default=str
        )

    # ======================================================
    # FINAL LOGGING
    # ======================================================

    logger.info("=" * 70)
    logger.info("UNIFIED SYNCHRONIZATION FINISHED")
    logger.info("Organization: %s", organization_id or "ALL")
    logger.info("Overall status: %s", overall_status)

    logger.info(
        "Successful modules: %s",
        len(successful_modules)
    )

    logger.info(
        "Failed modules: %s",
        len(failed_modules)
    )

    logger.info(
        "Partial modules: %s",
        len(partial_modules)
    )

    logger.info(
        "Duration: %s seconds",
        total_duration
    )

    logger.info("Report: %s", report_path)
    logger.info("=" * 70)

    return report


# ==========================================================
# EXECUTION ENTRY POINT
# ==========================================================

if __name__ == "__main__":

    final_report = run_unified_sync()

    print("\nNEXAGRAPH AI SYNCHRONIZATION REPORT")

    print(
        json.dumps(
            final_report,
            indent=4,
            default=str
        )
    )