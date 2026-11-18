"""
NexaGraph AI
Shared Neo4j Connection Manager

Provides reusable Neo4j driver management
for the entire backend.
"""

import os
import threading

from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

_driver = None
_driver_lock = threading.Lock()


def get_neo4j_driver():
    """
    Return a shared Neo4j driver.

    Creates the driver only when required.
    """

    global _driver

    if _driver is not None:
        return _driver

    with _driver_lock:

        if _driver is not None:
            return _driver

        if not all([
            NEO4J_URI,
            NEO4J_USER,
            NEO4J_PASSWORD
        ]):
            raise RuntimeError(
                "Neo4j configuration is incomplete. "
                "Check NEO4J_URI, NEO4J_USER and NEO4J_PASSWORD."
            )

        driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD),
            max_connection_pool_size=50,
            connection_timeout=15,
            max_connection_lifetime=3600,
        )

        try:
            driver.verify_connectivity()
        except Exception:
            driver.close()
            raise

        _driver = driver

    return _driver


def get_neo4j_session():
    """
    Create a session using the shared driver.

    Usage:
        with get_neo4j_session() as session:
            session.run(...)
    """

    driver = get_neo4j_driver()

    return driver.session(
        database=NEO4J_DATABASE
    )


def check_neo4j_connection():
    """Check Neo4j connectivity."""

    try:
        driver = get_neo4j_driver()

        driver.verify_connectivity()

        return {
            "status": "connected",
            "database": "neo4j",
        }

    except Exception as exc:

        return {
            "status": "disconnected",
            "database": "neo4j",
            "error": str(exc),
        }


def close_neo4j_driver():
    """Close the shared Neo4j driver."""

    global _driver

    with _driver_lock:

        if _driver is not None:
            _driver.close()
            _driver = None