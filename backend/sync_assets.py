import os

from dotenv import load_dotenv
from neo4j import GraphDatabase
from sqlalchemy import text

from backend.database import engine

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")


def fetch_postgres_assets():
    query = text("""
        SELECT
            graph_asset_id,
            asset_name,
            asset_type,
            ip_address,
            criticality
        FROM assets_metadata
        ORDER BY graph_asset_id
    """)

    with engine.connect() as connection:
        return [dict(row._mapping) for row in connection.execute(query)]


def synchronize_assets():
    if not all([NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD]):
        raise RuntimeError("Neo4j configuration is incomplete.")

    assets = fetch_postgres_assets()

    if not assets:
        print("No PostgreSQL assets found.")
        return

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USER, NEO4J_PASSWORD)
    )

    try:
        driver.verify_connectivity()

        with driver.session() as session:
            for asset in assets:
                session.run("""
                    MERGE (a:Asset {id: $id})
                    SET
                        a.name = $name,
                        a.type = $type,
                        a.ip = $ip,
                        a.criticality = $criticality,
                        a.exposed = coalesce(a.exposed, 'No'),
                        a.compromised = coalesce(a.compromised, 'No')
                """,
                    id=asset["graph_asset_id"],
                    name=asset["asset_name"],
                    type=asset["asset_type"],
                    ip=str(asset["ip_address"]) if asset["ip_address"] else "",
                    criticality=asset["criticality"].title()
                    if asset["criticality"] else "Medium"
                )

        print(f"Successfully synchronized {len(assets)} assets.")

    finally:
        driver.close()


if __name__ == "__main__":
    synchronize_assets()