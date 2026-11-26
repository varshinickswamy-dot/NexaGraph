
import pytest
from fastapi.testclient import TestClient

import main


client = TestClient(main.app)


@pytest.fixture
def mock_graph(monkeypatch):
    """Provide an isolated graph without connecting to Neo4j."""
    nodes = [
        {
            "id": "A01",
            "name": "Internet",
            "type": "External",
            "criticality": "Low",
            "exposed": "Yes",
            "compromised": "No",
        },
        {
            "id": "A02",
            "name": "Web-Server",
            "type": "Server",
            "criticality": "High",
            "exposed": "Yes",
            "compromised": "No",
        },
        {
            "id": "A06",
            "name": "Customer-DB",
            "type": "Database",
            "criticality": "Critical",
            "exposed": "No",
            "compromised": "No",
        },
    ]

    edges = [
        {
            "source": "A01",
            "target": "A02",
            "relationship": "CONNECTS",
        },
        {
            "source": "A02",
            "target": "A06",
            "relationship": "CONNECTS",
        },
    ]

    original_nodes = [dict(node) for node in nodes]
    original_edges = [dict(edge) for edge in edges]

    # Keep the production authentication dependency enabled while supplying
    # an isolated authenticated organization-scoped user to this API test.
    monkeypatch.setitem(
        main.app.dependency_overrides,
        main.get_current_user,
        lambda: {
            "id": "ci-test-user",
            "full_name": "CI Test User",
            "email": "ci-test@example.invalid",
            "organization_id": "ci-test-organization",
            "role": "ANALYST",
            "session_id": "ci-test-session",
        },
    )

    monkeypatch.setattr(
        main,
        "graph_data",
        lambda organization_id=None: {"nodes": nodes, "edges": edges},
    )

    return original_nodes, original_edges


def test_remove_connection_success(mock_graph):
    response = client.post(
        "/simulate-remediation",
        json={
            "action_type": "remove-connection",
            "source_id": "A02",
            "destination_id": "A06",
            "relationship": "CONNECTS",
        },
    )

    assert response.status_code == 200

    data = response.json()
    assert data["simulated_only"] is True
    assert data["database_modified"] is False
    assert data["before"]["total_paths"] == 2
    assert data["after"]["total_paths"] == 0
    assert data["paths_eliminated"] == 1


def test_isolate_asset_success(mock_graph):
    response = client.post(
        "/simulate-remediation",
        json={
            "action_type": "isolate-asset",
            "target_id": "A02",
        },
    )

    assert response.status_code == 200

    data = response.json()
    assert data["simulated_only"] is True
    assert data["database_modified"] is False
    assert data["after"]["total_paths"] == 0


def test_isolate_asset_missing_target_id(mock_graph):
    response = client.post(
        "/simulate-remediation",
        json={"action_type": "isolate-asset"},
    )

    assert response.status_code == 400


def test_isolate_nonexistent_asset(mock_graph):
    response = client.post(
        "/simulate-remediation",
        json={
            "action_type": "isolate-asset",
            "target_id": "UNKNOWN",
        },
    )

    assert response.status_code == 404


def test_remove_connection_missing_fields(mock_graph):
    response = client.post(
        "/simulate-remediation",
        json={
            "action_type": "remove-connection",
            "source_id": "A02",
        },
    )

    assert response.status_code == 400


def test_remove_nonexistent_connection(mock_graph):
    response = client.post(
        "/simulate-remediation",
        json={
            "action_type": "remove-connection",
            "source_id": "A01",
            "destination_id": "A06",
            "relationship": "CONNECTS",
        },
    )

    assert response.status_code == 404


def test_invalid_relationship_type(mock_graph):
    response = client.post(
        "/simulate-remediation",
        json={
            "action_type": "remove-connection",
            "source_id": "A02",
            "destination_id": "A06",
            "relationship": "INVALID TYPE!",
        },
    )

    assert response.status_code == 400


def test_invalid_action_type(mock_graph):
    response = client.post(
        "/simulate-remediation",
        json={"action_type": "delete-everything"},
    )

    assert response.status_code == 400


def test_simulation_does_not_mutate_original_graph(
    mock_graph,
):
    original_nodes, original_edges = mock_graph

    response = client.post(
        "/simulate-remediation",
        json={
            "action_type": "isolate-asset",
            "target_id": "A02",
        },
    )

    assert response.status_code == 200

    current_graph = main.graph_data("ci-test-organization")

    assert current_graph["nodes"] == original_nodes
    assert current_graph["edges"] == original_edges
