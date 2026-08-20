from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

GOOD_PERMS = {"contents": "read", "packages": "write", "id-token": "none"}
GOOD_ACTIONS = [
    {"owner": "actions", "name": "checkout", "ref": "v4"},
    {
        "owner": "docker",
        "name": "build-push-action",
        "ref": "a" * 40,
    },
]
GOOD_IMAGE = {
    "multiStage": True,
    "runsAsRoot": False,
    "secretMode": "buildkit",
    "criticalVulnerabilities": 0,
    "digestPinned": True,
}


def base_preview_payload():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/pull/12/merge",
        "workflow": {
            "trigger": "pull_request",
            "permissions": GOOD_PERMS,
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": GOOD_ACTIONS,
        },
        "image": GOOD_IMAGE,
    }


def base_production_payload():
    return {
        "target": "production",
        "event": "push",
        "ref": "refs/heads/main",
        "workflow": {
            "trigger": "push",
            "permissions": GOOD_PERMS,
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": GOOD_ACTIONS,
            "environmentApproval": True,
        },
        "image": GOOD_IMAGE,
    }


def test_healthy_preview_promotes():
    r = client.post("/release-gate", json=base_preview_payload())
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "promote"
    assert body["violations"] == []


def test_healthy_production_promotes():
    r = client.post("/release-gate", json=base_production_payload())
    body = r.json()
    assert body["decision"] == "promote"
    assert body["violations"] == []


def test_excess_permission():
    payload = base_preview_payload()
    payload["workflow"]["permissions"] = {**GOOD_PERMS, "actions": "write"}
    body = client.post("/release-gate", json=payload).json()
    assert "EXCESS_PERMISSION" in body["violations"]
    assert body["decision"] == "block"


def test_unsafe_pr_trigger():
    payload = base_preview_payload()
    payload["workflow"]["trigger"] = "pull_request_target"
    body = client.post("/release-gate", json=payload).json()
    assert "UNSAFE_PR_TRIGGER" in body["violations"]


def test_tests_incomplete_variants():
    for field, value in [
        ("testsPassed", False),
        ("matrixComplete", False),
        ("failFast", True),
    ]:
        payload = base_preview_payload()
        payload["workflow"][field] = value
        body = client.post("/release-gate", json=payload).json()
        assert "TESTS_INCOMPLETE" in body["violations"], field


def test_mutable_action():
    payload = base_preview_payload()
    payload["workflow"]["actions"] = [
        {"owner": "docker", "name": "build-push-action", "ref": "v5"}
    ]
    body = client.post("/release-gate", json=payload).json()
    assert "MUTABLE_ACTION" in body["violations"]


def test_actions_owner_may_use_tag():
    payload = base_preview_payload()
    payload["workflow"]["actions"] = [
        {"owner": "actions", "name": "setup-python", "ref": "v5"}
    ]
    body = client.post("/release-gate", json=payload).json()
    assert "MUTABLE_ACTION" not in body["violations"]


def test_image_violations():
    payload = base_preview_payload()
    payload["image"] = {
        "multiStage": False,
        "runsAsRoot": True,
        "secretMode": "copy",
        "criticalVulnerabilities": 3,
        "digestPinned": False,
    }
    body = client.post("/release-gate", json=payload).json()
    for code in [
        "SINGLE_STAGE_IMAGE",
        "ROOT_RUNTIME",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE",
    ]:
        assert code in body["violations"]


def test_secret_mode_none_is_safe():
    payload = base_preview_payload()
    payload["image"]["secretMode"] = "none"
    body = client.post("/release-gate", json=payload).json()
    assert "SECRET_IN_LAYER" not in body["violations"]


def test_production_wrong_ref():
    payload = base_production_payload()
    payload["ref"] = "refs/heads/develop"
    body = client.post("/release-gate", json=payload).json()
    assert "INVALID_PRODUCTION_REF" in body["violations"]


def test_production_wrong_event():
    payload = base_production_payload()
    payload["event"] = "pull_request"
    body = client.post("/release-gate", json=payload).json()
    assert "INVALID_PRODUCTION_REF" in body["violations"]


def test_production_requires_approval():
    payload = base_production_payload()
    payload["workflow"]["environmentApproval"] = False
    body = client.post("/release-gate", json=payload).json()
    assert "APPROVAL_REQUIRED" in body["violations"]


def test_multi_failure_combination():
    payload = base_production_payload()
    payload["workflow"]["permissions"] = {"contents": "write"}
    payload["workflow"]["testsPassed"] = False
    payload["image"]["runsAsRoot"] = True
    payload["workflow"]["environmentApproval"] = False
    body = client.post("/release-gate", json=payload).json()
    assert body["decision"] == "block"
    for code in [
        "EXCESS_PERMISSION",
        "TESTS_INCOMPLETE",
        "ROOT_RUNTIME",
        "APPROVAL_REQUIRED",
    ]:
        assert code in body["violations"]
