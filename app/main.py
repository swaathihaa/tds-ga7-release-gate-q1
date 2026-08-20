import re
from typing import List, Optional

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CI/CD Container Release Gate")

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}

UNSAFE_SECRET_MODES = {"arg", "copy"}


class ActionRef(BaseModel):
    owner: str
    name: str
    ref: str


class WorkflowMeta(BaseModel):
    trigger: str
    permissions: dict
    testsPassed: bool
    matrixComplete: bool
    failFast: bool
    actions: List[ActionRef] = []
    environmentApproval: Optional[bool] = None


class ImageMeta(BaseModel):
    multiStage: bool
    runsAsRoot: bool
    secretMode: str
    criticalVulnerabilities: int
    digestPinned: bool


class ReleaseGateRequest(BaseModel):
    target: str
    event: str
    ref: str
    workflow: WorkflowMeta
    image: ImageMeta


class ReleaseGateResponse(BaseModel):
    decision: str
    violations: List[str]


def evaluate(req: ReleaseGateRequest) -> List[str]:
    violations: List[str] = []
    wf = req.workflow
    img = req.image

    # 1. Least-privilege permissions
    if wf.permissions != REQUIRED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # 2. PR trigger safety
    if wf.trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Test / matrix completeness
    if (not wf.testsPassed) or (not wf.matrixComplete) or wf.failFast:
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    for action in wf.actions:
        if action.owner == "actions":
            continue
        if not SHA_RE.match(action.ref):
            violations.append("MUTABLE_ACTION")
            break

    # 5. Image hardening
    if not img.multiStage:
        violations.append("SINGLE_STAGE_IMAGE")

    if img.runsAsRoot:
        violations.append("ROOT_RUNTIME")

    if img.secretMode in UNSAFE_SECRET_MODES:
        violations.append("SECRET_IN_LAYER")

    if img.criticalVulnerabilities > 0:
        violations.append("CRITICAL_CVE")

    if not img.digestPinned:
        violations.append("UNPINNED_IMAGE")

    # 6. Production-only requirements
    if req.target == "production":
        if req.event != "push" or req.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if wf.environmentApproval is not True:
            violations.append("APPROVAL_REQUIRED")

    return violations


@app.post("/release-gate", response_model=ReleaseGateResponse)
def release_gate(req: ReleaseGateRequest) -> ReleaseGateResponse:
    violations = evaluate(req)
    decision = "promote" if not violations else "block"
    return ReleaseGateResponse(decision=decision, violations=violations)


@app.get("/")
def root():
    return {"status": "ok", "service": "release-gate"}
