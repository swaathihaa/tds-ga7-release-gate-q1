# CI/CD Container Release Gate

Deterministic policy endpoint `POST /release-gate` for gating container promotion
in GitHub Actions CI/CD, per TDS GA7.

## Run locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Test:

```bash
curl -X POST http://localhost:8000/release-gate \
  -H "Content-Type: application/json" \
  -d '{
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/pull/12/merge",
    "workflow": {
      "trigger": "pull_request",
      "permissions": {"contents":"read","packages":"write","id-token":"none"},
      "testsPassed": true, "matrixComplete": true, "failFast": false,
      "actions": [{"owner":"actions","name":"checkout","ref":"v4"}]
    },
    "image": {
      "multiStage": true, "runsAsRoot": false, "secretMode": "none",
      "criticalVulnerabilities": 0, "digestPinned": true
    }
  }'
```

## Deploy (Render free tier — zero cost)

1. Push this repo to a **public** GitHub repository.
2. On [render.com](https://render.com), create a new **Web Service** from the repo.
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Once live, the endpoint is `https://<your-service>.onrender.com/release-gate`.

## Submission checklist

- [ ] Repo is public.
- [ ] Workflow file at `.github/workflows/release-gate.yml`, named exactly
      `TDS GA7 Release Gate`, triggers on push to `main`.
- [ ] A step named exactly `TDS identity: 22f3002344@ds.study.iitm.ac.in` exists
      and the workflow has run **successfully** at least once on `main`.
- [ ] Submit the **workflow page URL** (e.g.
      `https://github.com/<user>/<repo>/actions/workflows/release-gate.yml`),
      not an individual run URL.
- [ ] Submit the deployed `/release-gate` endpoint URL for the hidden policy probes.

## Rule summary implemented in `app/main.py`

| Check | Violation code |
|---|---|
| `permissions` != exactly `{contents:read, packages:write, id-token:none}` | `EXCESS_PERMISSION` |
| `trigger == "pull_request_target"` | `UNSAFE_PR_TRIGGER` |
| tests not passed / matrix incomplete / `failFast` true | `TESTS_INCOMPLETE` |
| any non-`actions`-owned action ref isn't a 40-char lowercase hex SHA | `MUTABLE_ACTION` |
| `image.multiStage == false` | `SINGLE_STAGE_IMAGE` |
| `image.runsAsRoot == true` | `ROOT_RUNTIME` |
| `image.secretMode` in `{arg, copy}` | `SECRET_IN_LAYER` |
| `image.criticalVulnerabilities > 0` | `CRITICAL_CVE` |
| `image.digestPinned == false` | `UNPINNED_IMAGE` |
| target `production` and (`event != push` or `ref != refs/heads/main`) | `INVALID_PRODUCTION_REF` |
| target `production` and `workflow.environmentApproval != true` | `APPROVAL_REQUIRED` |

`decision` is `"promote"` only when `violations` is empty.
