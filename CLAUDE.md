# CLAUDE.md — AI Assistant Guidelines for terraform-aws-log-enricher

This file governs how AI coding assistants (Claude Code, Cursor, Copilot, etc.) should interact with this repository. Follow every rule here. When in doubt, ask before acting.

---

## Project Context

`terraform-aws-log-enricher` is a production-grade, 100% AWS-native serverless Terraform module (Python 3.12 + Terraform ≥ 1.5) that enriches VPC Flow Logs in real-time with L3/L4 resource metadata and open-source Threat Intel, then delivers structured JSON to a configurable SIEM destination (S3, Datadog, or Splunk).

---

## Repository Structure

```
terraform-aws-log-enricher/
├── main.tf                   # Firehose stream, VPC Flow Logs, S3, EventBridge
├── variables.tf              # All input variables
├── outputs.tf                # Key resource ARNs/names
├── dynamodb.tf               # IP cache table with TTL
├── iam.tf                    # 4 least-privilege IAM roles
├── lambdas.tf                # Lambda packaging, functions, Log Groups, permissions
├── versions.tf               # Terraform + provider version constraints
│
├── functions/
│   ├── collector/
│   │   ├── collector.py      # Cold path: cache worker Lambda
│   │   └── requirements.txt
│   └── enricher/
│       ├── enricher.py       # Hot path: Firehose transformation Lambda
│       └── requirements.txt
│
├── tests/
│   ├── conftest.py           # sys.path setup for both function directories
│   ├── test_collector.py     # 14 unit tests
│   └── test_enricher.py      # 18 unit tests
│
└── examples/
    ├── s3/main.tf
    ├── datadog/main.tf
    └── splunk/main.tf
```

---

## Build & Test Commands

### Python tests (run from the repository root)

```bash
# Run the full test suite
pytest tests/ -v

# Run a single test file
pytest tests/test_collector.py -v
pytest tests/test_enricher.py -v

# Run a single test
pytest tests/test_enricher.py::TestLambdaHandler::test_returns_ok_result_for_valid_record -v

# Install test dependencies (one-time)
pip install pytest requests-mock boto3
```

Expected: **32 passed, 0 failed**.

The `tests/conftest.py` adds both `functions/collector` and `functions/enricher` to `sys.path` automatically — do not set `PYTHONPATH` manually.

### Terraform validation (run from the repository root)

```bash
# Initialize (required once, or after provider changes)
terraform init -backend=false

# Validate root module
terraform validate

# Format all .tf files
terraform fmt -recursive

# Validate examples
cd examples/s3    && terraform init && terraform validate && cd ../..
cd examples/datadog && terraform init && terraform validate && cd ../..
cd examples/splunk  && terraform init && terraform validate && cd ../..
```

All four `terraform validate` calls must return `Success! The configuration is valid.`

### Lint & format Python

```bash
# Format (PEP 8)
black functions/

# Type-check
mypy functions/ --strict
```

---

## Coding Standards — Python

### Language & runtime
- **Python 3.12** exclusively. No walrus operator workarounds, no `__future__` imports.
- Both Lambda functions must remain compatible with the **Python 3.12 AWS Lambda runtime** (`python3.12`).

### Type hints
- **Mandatory on every function signature** — parameters and return type.
- Use `str | None` (union syntax), not `Optional[str]`.
- Use `list[str]`, `dict[str, Any]`, not `List[str]`, `Dict[str, Any]`.
- `from typing import Any` is acceptable where the shape is genuinely dynamic.

### Standard library & dependencies

**Collector** (`functions/collector/`):
- Uses `boto3`, `requests` (pinned with `==` in `requirements.txt`).
- Pin all dependencies with exact versions (`requests==2.31.0`), never floor-pins (`>=`).

**Enricher** (`functions/enricher/`):
- **stdlib + boto3 only**. No third-party packages. Boto3 is pre-installed in the Lambda runtime and must NOT appear in `requirements.txt`.
- `functions/enricher/requirements.txt` stays empty (or contains only a comment).

### Module-level initialisation
- Constants and boto3 clients/resources initialised at **module level**, not inside `lambda_handler`. This enables warm-invocation reuse.
- `DYNAMODB_TABLE_NAME`, `AWS_REGION` are read from `os.environ` at import time. A missing env var should raise `KeyError` immediately (fail-fast), not silently default.

### Error handling
- The enricher's `lambda_handler` must handle errors **per record** — a single malformed record must never abort the entire Firehose batch. Return `result: "ProcessingFailed"` with the original base64 data preserved for that record only.
- The collector's threat-intel fetcher must tolerate per-feed failures (log a warning, continue to the next feed).

### Comments
- No comments that describe *what* code does — well-named identifiers do that.
- Comments are only for non-obvious constraints, workarounds, or invariants (e.g., "Field order MUST match log_format in main.tf").

### Testing
- Every new function must have a corresponding unit test added to `tests/`.
- Tests mock external calls (`boto3`, `requests`) — never hit real AWS or the internet.
- Use `patch.object(module, "function_name", ...)` to mock module-level functions (not `patch("path.to.function")`).
- Follow TDD: write failing tests first, then implement.
- Do not modify existing tests to make new code pass — fix the code instead.

---

## Coding Standards — Terraform

### Formatting
- **Always run `terraform fmt -recursive` before committing any `.tf` changes.**
- The CI check for formatting is `terraform fmt -check -recursive`. A non-zero exit code is a hard failure.

### Variables
- Every variable must have a `description` (non-empty) and an explicit `type`.
- Use the most specific type possible (`list(string)` over `any`).
- Sensitive variables (`datadog_api_key`, `splunk_hec_token`) must have `sensitive = true`.
- Validation blocks must cover any variable with constrained values (see `siem_destination_type`).

### Resources
- All resources must include `tags = var.tags` (or `tags = merge(var.tags, {...})`).
- Use `project_name` prefix on every resource name for clear namespacing.
- Prefer `for_each` over `count` for resources with meaningful keys (e.g., one per VPC).

### IAM
- Policies must follow least-privilege: scope every `Resource` to the specific ARN where possible.
- Never use `Resource = "*"` for data-write actions (DynamoDB, S3, Lambda invoke).
- `Resource = "*"` is acceptable only for EC2 Describe APIs (no alternative) and CloudWatch Logs `CreateLogGroup`.
- The `FlowLogsDeliveryRole` must keep the `aws:SourceAccount` confused-deputy condition — do not remove it.

### Lock files
- `.terraform.lock.hcl` files **must be committed** (root and each example). They pin provider versions for reproducibility. They are intentionally excluded from `.gitignore`.

---

## Architectural Boundaries

### v1.0 — Single-account only

The current release is **strictly single-account**. Do not implement cross-account logic in v1.0.

The multi-account extension point is already in place:

```python
# collector.py — the ONLY place cross-account logic belongs
def get_boto3_client(service: str, account_id: str | None = None, region: str | None = None):
    if account_id is None or account_id == LOCAL_ACCOUNT_ID:
        return boto3.client(service, region_name=region or AWS_REGION)
    # v2.0 hook: AssumeRole logic goes here
    raise NotImplementedError("Multi-account support coming in v2.0")
```

In v2.0, the `target_accounts` list in `lambda_handler` will be populated from AWS Organizations. The rest of the collector loop is already written to accept multiple accounts.

**Do not add AssumeRole calls, cross-account IAM roles, or Organizations API calls to v1.0 code.**

### Hot path vs. Cold path — keep them separated

| Concern | Where it lives |
|---------|---------------|
| EC2 metadata scanning | `collector.py` only |
| Threat Intel fetching | `collector.py` only |
| DynamoDB writes | `collector.py` only |
| DynamoDB reads | `enricher.py` only |
| Firehose transformation logic | `enricher.py` only |

The enricher must never write to DynamoDB. The collector must never be invoked by Firehose.

### Flow Log field order

The 17-field custom log format is defined in `main.tf` (`aws_flow_log.log_format`) and consumed in `enricher.py` (`FLOW_LOG_FIELDS`). **These two must always be in sync.** If you change the log format in Terraform, update `FLOW_LOG_FIELDS` in the same commit, and vice versa.

### Output schema

The output JSON structure is the public contract of this module. Do not rename or remove top-level keys (`enrichment`, `troubleshooting`, `source_asset`, `destination_asset`, `cache_miss`). Adding new keys to existing nodes is backward-compatible; removing or renaming keys is a breaking change requiring a major version bump.

### v2.0 is out of scope for all current PRs

If a proposed change mentions any of these, it belongs in a v2.0 branch:
- Multi-account / cross-account AssumeRole
- AWS Organizations-wide deployment via StackSets
- IPv6 fields in Flow Logs
- API-based Threat Intel (AbuseIPDB, VirusTotal)
- CloudWatch Dashboard or alerting resources

---

## Common Pitfalls

| Trap | Why it matters |
|------|---------------|
| Committing `.builds/*.zip` | Gitignored — never commit Lambda deployment packages |
| Removing `.terraform.lock.hcl` from git | These must be tracked to pin provider versions |
| Using `Resource = "*"` on DynamoDB writes | Violates least-privilege; scope to the table ARN |
| Adding third-party packages to the enricher | Enricher is stdlib + boto3 only — no pip install at deploy time |
| Floor-pinning dependencies (`>=`) in collector `requirements.txt` | Use exact pins (`==`) for deterministic Lambda builds |
| Calling `parse_flow_log_line` inside the batch-collection loop | Already called in `enrich_record` — calling twice wastes CPU on large batches |
| Removing the `aws:SourceAccount` condition from `FlowLogsDeliveryRole` | Opens confused-deputy vulnerability; VPC Flow Logs will write to Firehose from any account |
