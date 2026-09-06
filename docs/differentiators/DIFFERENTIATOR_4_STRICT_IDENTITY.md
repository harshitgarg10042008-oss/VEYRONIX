# Differentiator #4: Human Approval and Separation of Duties (Strict Identity) — Evidence Document

## Status

**Differentiator #4 Status**: IMPLEMENTED

## Overview

ConfigSentinel AI enforces strict server-derived identity and separation of duties to prevent unauthorized approvals, self-approvals, and role escalation. The governance system ensures that browser-supplied identity is never trusted in strict mode, and that approvals require independent reviewers.

## Implementation

### Governance Model (`src/configsentinel/governance.py`)

**Role-based permissions**:
- **OPERATOR**: Can request approval
- **REVIEWER**: Can approve/reject requests
- **ADMIN**: Can request and approve (but should not self-approve in production)

**Separation of duties enforcement**:
- Requester cannot approve their own request
- Only reviewers or administrators can decide approvals
- Only operators or administrators can request approvals
- Duplicate decisions are rejected
- Decision without prior request is rejected

**Ledger properties**:
- Append-only JSONL storage
- 2 MiB size limit
- Immutable event history
- Event ID, resource ID, actor ID, role, action, reason, timestamp

### Strict Identity Mode (`src/configsentinel/api.py`)

**Server-derived identity headers** (when `CONFIGSENTINEL_IDENTITY_REQUIRED=true`):
- `x-authenticated-user`: Actor ID (server-derived, not browser-supplied)
- `x-authenticated-role`: Role (server-validated)
- `x-authenticated-workspace`: Workspace ID (server-derived)

**Rejection conditions**:
- Missing identity headers → 403 Forbidden
- Empty identity values → 403 Forbidden
- Invalid role value → 403 Forbidden
- Browser-supplied identity ignored in strict mode

### Safety Boundaries

1. **No browser trust**: In strict mode, identity must come from server headers
2. **Self-approval prevention**: Requester cannot approve their own request
3. **Role enforcement**: Permission checks before every action
4. **Immutable ledger**: Events cannot be modified after writing
5. **Size limits**: Ledger cannot exceed 2 MiB
6. **Validation**: Invalid ledger data raises GovernanceError

## Test Coverage

### Strict Identity Tests (`tests/test_strict_identity.py`)

15 tests covering:
- Self-approval rejection
- Operator cannot approve without reviewer role
- Reviewer cannot request approval
- Duplicate decision rejection
- Decision without request rejection
- Strict mode requires server headers
- Strict mode rejects spoofed identity
- Strict mode rejects invalid role
- Strict mode rejects empty identity
- Strict mode accepts valid identity
- Admin can request and approve
- Ledger size limit enforcement
- Invalid ledger data rejection
- Empty actor_id or resource_id rejection
- Reason truncation (500 character limit)

**Test Results**: 15/15 passed

## Evidence Chain Example

```
1. Operator requests approval
   - Resource: resource-001
   - Actor: operator-001
   - Role: OPERATOR
   - Action: REQUEST

2. Reviewer approves (different actor)
   - Resource: resource-001
   - Actor: reviewer-001
   - Role: REVIEWER
   - Action: APPROVE
   - Separation of duties enforced

3. Ledger records both events
   - Immutable append-only JSONL
   - Timestamps for audit trail
```

## Differentiation from Existing Solutions

| Feature | ConfigSentinel AI | Typical Approval Systems |
|---------|-------------------|--------------------------|
| Server-derived identity | Required in strict mode | Often browser-supplied |
| Self-approval prevention | Enforced at ledger level | Often UI-only |
| Role-based permissions | Enforced at every action | Sometimes bypassable |
| Immutable ledger | Append-only JSONL | Often mutable database |
| Size limits | 2 MiB enforcement | Often unbounded |
| Invalid data rejection | GovernanceError on load | Silent corruption |

## Strict Mode Configuration

Enable strict identity mode:
```bash
export CONFIGSENTINEL_IDENTITY_REQUIRED=true
```

Required headers in strict mode:
```
x-authenticated-user: operator-001
x-authenticated-role: operator
x-authenticated-workspace: workspace-001
```

## Limitations

1. **In-memory ledger by default**: Production should use persistent file path
2. **No workspace isolation**: Current implementation doesn't enforce workspace boundaries
3. **No cross-workspace approval tests**: Tests focus on role-based separation
4. **No authorization escalation tests**: Tests don't cover privilege escalation attempts
5. **Manual header injection**: In production, reverse proxy must inject headers

## Future Enhancements

1. **Workspace isolation**: Enforce workspace boundaries in governance
2. **Cross-workspace approval tests**: Add tests for cross-workspace access blocking
3. **Authorization escalation tests**: Add tests for privilege escalation prevention
4. **Persistent ledger**: Use database-backed ledger for production
5. **Header injection**: Document reverse proxy configuration for header injection

## Commit Information

**Commit**: `feat: implement strict identity and separation of duties tests`  
**Files Changed**:
- `tests/test_strict_identity.py` (15 tests for strict identity)
- `docs/DIFFERENTIATOR_4_STRICT_IDENTITY.md` (this document)

## Test Results Summary

- Backend tests: 203 passed (including 15 new strict identity tests)
- Strict identity tests: 15 passed
- Total new tests: 15
- All existing governance tests remain passing
