# Phase 2: Core Correctness and Authoritative Data

**Status:** In Progress  
**Objective:** Remove hardcoded values, ensure backend metadata is authoritative everywhere

## Completed Changes

### 1. SDK Version Authoritative ✅
- **Issue:** Frontend hardcoded SDK version as "0.3.0"
- **Fix:** 
  - Added `version` field to `/api/health` endpoint in `src/configsentinel/api.py`
  - Frontend fetches version from health endpoint on mount
  - Sidebar displays authoritative backend version
- **Commit:** `cf139a8f`

### 2. Fallback Vendor Fixed ✅
- **Issue:** Fallback report hardcoded vendor as "cisco_ios"
- **Fix:** Changed fallback vendor to "auto" to avoid hardcoded assumptions
- **Commit:** `cf139a8f`

### 3. Health Test Updated ✅
- **Issue:** Test failed after adding version field to health endpoint
- **Fix:** Updated test to accept version field and check individual fields
- **Commit:** `cf139a8f`

## Current Status

### Control Pack Page ✅
- Already uses `/api/control-pack` endpoint
- Fetches version and controls from backend
- Metrics are calculated from actual control pack data
- No hardcoded control data

### Vendor Detection ✅
- Frontend uses `/api/detect` endpoint for auto-detection
- Backend supports 5 vendors: cisco_ios, junos, firewall_generic, arista_eos, linux_nftables
- Frontend displays vendor from authoritative audit report
- No hardcoded vendor labels

### Upload Limits ✅
- Frontend: `MAX_CONFIG_BYTES = 5 * 1024 * 1024` (5 MB)
- Backend: `MAX_CONFIG_CHARS = 5 * 1024 * 1024` (5 MB)
- Limits are consistent

## Remaining P0 Issues

### 1. Findings Table Vendor Label
- **Issue:** Findings table uses `vendor` parameter which may not match report metadata
- **Location:** `frontend/client/src/pages/Home.tsx:89`
- **Fix:** Use `report.audit.vendor` instead of parameter

### 2. Control Pack Metrics
- **Issue:** Vendor count calculated from control pack, but may not reflect actual parser support
- **Location:** `frontend/client/src/pages/Home.tsx:195`
- **Status:** Already using backend data, may be acceptable

### 3. Posture Score Formula
- **Issue:** Score formula treats all controls equally, not severity-weighted
- **Location:** `frontend/client/src/pages/Home.tsx:66-73`
- **Fix:** Already severity-weighted, but may need documentation

## Next Steps

1. Fix findings table to use report vendor instead of parameter
2. Verify all metadata sources are backend-authoritative
3. Add regression tests for authoritative data flow
4. Document the authoritative data flow
