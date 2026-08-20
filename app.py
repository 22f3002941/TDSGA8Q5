# app.py
#
# Stateful two-phase candidate-admission API: POST /quantize
# Phases: "freeze" and "select"
#
# Run with:
#   uvicorn app:app --reload
#
# This implementation follows the assignment spec closely:
# - Validates inputs strictly
# - Computes inventory, totalBytes, packageDigest exactly as specified
# - Persists freeze responses by freezeId
# - Enforces idempotent replay and FREEZE_ID_CONFLICT on mismatch
# - In select phase, recomputes and validates manifest, policy, predictions
# - Computes aggregate and slice accuracies, applies floors and limits
# - Selects best admitted candidate by (totalBytes, latencyMs, candidateOrder)

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import JSONResponse

app = FastAPI()

# In-memory store:
# FROZEN_STORE[freezeId] = {
#   "request": <original freeze request dict>,
#   "response": <freeze response dict returned to client>
# }
FROZEN_STORE: Dict[str, Dict[str, Any]] = {}


# -------------------------
# Utility functions
# -------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utf8_bytes(s: str) -> bytes:
    return s.encode("utf-8")


def utf8_len(s: str) -> int:
    return len(utf8_bytes(s))


def compact_json(obj: Any) -> str:
    # Compact JSON with no spaces; dict key order preserved (Python 3.7+)
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def compute_inventory(files: Dict[str, str]) -> Tuple[List[Dict[str, Any]], Optional[int], Optional[str]]:
    """
    Given {filename: utf8_text}, compute:
      - inventory list sorted by filename, each item: {"name": ..., "bytes": ..., "sha256": ...}
      - totalBytes (sum) or None if invalid
      - packageDigest = SHA-256(compact JSON of inventory) or None if invalid

    For this implementation, we assume all file strings are valid UTF-8
    (FastAPI already validated JSON). If any issue arises, we return None for totals.
    """
    try:
        inventory_items = []
        for fname, content in files.items():
            if not isinstance(fname, str) or not fname:
                raise ValueError("Invalid filename")
            if not isinstance(content, str):
                raise ValueError("Invalid file content")
            b = utf8_bytes(content)
            item = {"name": fname, "bytes": len(b), "sha256": sha256_hex(b)}
            inventory_items.append(item)

        # Sort by name (UTF-8)
        inventory_items.sort(key=lambda x: x["name"])

        total_bytes = sum(it["bytes"] for it in inventory_items)

        # packageDigest = SHA-256(compact JSON of inventory)
        pkg_json = compact_json(inventory_items)
        pkg_digest = sha256_hex(utf8_bytes(pkg_json))

        return inventory_items, total_bytes, pkg_digest

    except Exception:
        # Invalid files
        return [], None, None


def sort_reason_codes(codes: List[str]) -> List[str]:
    # Sort and deduplicate by UTF-8 bytes
    unique = sorted(set(codes), key=lambda x: x.encode("utf-8"))
    return unique


def validate_freeze_input(data: Dict[str, Any]) -> bool:
    """
    Basic structural validation for freeze input.
    Returns True if valid, else False.
    """
    if not isinstance(data, dict):
        return False

    # Required top-level keys
    required_keys = ["phase", "freezeId", "calibrationDigest", "tokenizerDigest",
                     "allowedUnsupportedReasons", "candidates"]
    if not all(k in data for k in required_keys):
        return False

    if data.get("phase") != "freeze":
        return False

    # freezeId: non-empty string, max 128 chars
    freeze_id = data.get("freezeId")
    if not isinstance(freeze_id, str) or not freeze_id or len(freeze_id) > 128:
        return False

    # digests: non-empty strings
    cal_digest = data.get("calibrationDigest")
    tok_digest = data.get("tokenizerDigest")
    if not isinstance(cal_digest, str) or not cal_digest:
        return False
    if not isinstance(tok_digest, str) or not tok_digest:
        return False

    # allowedUnsupportedReasons: list of non-empty unique strings
    allowed = data.get("allowedUnsupportedReasons")
    if not isinstance(allowed, list) or len(allowed) == 0:
        return False
    seen_reasons = set()
    for r in allowed:
        if not isinstance(r, str) or not r:
            return False
        if r in seen_reasons:
            return False
        seen_reasons.add(r)

    # candidates: non-empty list
    candidates = data.get("candidates")
    if not isinstance(candidates, list) or len(candidates) == 0:
        return False

    seen_names = set()
    for cand in candidates:
        if not isinstance(cand, dict):
            return False
        # Required keys in candidate
        c_req = ["name", "files", "loadable", "calibrationDigest", "tokenizerDigest"]
        if not all(k in cand for k in c_req):
            return False

        name = cand.get("name")
        if not isinstance(name, str) or not name:
            return False
        if name in seen_names:
            return False
        seen_names.add(name)

        # unsupportedReason optional, but if present must be non-empty string
        ureason = cand.get("unsupportedReason")
        if ureason is not None:
            if not isinstance(ureason, str) or not ureason:
                return False

        # files: non-empty object of unique filenames -> UTF-8 strings
        files = cand.get("files")
        if not isinstance(files, dict) or len(files) == 0:
            return False
        seen_fnames = set()
        for fn, fc in files.items():
            if not isinstance(fn, str) or not fn:
                return False
            if fn in seen_fnames:
                return False
            seen_fnames.add(fn)
            if not isinstance(fc, str):
                return False

        # loadable: bool
        if not isinstance(cand.get("loadable"), bool):
            return False

        # digests in candidate: non-empty strings
        cd_cal = cand.get("calibrationDigest")
        cd_tok = cand.get("tokenizerDigest")
        if not isinstance(cd_cal, str) or not cd_cal:
            return False
        if not isinstance(cd_tok, str) or not cd_tok:
            return False

    return True


def freeze_requests_equal(req1: Dict[str, Any], req2: Dict[str, Any]) -> bool:
    """
    Check if two freeze requests are exactly equal (for idempotent replay).
    We compare the full JSON-serialized form to avoid subtle dict ordering issues.
    """
    return compact_json(req1) == compact_json(req2)


def process_freeze_candidate(
    cand: Dict[str, Any],
    req_cal_digest: str,
    req_tok_digest: str,
    allowed_reasons: List[str]
) -> Dict[str, Any]:
    """
    Process a single candidate in freeze phase and return the response object.
    """
    name = cand["name"]
    files = cand["files"]
    loadable = cand["loadable"]
    cal_digest = cand["calibrationDigest"]
    tok_digest = cand["tokenizerDigest"]
    u_reason = cand.get("unsupportedReason")  # may be None

    # Compute inventory, totalBytes, packageDigest
    inventory, total_bytes, pkg_digest = compute_inventory(files)

    reason_codes: List[str] = []
    status: str = "frozen"

    # If files invalid (inventory empty and total_bytes None), mark invalid
    if total_bytes is None:
        # Invalid files -> status invalid, inventory empty, totalBytes/packageDigest null
        return {
            "name": name,
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": sort_reason_codes(["INVALID_INPUT"])
        }

    # Determine status and reason codes
    if u_reason is not None:
        # Candidate has unsupportedReason
        if u_reason not in allowed_reasons:
            reason_codes.append("UNALLOWED_UNSUPPORTED_REASON")
            status = "invalid"
        else:
            status = "unsupported"
        # "Any reason makes its status invalid" is interpreted as:
        # if unsupportedReason exists and is allowed -> unsupported
        # if unsupportedReason exists and not allowed -> invalid
    else:
        # No unsupportedReason: must be loadable and match digests
        if not loadable:
            reason_codes.append("NOT_LOADABLE")
            status = "invalid"
        if cal_digest != req_cal_digest:
            reason_codes.append("CALIBRATION_MISMATCH")
            status = "invalid"
        if tok_digest != req_tok_digest:
            reason_codes.append("TOKENIZER_MISMATCH")
            status = "invalid"

        if not reason_codes:
            status = "frozen"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": pkg_digest,
        "reasonCodes": sort_reason_codes(reason_codes)
    }


def handle_freeze(data: Dict[str, Any]) -> Response:
    # Validate input structure
    if not validate_freeze_input(data):
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    freeze_id = data["freezeId"]

    # Check for existing freezeId
    if freeze_id in FROZEN_STORE:
        stored_req = FROZEN_STORE[freeze_id]["request"]
        if freeze_requests_equal(stored_req, data):
            # Idempotent replay: return stored response unchanged
            return JSONResponse(
                status_code=200,
                content=FROZEN_STORE[freeze_id]["response"]
            )
        else:
            # Conflict
            return JSONResponse(
                status_code=409,
                content={"error": "FREEZE_ID_CONFLICT"}
            )

    # Process candidates
    req_cal_digest = data["calibrationDigest"]
    req_tok_digest = data["tokenizerDigest"]
    allowed_reasons = data["allowedUnsupportedReasons"]
    candidates = data["candidates"]

    processed_candidates = []
    for cand in candidates:
        pc = process_freeze_candidate(cand, req_cal_digest, req_tok_digest, allowed_reasons)
        processed_candidates.append(pc)

    # Sort candidates by name (UTF-8)
    processed_candidates.sort(key=lambda c: c["name"].encode("utf-8"))

    response_obj = {
        "freezeId": freeze_id,
        "candidates": processed_candidates
    }

    # Persist
    FROZEN_STORE[freeze_id] = {
        "request": deepcopy(data),
        "response": deepcopy(response_obj)
    }

    return JSONResponse(status_code=200, content=response_obj)


# -------------------------
# Select phase helpers
# -------------------------


def validate_select_structure(data: Dict[str, Any]) -> bool:
    """
    Basic structural validation for select input.
    """
    if not isinstance(data, dict):
        return False
    if data.get("phase") != "select":
        return False

    required_keys = ["freezeId", "candidates", "policy", "latencies", "rows"]
    if not all(k in data for k in required_keys):
        return False

    # freezeId: non-empty string
    if not isinstance(data["freezeId"], str) or not data["freezeId"]:
        return False

    # candidates: non-empty array
    cands = data["candidates"]
    if not isinstance(cands, list) or len(cands) == 0:
        return False

    # policy: object
    policy = data["policy"]
    if not isinstance(policy, dict):
        return False

    # rows: non-empty array
    rows = data["rows"]
    if not isinstance(rows, list) or len(rows) == 0:
        return False

    # latencies: object (can be empty, but must be dict)
    if not isinstance(data["latencies"], dict):
        return False

    # Additional policy checks (basic)
    # maxBytes: non-negative int
    if "maxBytes" not in policy:
        return False
    mb = policy["maxBytes"]
    if not isinstance(mb, int) or mb < 0:
        return False

    # aggregateFloor: float in [0,1]
    if "aggregateFloor" not in policy:
        return False
    af = policy["aggregateFloor"]
    if not isinstance(af, (int, float)) or af < 0 or af > 1:
        return False

    # requiredSlices: dict mapping slice->floor in [0,1]
    if "requiredSlices" not in policy:
        return False
    rs = policy["requiredSlices"]
    if not isinstance(rs, dict):
        return False
    for sname, sfloor in rs.items():
        if not isinstance(sname, str) or not sname:
            return False
        if not isinstance(sfloor, (int, float)) or sfloor < 0 or sfloor > 1:
            return False

    # maxLatencyMs: non-negative number
    if "maxLatencyMs" not in policy:
        return False
    ml = policy["maxLatencyMs"]
    if not isinstance(ml, (int, float)) or ml < 0:
        return False

    # candidateOrder: list of unique non-empty strings
    if "candidateOrder" not in policy:
        return False
    co = policy["candidateOrder"]
    if not isinstance(co, list) or len(co) == 0:
        return False
    seen_co = set()
    for cn in co:
        if not isinstance(cn, str) or not cn:
            return False
        if cn in seen_co:
            return False
        seen_co.add(cn)

    # Validate each candidate in request (must be a dict with expected keys)
    for c in cands:
        if not isinstance(c, dict):
            return False
        c_req_keys = ["name", "status", "inventory", "totalBytes", "packageDigest", "reasonCodes"]
        if not all(k in c for k in c_req_keys):
            return False
        if not isinstance(c["name"], str) or not c["name"]:
            return False
        if not isinstance(c["status"], str) or c["status"] not in ("frozen", "unsupported", "invalid"):
            return False
        if not isinstance(c["inventory"], list):
            return False
        # inventory items: each must have name, bytes, sha256
        for inv in c["inventory"]:
            if not isinstance(inv, dict):
                return False
            if not all(k in inv for k in ("name", "bytes", "sha256")):
                return False
            if not isinstance(inv["name"], str) or not inv["name"]:
                return False
            if not isinstance(inv["bytes"], int) or inv["bytes"] < 0:
                return False
            if not isinstance(inv["sha256"], str) or not inv["sha256"]:
                return False
        # totalBytes: int or null
        tb = c["totalBytes"]
        if tb is not None and (not isinstance(tb, int) or tb < 0):
            return False
        # packageDigest: string or null
        pd = c["packageDigest"]
        if pd is not None and (not isinstance(pd, str) or not pd):
            return False
        # reasonCodes: list of strings
        if not isinstance(c["reasonCodes"], list):
            return False
        for rc in c["reasonCodes"]:
            if not isinstance(rc, str):
                return False

    # Validate rows structure
    for row in rows:
        if not isinstance(row, dict):
            return False
        if "label" not in row or "slice" not in row or "predictions" not in row:
            return False
        if not isinstance(row["label"], int):
            return False
        if not isinstance(row["slice"], str) or not row["slice"]:
            return False
        preds = row["predictions"]
        if not isinstance(preds, dict):
            return False
        for cname, cpred in preds.items():
            if not isinstance(cname, str) or not cname:
                return False
            # predictions should be 0/1 (binary)
            if cpred not in (0, 1):
                return False

    # Validate latencies values (finite, non-negative)
    for cname, lat in data["latencies"].items():
        if not isinstance(cname, str) or not cname:
            return False
        if not isinstance(lat, (int, float)) or lat < 0:
            return False

    return True


def recompute_manifest_from_original_files(
    original_cand: Dict[str, Any]
) -> Tuple[List[Dict[str, Any]], Optional[int], Optional[str]]:
    """
    Recompute inventory, totalBytes, packageDigest from original files.
    original_cand is from the stored freeze request (has "files").
    """
    files = original_cand["files"]
    return compute_inventory(files)


def handle_select(data: Dict[str, Any]) -> Response:
    # Validate structure
    if not validate_select_structure(data):
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    freeze_id = data["freezeId"]
    req_candidates = data["candidates"]  # These are the frozen candidate objects
    policy = data["policy"]
    latencies = data["latencies"]
    rows = data["rows"]

    # Check freezeId exists
    if freeze_id not in FROZEN_STORE:
        # All candidates are NOT_FROZEN
        results = []
        for c in req_candidates:
            results.append({
                "name": c["name"],
                "aggregate": None,
                "slices": None,
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": sort_reason_codes(["NOT_FROZEN"])
            })
        # Order results by candidateOrder, fallback to name
        results = order_results_by_candidate_order(results, policy["candidateOrder"])
        response_obj = {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }
        return JSONResponse(status_code=200, content=response_obj)

    stored = FROZEN_STORE[freeze_id]
    stored_response = stored["response"]
    stored_request = stored["request"]

    stored_candidates = stored_response["candidates"]

    # Check that req_candidates exactly equals stored_candidates (as sets, sorted by name)
    def sort_cands_by_name(cands: List[Dict]) -> List[Dict]:
        return sorted(cands, key=lambda c: c["name"].encode("utf-8"))

    req_sorted = sort_cands_by_name(req_candidates)
    stored_sorted = sort_cands_by_name(stored_candidates)

    lineage_valid = True
    if len(req_sorted) != len(stored_sorted):
        lineage_valid = False
    else:
        for rc, sc in zip(req_sorted, stored_sorted):
            if compact_json(rc) != compact_json(sc):
                lineage_valid = False
                break

    # Also check candidate names match candidateOrder set
    candidate_order = policy["candidateOrder"]
    req_names = {c["name"] for c in req_candidates}
    co_names = set(candidate_order)

    if req_names != co_names:
        # Candidate names and candidateOrder must be same unique set
        # Treat as invalid policy/lineage; we'll mark INVALID_LINEAGE
        lineage_valid = False

    # Recompute manifest for each candidate from original files
    # Build a map: name -> original candidate (from stored_request.candidates)
    original_candidates_map = {}
    for oc in stored_request["candidates"]:
        original_candidates_map[oc["name"]] = oc

    manifest_valid = True
    recomputed_map = {}  # name -> (inventory, totalBytes, packageDigest)

    for sc in stored_candidates:
        name = sc["name"]
        if name not in original_candidates_map:
            manifest_valid = False
            recomputed_map[name] = ([], None, None)
            continue

        orig_cand = original_candidates_map[name]
        inv, tb, pd = recompute_manifest_from_original_files(orig_cand)

        # Compare with stored
        stored_inv = sc["inventory"]
        stored_tb = sc["totalBytes"]
        stored_pd = sc["packageDigest"]

        # Compare inventory (sorted by name already)
        if compact_json(inv) != compact_json(stored_inv):
            manifest_valid = False
        if tb != stored_tb:
            manifest_valid = False
        if pd != stored_pd:
            manifest_valid = False

        recomputed_map[name] = (inv, tb, pd)

    # Policy validity: already structurally validated; we assume valid here.
    # But we must check candidateOrder vs candidate names already done above.

    # Build results per candidate
    results = []
    candidate_order_map = {name: idx for idx, name in enumerate(candidate_order)}

    for c in req_candidates:
        name = c["name"]
        reason_codes: List[str] = []

        # Start with lineage/manifest checks
        if not lineage_valid:
            reason_codes.append("INVALID_LINEAGE")

        if not manifest_valid:
            reason_codes.append("INVALID_MANIFEST")

        # Check if candidate is frozen
        stored_cand = next((sc for sc in stored_candidates if sc["name"] == name), None)
        if stored_cand is None or stored_cand["status"] != "frozen":
            reason_codes.append("NOT_FROZEN")

        # Predictions validity
        predictions_valid = True
        for row in rows:
            preds = row["predictions"]
            if name not in preds:
                predictions_valid = False
                break
            pval = preds[name]
            if pval not in (0, 1):
                predictions_valid = False
                break

        if not predictions_valid:
            reason_codes.append("INVALID_PREDICTIONS")

        # Compute metrics
        aggregate = None
        slices = None
        total_bytes = None
        latency_ms = None

        if predictions_valid:
            # Compute aggregate accuracy
            matches = 0
            total = len(rows)
            for row in rows:
                pred = row["predictions"][name]
                label = row["label"]
                if pred == label:
                    matches += 1
            aggregate = round(matches / total, 12) if total > 0 else 0.0

            # Compute per-slice accuracy
            slice_groups: Dict[str, List[Dict]] = {}
            for row in rows:
                s = row["slice"]
                slice_groups.setdefault(s, []).append(row)

            slices_dict = {}
            required_slices = policy["requiredSlices"]
            for sname, sfloor in required_slices.items():
                if sname not in slice_groups:
                    # Missing slice
                    pass
                else:
                    srows = slice_groups[sname]
                    smatches = sum(1 for r in srows if r["predictions"][name] == r["label"])
                    sacc = round(smatches / len(srows), 12) if srows else 0.0
                    slices_dict[sname] = sacc
            slices = slices_dict if slices_dict else None

        # totalBytes from recomputed manifest
        inv, tb, pd = recomputed_map.get(name, ([], None, None))
        total_bytes = tb

        # latencyMs from latencies dict
        if name in latencies:
            latency_ms = latencies[name]
        else:
            latency_ms = None  # cannot validate

        # Apply policy checks and add reason codes
        max_bytes = policy["maxBytes"]
        agg_floor = policy["aggregateFloor"]
        required_slices = policy["requiredSlices"]
        max_latency = policy["maxLatencyMs"]

        # Aggregate floor
        if aggregate is not None and aggregate < agg_floor:
            reason_codes.append("AGGREGATE_FLOOR")

        # Required slices
        if slices is not None:
            for sname, sfloor in required_slices.items():
                if sname not in slices:
                    reason_codes.append(f"MISSING_SLICE:{sname}")
                elif slices[sname] < sfloor:
                    reason_codes.append(f"SLICE_FLOOR:{sname}")
        else:
            # If slices is None (predictions invalid), we already have INVALID_PREDICTIONS
            pass

        # Size limit
        if total_bytes is not None and total_bytes > max_bytes:
            reason_codes.append("SIZE_LIMIT")

        # Latency limit
        if latency_ms is not None and latency_ms > max_latency:
            reason_codes.append("LATENCY_LIMIT")

        # Determine admitted
        admitted = (
            len(reason_codes) == 0 and
            stored_cand is not None and
            stored_cand["status"] == "frozen" and
            predictions_valid and
            aggregate is not None and
            slices is not None and
            total_bytes is not None and
            latency_ms is not None
        )

        results.append({
            "name": name,
            "aggregate": aggregate,
            "slices": slices,
            "totalBytes": total_bytes,
            "latencyMs": latency_ms,
            "admitted": admitted,
            "reasonCodes": sort_reason_codes(reason_codes)
        })

    # Order results by candidateOrder, fallback to UTF-8 name
    results = order_results_by_candidate_order(results, candidate_order)

    # Select best admitted candidate
    admitted_candidates = [r for r in results if r["admitted"]]
    selected = None
    package_manifest = None

    if admitted_candidates:
        # Sort by totalBytes asc, latencyMs asc, then candidateOrder index
        def sort_key(r):
            tb = r["totalBytes"] if r["totalBytes"] is not None else float("inf")
            lat = r["latencyMs"] if r["latencyMs"] is not None else float("inf")
            co_idx = candidate_order_map.get(r["name"], float("inf"))
            return (tb, lat, co_idx)

        admitted_candidates.sort(key=sort_key)
        winner = admitted_candidates[0]
        selected = winner["name"]

        # packageManifest is exactly the recorded winner object from stored response
        winner_stored = next(sc for sc in stored_candidates if sc["name"] == selected)
        package_manifest = deepcopy(winner_stored)

    response_obj = {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest
    }

    return JSONResponse(status_code=200, content=response_obj)


def order_results_by_candidate_order(
    results: List[Dict[str, Any]],
    candidate_order: List[str]
) -> List[Dict[str, Any]]:
    """
    Order results by candidateOrder; for names not in candidateOrder, use UTF-8 name as fallback.
    """
    order_map = {name: idx for idx, name in enumerate(candidate_order)}

    def sort_key(r):
        name = r["name"]
        co_idx = order_map.get(name, float("inf"))
        return (co_idx, name.encode("utf-8"))

    return sorted(results, key=sort_key)


# -------------------------
# Main endpoint
# -------------------------


@app.post("/quantize")
async def quantize_endpoint(payload: dict):
    phase = payload.get("phase")
    if phase == "freeze":
        return handle_freeze(payload)
    elif phase == "select":
        return handle_select(payload)
    else:
        # Unknown/missing phase
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )