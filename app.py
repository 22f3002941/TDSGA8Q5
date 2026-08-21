# app.py
#
# Stateful two-phase candidate-admission API: POST /quantize
# Phases: "freeze" and "select"
#
# Run with:
#   uvicorn app:app --reload

from __future__ import annotations

import hashlib
import json
import logging
import sys
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import JSONResponse

app = FastAPI()

# Debug logging: prints the precise reason a request was rejected with
# INVALID_INPUT, WITHOUT changing the response body sent to the client.
# View these in your platform's log stream (e.g. Render's "Logs" tab).
logger = logging.getLogger("quantize")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("[VALIDATION] %(message)s"))
    logger.addHandler(_handler)

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
    Returns True if valid, else False. Logs the precise failing check.
    """
    ok, reason = _validate_freeze_input_verbose(data)
    if not ok:
        logger.info("freeze rejected: %s", reason)
    return ok


def _validate_freeze_input_verbose(data: Dict[str, Any]) -> Tuple[bool, str]:
    if not isinstance(data, dict):
        return False, "body is not a JSON object"

    # Required top-level keys
    required_keys = ["phase", "freezeId", "calibrationDigest", "tokenizerDigest",
                     "allowedUnsupportedReasons", "candidates"]
    missing = [k for k in required_keys if k not in data]
    if missing:
        return False, f"missing top-level key(s): {missing}"

    if data.get("phase") != "freeze":
        return False, f"phase != 'freeze' (got {data.get('phase')!r})"

    # freezeId: non-empty string, max 128 chars
    freeze_id = data.get("freezeId")
    if not isinstance(freeze_id, str):
        return False, f"freezeId is not a string (type={type(freeze_id).__name__})"
    if not freeze_id:
        return False, "freezeId is empty string"
    if len(freeze_id) > 128:
        return False, f"freezeId longer than 128 chars (len={len(freeze_id)})"

    # digests: non-empty strings
    cal_digest = data.get("calibrationDigest")
    tok_digest = data.get("tokenizerDigest")
    if not isinstance(cal_digest, str) or not cal_digest:
        return False, f"calibrationDigest invalid (value={cal_digest!r})"
    if not isinstance(tok_digest, str) or not tok_digest:
        return False, f"tokenizerDigest invalid (value={tok_digest!r})"

    # allowedUnsupportedReasons: array (may be empty); items non-empty & unique
    allowed = data.get("allowedUnsupportedReasons")
    if not isinstance(allowed, list):
        return False, f"allowedUnsupportedReasons is not an array (type={type(allowed).__name__})"
    seen_reasons = set()
    for i, r in enumerate(allowed):
        if not isinstance(r, str) or not r:
            return False, f"allowedUnsupportedReasons[{i}] invalid (value={r!r})"
        if r in seen_reasons:
            return False, f"allowedUnsupportedReasons has duplicate {r!r}"
        seen_reasons.add(r)

    # candidates: non-empty list
    candidates = data.get("candidates")
    if not isinstance(candidates, list):
        return False, f"candidates is not an array (type={type(candidates).__name__})"
    if len(candidates) == 0:
        return False, "candidates array is empty"

    seen_names = set()
    for idx, cand in enumerate(candidates):
        if not isinstance(cand, dict):
            return False, f"candidates[{idx}] is not an object"
        c_req = ["name", "files", "loadable", "calibrationDigest", "tokenizerDigest"]
        missing_c = [k for k in c_req if k not in cand]
        if missing_c:
            return False, f"candidates[{idx}] missing key(s): {missing_c}"

        name = cand.get("name")
        if not isinstance(name, str) or not name:
            return False, f"candidates[{idx}].name invalid (value={name!r})"
        if name in seen_names:
            return False, f"duplicate candidate name {name!r}"
        seen_names.add(name)

        # unsupportedReason optional, but if present must be non-empty string
        ureason = cand.get("unsupportedReason")
        if ureason is not None:
            if not isinstance(ureason, str) or not ureason:
                return False, f"candidates[{idx}({name})].unsupportedReason invalid (value={ureason!r})"

        # files: non-empty object of unique filenames -> UTF-8 strings
        files = cand.get("files")
        if not isinstance(files, dict):
            return False, f"candidates[{idx}({name})].files is not an object (type={type(files).__name__})"
        if len(files) == 0:
            return False, f"candidates[{idx}({name})].files is empty"
        seen_fnames = set()
        for fn, fc in files.items():
            if not isinstance(fn, str) or not fn:
                return False, f"candidates[{idx}({name})].files has invalid filename {fn!r}"
            if fn in seen_fnames:
                return False, f"candidates[{idx}({name})].files duplicate filename {fn!r}"
            seen_fnames.add(fn)
            if not isinstance(fc, str):
                return False, f"candidates[{idx}({name})].files[{fn!r}] value is not a string (type={type(fc).__name__})"

        # loadable: bool
        if not isinstance(cand.get("loadable"), bool):
            return False, f"candidates[{idx}({name})].loadable is not a boolean (value={cand.get('loadable')!r}, type={type(cand.get('loadable')).__name__})"

        # digests in candidate: non-empty strings
        cd_cal = cand.get("calibrationDigest")
        cd_tok = cand.get("tokenizerDigest")
        if not isinstance(cd_cal, str) or not cd_cal:
            return False, f"candidates[{idx}({name})].calibrationDigest invalid (value={cd_cal!r})"
        if not isinstance(cd_tok, str) or not cd_tok:
            return False, f"candidates[{idx}({name})].tokenizerDigest invalid (value={cd_tok!r})"

    return True, "ok"


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
    Minimal structural validation for select input.
    Returns True if valid, else False. Logs the precise failing check.
    """
    ok, reason = _validate_select_structure_verbose(data)
    if not ok:
        logger.info("select rejected: %s", reason)
    return ok


def _validate_select_structure_verbose(data: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Per spec: a select request without array `candidates` and `rows` plus an
    object `policy` returns 400. `latencies` is NOT named in that 400 trigger,
    so its absence is tolerated here (treated as {} downstream) — only its
    type is checked if present. Everything else (policy field values,
    prediction values, latency values) is validated per-candidate inside
    handle_select and surfaces as reason codes, not as a 400.
    """
    if not isinstance(data, dict):
        return False, "body is not a JSON object"
    if data.get("phase") != "select":
        return False, f"phase != 'select' (got {data.get('phase')!r})"

    required_keys = ["freezeId", "candidates", "policy", "rows"]
    missing = [k for k in required_keys if k not in data]
    if missing:
        return False, f"missing top-level key(s): {missing}"

    # freezeId: non-empty string
    if not isinstance(data["freezeId"], str) or not data["freezeId"]:
        return False, f"freezeId invalid (value={data['freezeId']!r})"

    # candidates: array (per spec's literal 400 wording, just "array" — not
    # explicitly required to be non-empty, but an empty array can never
    # equal a non-empty frozen response, so it's kept for sanity here;
    # relax this line first if this turns out to be the rejection point)
    cands = data["candidates"]
    if not isinstance(cands, list):
        return False, f"candidates is not an array (type={type(cands).__name__})"
    if len(cands) == 0:
        return False, "candidates array is empty"

    # policy: object
    policy = data["policy"]
    if not isinstance(policy, dict):
        return False, f"policy is not an object (type={type(policy).__name__})"

    # rows: array
    rows = data["rows"]
    if not isinstance(rows, list):
        return False, f"rows is not an array (type={type(rows).__name__})"
    if len(rows) == 0:
        return False, "rows array is empty"

    # latencies: optional; if present, must be an object
    latencies_val = data.get("latencies", {})
    if not isinstance(latencies_val, dict):
        return False, f"latencies is not an object (type={type(latencies_val).__name__})"

    # Validate each candidate in request (shape only)
    for idx, c in enumerate(cands):
        if not isinstance(c, dict):
            return False, f"candidates[{idx}] is not an object"
        c_req_keys = ["name", "status", "inventory", "totalBytes", "packageDigest", "reasonCodes"]
        missing_c = [k for k in c_req_keys if k not in c]
        if missing_c:
            return False, f"candidates[{idx}] missing key(s): {missing_c}"
        if not isinstance(c["name"], str) or not c["name"]:
            return False, f"candidates[{idx}].name invalid (value={c['name']!r})"
        if not isinstance(c["status"], str) or c["status"] not in ("frozen", "unsupported", "invalid"):
            return False, f"candidates[{idx}({c['name']})].status invalid (value={c['status']!r})"
        if not isinstance(c["inventory"], list):
            return False, f"candidates[{idx}({c['name']})].inventory is not an array"
        for j, inv in enumerate(c["inventory"]):
            if not isinstance(inv, dict):
                return False, f"candidates[{idx}({c['name']})].inventory[{j}] is not an object"
            missing_inv = [k for k in ("name", "bytes", "sha256") if k not in inv]
            if missing_inv:
                return False, f"candidates[{idx}({c['name']})].inventory[{j}] missing key(s): {missing_inv}"
            if not isinstance(inv["name"], str) or not inv["name"]:
                return False, f"candidates[{idx}({c['name']})].inventory[{j}].name invalid"
            if not isinstance(inv["bytes"], int) or isinstance(inv["bytes"], bool) or inv["bytes"] < 0:
                return False, f"candidates[{idx}({c['name']})].inventory[{j}].bytes invalid (value={inv['bytes']!r})"
            if not isinstance(inv["sha256"], str) or not inv["sha256"]:
                return False, f"candidates[{idx}({c['name']})].inventory[{j}].sha256 invalid"
        tb = c["totalBytes"]
        if tb is not None and (not isinstance(tb, int) or isinstance(tb, bool) or tb < 0):
            return False, f"candidates[{idx}({c['name']})].totalBytes invalid (value={tb!r})"
        pd = c["packageDigest"]
        if pd is not None and (not isinstance(pd, str) or not pd):
            return False, f"candidates[{idx}({c['name']})].packageDigest invalid (value={pd!r})"
        if not isinstance(c["reasonCodes"], list):
            return False, f"candidates[{idx}({c['name']})].reasonCodes is not an array"
        for rc in c["reasonCodes"]:
            if not isinstance(rc, str):
                return False, f"candidates[{idx}({c['name']})].reasonCodes has non-string entry {rc!r}"

    # Validate rows structure only (NOT prediction values - that's per-candidate
    # in handle_select and surfaces as INVALID_PREDICTIONS, not a 400)
    for ridx, row in enumerate(rows):
        if not isinstance(row, dict):
            return False, f"rows[{ridx}] is not an object"
        missing_row = [k for k in ("label", "slice", "predictions") if k not in row]
        if missing_row:
            return False, f"rows[{ridx}] missing key(s): {missing_row}"
        if not isinstance(row["label"], int):
            return False, f"rows[{ridx}].label is not an int (value={row['label']!r})"
        if not isinstance(row["slice"], str) or not row["slice"]:
            return False, f"rows[{ridx}].slice invalid (value={row['slice']!r})"
        preds = row["predictions"]
        if not isinstance(preds, dict):
            return False, f"rows[{ridx}].predictions is not an object (type={type(preds).__name__})"
        for cname in preds.keys():
            if not isinstance(cname, str) or not cname:
                return False, f"rows[{ridx}].predictions has invalid key {cname!r}"

    # latencies: only check keys are strings (values validated per-candidate,
    # falling back to null latencyMs rather than a 400)
    for cname in latencies_val.keys():
        if not isinstance(cname, str) or not cname:
            return False, f"latencies has invalid key {cname!r}"

    return True, "ok"


def validate_policy(policy: Dict[str, Any]) -> bool:
    """
    Field-level validation of policy contents. Failure here does NOT
    produce a 400; instead every candidate result gets INVALID_POLICY.
    """
    if "maxBytes" not in policy:
        return False
    mb = policy["maxBytes"]
    if not isinstance(mb, int) or isinstance(mb, bool) or mb < 0:
        return False

    if "aggregateFloor" not in policy:
        return False
    af = policy["aggregateFloor"]
    if not isinstance(af, (int, float)) or isinstance(af, bool) or af < 0 or af > 1:
        return False

    if "requiredSlices" not in policy:
        return False
    rs = policy["requiredSlices"]
    if not isinstance(rs, dict):
        return False
    for sname, sfloor in rs.items():
        if not isinstance(sname, str) or not sname:
            return False
        if not isinstance(sfloor, (int, float)) or isinstance(sfloor, bool) or sfloor < 0 or sfloor > 1:
            return False

    if "maxLatencyMs" not in policy:
        return False
    ml = policy["maxLatencyMs"]
    if not isinstance(ml, (int, float)) or isinstance(ml, bool) or ml < 0:
        return False

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
    # Validate structure (shape only; see validate_select_structure docstring)
    if not validate_select_structure(data):
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    freeze_id = data["freezeId"]
    req_candidates = data["candidates"]  # These are the frozen candidate objects
    policy = data["policy"]
    latencies = data.get("latencies", {})
    rows = data["rows"]

    # Field-level policy validity; failure -> INVALID_POLICY per candidate, not 400
    policy_valid = validate_policy(policy)

    # Check freezeId exists
    if freeze_id not in FROZEN_STORE:
        # All candidates are NOT_FROZEN
        results = []
        for c in req_candidates:
            codes = ["NOT_FROZEN"]
            if not policy_valid:
                codes.append("INVALID_POLICY")
            results.append({
                "name": c["name"],
                "aggregate": None,
                "slices": None,
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": sort_reason_codes(codes)
            })
        candidate_order = policy.get("candidateOrder") if isinstance(policy.get("candidateOrder"), list) else []
        results = order_results_by_candidate_order(results, candidate_order)
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

    # Candidate names and candidateOrder must be the same unique set
    # (only checked when candidateOrder is itself well-formed; otherwise
    # that's captured by INVALID_POLICY instead)
    candidate_order = policy.get("candidateOrder")
    if policy_valid:
        req_names = {c["name"] for c in req_candidates}
        co_names = set(candidate_order)
        if req_names != co_names:
            lineage_valid = False
    if not isinstance(candidate_order, list):
        candidate_order = []

    # Recompute manifest for each candidate from original files (PER-CANDIDATE validity)
    original_candidates_map = {}
    for oc in stored_request["candidates"]:
        original_candidates_map[oc["name"]] = oc

    manifest_valid_map: Dict[str, bool] = {}
    recomputed_map = {}  # name -> (inventory, totalBytes, packageDigest)

    for sc in stored_candidates:
        name = sc["name"]
        if name not in original_candidates_map:
            manifest_valid_map[name] = False
            recomputed_map[name] = ([], None, None)
            continue

        orig_cand = original_candidates_map[name]
        inv, tb, pd = recompute_manifest_from_original_files(orig_cand)

        stored_inv = sc["inventory"]
        stored_tb = sc["totalBytes"]
        stored_pd = sc["packageDigest"]

        this_valid = True
        if compact_json(inv) != compact_json(stored_inv):
            this_valid = False
        if tb != stored_tb:
            this_valid = False
        if pd != stored_pd:
            this_valid = False

        manifest_valid_map[name] = this_valid
        recomputed_map[name] = (inv, tb, pd)

    # Build results per candidate
    results = []
    candidate_order_map = {name: idx for idx, name in enumerate(candidate_order)}

    for c in req_candidates:
        name = c["name"]
        reason_codes: List[str] = []

        if not policy_valid:
            reason_codes.append("INVALID_POLICY")

        if not lineage_valid:
            reason_codes.append("INVALID_LINEAGE")

        candidate_manifest_valid = manifest_valid_map.get(name, False)
        if not candidate_manifest_valid:
            reason_codes.append("INVALID_MANIFEST")

        # Check if candidate is frozen
        stored_cand = next((sc for sc in stored_candidates if sc["name"] == name), None)
        if stored_cand is None or stored_cand["status"] != "frozen":
            reason_codes.append("NOT_FROZEN")

        # Predictions validity (per-candidate; binary value check lives here)
        predictions_valid = True
        for row in rows:
            preds = row["predictions"]
            if name not in preds:
                predictions_valid = False
                break
            pval = preds[name]
            if pval not in (0, 1) or isinstance(pval, bool):
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
            required_slices = policy.get("requiredSlices") if policy_valid else {}
            required_slices = required_slices if isinstance(required_slices, dict) else {}
            for sname, sfloor in required_slices.items():
                if sname not in slice_groups:
                    # Missing slice; handled below via MISSING_SLICE
                    pass
                else:
                    srows = slice_groups[sname]
                    smatches = sum(1 for r in srows if r["predictions"][name] == r["label"])
                    sacc = round(smatches / len(srows), 12) if srows else 0.0
                    slices_dict[sname] = sacc
            # Empty dict is a valid (non-null) result, not None
            slices = slices_dict

        # totalBytes from recomputed manifest
        inv, tb, pd = recomputed_map.get(name, ([], None, None))
        total_bytes = tb

        # latencyMs from latencies dict; validated here, null if unusable
        raw_lat = latencies.get(name)
        if isinstance(raw_lat, (int, float)) and not isinstance(raw_lat, bool) and raw_lat >= 0:
            latency_ms = raw_lat
        else:
            latency_ms = None

        # Apply policy checks and add reason codes (only if policy itself is valid)
        if policy_valid:
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

            # Size limit
            if total_bytes is not None and total_bytes > max_bytes:
                reason_codes.append("SIZE_LIMIT")

            # Latency limit
            if latency_ms is not None and latency_ms > max_latency:
                reason_codes.append("LATENCY_LIMIT")

        # Determine admitted
        admitted = (
            policy_valid and
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
    logger.info("incoming request keys: %s", list(payload.keys()) if isinstance(payload, dict) else type(payload).__name__)
    try:
        phase = payload.get("phase") if isinstance(payload, dict) else None
        if phase == "freeze":
            return handle_freeze(payload)
        elif phase == "select":
            return handle_select(payload)
        else:
            # Unknown/missing phase
            logger.info("rejected: unknown/missing phase (got %r)", phase)
            return JSONResponse(
                status_code=400,
                content={"error": "INVALID_INPUT"}
            )
    except Exception:
        # Log full traceback so an unexpected 500 is diagnosable from
        # the platform's log stream, rather than opaque either way.
        logger.exception("unhandled exception while processing /quantize request")
        raise
