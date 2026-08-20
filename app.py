from flask import Flask, request, jsonify
import hashlib
import json
import math
import os
import sqlite3

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "quantize_state.db")
SAFE_MAX = 9007199254740991


def compact(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":")
    )


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_text(value):
    return sha256_bytes(value.encode("utf-8"))


def sha256_json(value):
    return sha256_text(compact(value))


def utf8_key(value):
    return value.encode("utf-8")


def safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_MAX
    )


def positive_safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 < value <= SAFE_MAX
    )


def finite_nonnegative(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def finite_unit(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0 <= value <= 1
    )


def binary(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value in (0, 1)
    )


def unique_strings(value):
    return (
        isinstance(value, list)
        and all(
            isinstance(x, str) and x
            for x in value
        )
        and len(value) == len(set(value))
    )


def sorted_codes(items):
    return sorted(set(items), key=utf8_key)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS freezes (
            freeze_id TEXT PRIMARY KEY,
            request_json TEXT NOT NULL,
            response_json TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def make_inventory(files):
    if not isinstance(files, dict) or not files:
        return None

    inventory = []

    for filename, content in files.items():
        if (
            not isinstance(filename, str)
            or not filename
            or not isinstance(content, str)
        ):
            return None

        raw = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw)
        })

    inventory.sort(
        key=lambda x: utf8_key(x["name"])
    )

    total = sum(
        item["bytes"]
        for item in inventory
    )

    return (
        inventory,
        total,
        sha256_json(inventory)
    )


def freeze(body):
    freeze_id = body.get("freezeId")
    calibration = body.get("calibrationDigest")
    tokenizer = body.get("tokenizerDigest")
    allowed = body.get("allowedUnsupportedReasons")
    candidates = body.get("candidates")

    if (
        not isinstance(freeze_id, str)
        or not freeze_id
        or len(freeze_id) > 128
        or not isinstance(calibration, str)
        or not calibration
        or not isinstance(tokenizer, str)
        or not tokenizer
        or not unique_strings(allowed)
        or not isinstance(candidates, list)
        or not candidates
    ):
        return {"error": "INVALID_INPUT"}, 400

    names = []

    for candidate in candidates:
        if not isinstance(candidate, dict):
            return {"error": "INVALID_INPUT"}, 400

        name = candidate.get("name")

        if not isinstance(name, str) or not name:
            return {"error": "INVALID_INPUT"}, 400

        names.append(name)

    if len(names) != len(set(names)):
        return {"error": "INVALID_INPUT"}, 400

    output = []

    for candidate in candidates:
        name = candidate["name"]
        reason_codes = []

        inventory_result = make_inventory(
            candidate.get("files")
        )

        if inventory_result is None:
            inventory = []
            total_bytes = None
            package_digest = None
            files_valid = False
        else:
            inventory, total_bytes, package_digest = inventory_result
            files_valid = True

        unsupported_reason = candidate.get(
            "unsupportedReason"
        )

        has_unsupported_reason = (
            isinstance(unsupported_reason, str)
            and bool(unsupported_reason)
        )

        allowed_unsupported = (
            has_unsupported_reason
            and unsupported_reason in allowed
        )

        if has_unsupported_reason and not allowed_unsupported:
            reason_codes.append(
                "UNALLOWED_UNSUPPORTED_REASON"
            )

        if not files_valid:
            reason_codes.append(
                "INVALID_INPUT"
            )

        if has_unsupported_reason:
            if not allowed_unsupported:
                status_invalid = True
            else:
                status_invalid = False
        else:
            status_invalid = False

            if candidate.get("loadable") is not True:
                reason_codes.append("NOT_LOADABLE")

            if candidate.get("calibrationDigest") != calibration:
                reason_codes.append(
                    "CALIBRATION_MISMATCH"
                )

            if candidate.get("tokenizerDigest") != tokenizer:
                reason_codes.append(
                    "TOKENIZER_MISMATCH"
                )

        if reason_codes:
            status = "invalid"
        elif allowed_unsupported:
            status = "unsupported"
        else:
            status = "frozen"

        output.append({
            "name": name,
            "status": status,
            "inventory": inventory,
            "totalBytes": total_bytes,
            "packageDigest": package_digest,
            "reasonCodes": sorted_codes(reason_codes)
        })

    output.sort(
        key=lambda x: utf8_key(x["name"])
    )

    response = {
        "freezeId": freeze_id,
        "candidates": output
    }

    request_json = compact(body)

    conn = get_db()

    existing = conn.execute(
        """
        SELECT request_json, response_json
        FROM freezes
        WHERE freeze_id = ?
        """,
        (freeze_id,)
    ).fetchone()

    if existing:
        conn.close()

        if existing[0] == request_json:
            return json.loads(existing[1]), 200

        return {
            "error": "FREEZE_ID_CONFLICT"
        }, 409

    conn.execute(
        """
        INSERT INTO freezes
        (freeze_id, request_json, response_json)
        VALUES (?, ?, ?)
        """,
        (
            freeze_id,
            request_json,
            compact(response)
        )
    )

    conn.commit()
    conn.close()

    return response, 200


def load_freeze(freeze_id):
    conn = get_db()

    row = conn.execute(
        """
        SELECT request_json, response_json
        FROM freezes
        WHERE freeze_id = ?
        """,
        (freeze_id,)
    ).fetchone()

    conn.close()

    if row is None:
        return None

    return {
        "request": json.loads(row[0]),
        "response": json.loads(row[1])
    }


def validate_stored_manifest(
    freeze_request,
    frozen_candidate
):
    original_candidates = freeze_request["candidates"]

    original = None

    for candidate in original_candidates:
        if candidate.get("name") == frozen_candidate.get("name"):
            original = candidate
            break

    if original is None:
        return False, None, None, None

    result = make_inventory(
        original.get("files")
    )

    if result is None:
        return False, None, None, None

    inventory, total, digest = result

    if (
        frozen_candidate.get("inventory") != inventory
        or frozen_candidate.get("totalBytes") != total
        or frozen_candidate.get("packageDigest") != digest
    ):
        return False, inventory, total, digest

    return True, inventory, total, digest


def select_phase(body):
    freeze_id = body.get("freezeId")
    candidates = body.get("candidates")
    policy = body.get("policy")
    latencies = body.get("latencies")
    rows = body.get("rows")

    if (
        not isinstance(freeze_id, str)
        or not freeze_id
        or not isinstance(candidates, list)
        or not candidates
        or not isinstance(rows, list)
        or not isinstance(policy, dict)
        or not isinstance(latencies, dict)
    ):
        return {"error": "INVALID_INPUT"}, 400

    frozen = load_freeze(freeze_id)

    if frozen is None:
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    stored_response = frozen["response"]

    if candidates != stored_response["candidates"]:
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    max_bytes = policy.get("maxBytes")
    aggregate_floor = policy.get("aggregateFloor")
    required_slices = policy.get("requiredSlices")
    max_latency = policy.get("maxLatencyMs")
    candidate_order = policy.get("candidateOrder")

    if (
        not safe_integer(max_bytes)
        or not finite_unit(aggregate_floor)
        or not isinstance(required_slices, dict)
        or not finite_nonnegative(max_latency)
        or not unique_strings(candidate_order)
    ):
        return {"error": "INVALID_INPUT"}, 400

    for slice_name, floor in required_slices.items():
        if (
            not isinstance(slice_name, str)
            or not slice_name
            or not finite_unit(floor)
        ):
            return {"error": "INVALID_INPUT"}, 400

    names = []

    for candidate in candidates:
        if (
            not isinstance(candidate, dict)
            or not isinstance(candidate.get("name"), str)
            or not candidate["name"]
        ):
            return {"error": "INVALID_INPUT"}, 400

        names.append(candidate["name"])

    if (
        len(names) != len(set(names))
        or set(names) != set(candidate_order)
    ):
        return {"error": "INVALID_INPUT"}, 400

    if not isinstance(latencies, dict):
        return {"error": "INVALID_INPUT"}, 400

    results = []

    order = {
        name: index
        for index, name in enumerate(candidate_order)
    }

    for candidate in candidates:
        name = candidate["name"]
        reason_codes = []

        frozen_candidate = None

        for item in stored_response["candidates"]:
            if item["name"] == name:
                frozen_candidate = item
                break

        if frozen_candidate is None:
            reason_codes.append("INVALID_LINEAGE")
        elif candidate != frozen_candidate:
            reason_codes.append("INVALID_LINEAGE")

        manifest_ok, inventory, total_bytes, package_digest = \
            validate_stored_manifest(
                frozen["request"],
                frozen_candidate
            )

        if not manifest_ok:
            reason_codes.append("INVALID_MANIFEST")

        if frozen_candidate is not None:
            if (
                frozen_candidate["packageDigest"]
                != package_digest
                or frozen_candidate["totalBytes"]
                != total_bytes
                or frozen_candidate["inventory"]
                != inventory
            ):
                reason_codes.append("INVALID_LINEAGE")

        aggregate = None
        slices = {}

        prediction_ok = True
        slice_correct = {}

        for row in rows:
            if not isinstance(row, dict):
                prediction_ok = False
                break

            label = row.get("label")
            slice_name = row.get("slice")
            predictions = row.get("predictions")

            if (
                not binary(label)
                or not isinstance(slice_name, str)
                or not slice_name
                or not isinstance(predictions, dict)
                or name not in predictions
                or not binary(predictions[name])
            ):
                prediction_ok = False
                break

            correct = (
                predictions[name] == label
            )

            slice_correct.setdefault(
                slice_name,
                []
            ).append(correct)

        if not prediction_ok or not rows:
            reason_codes.append(
                "INVALID_PREDICTIONS"
            )
        else:
            aggregate = round(
                sum(
                    row["predictions"][name] == row["label"]
                    for row in rows
                ) / len(rows),
                12
            )

            for slice_name, values in slice_correct.items():
                slices[slice_name] = round(
                    sum(values) / len(values),
                    12
                )

            if aggregate < aggregate_floor:
                reason_codes.append(
                    "AGGREGATE_FLOOR"
                )

            for slice_name, floor in required_slices.items():
                if slice_name not in slices:
                    reason_codes.append(
                        "MISSING_SLICE:" + slice_name
                    )
                elif slices[slice_name] < floor:
                    reason_codes.append(
                        "SLICE_FLOOR:" + slice_name
                    )

        latency_value = latencies.get(name)

        if not finite_nonnegative(latency_value):
            latency_value = None
            reason_codes.append("LATENCY_LIMIT")
        elif latency_value > max_latency:
            reason_codes.append("LATENCY_LIMIT")

        if manifest_ok:
            if total_bytes > max_bytes:
                reason_codes.append("SIZE_LIMIT")
        else:
            total_bytes = None

        if frozen_candidate is None:
            frozen_status = "invalid"
        else:
            frozen_status = frozen_candidate["status"]

        admitted = (
            frozen_status == "frozen"
            and manifest_ok
            and prediction_ok
            and bool(rows)
            and aggregate is not None
            and total_bytes is not None
            and latency_value is not None
            and total_bytes <= max_bytes
            and latency_value <= max_latency
            and aggregate >= aggregate_floor
            and all(
                slice_name in slices
                and slices[slice_name] >= floor
                for slice_name, floor
                in required_slices.items()
            )
            and not reason_codes
        )

        results.append({
            "name": name,
            "aggregate": aggregate,
            "slices": slices,
            "totalBytes": total_bytes,
            "latencyMs": latency_value,
            "admitted": admitted,
            "reasonCodes": sorted_codes(reason_codes)
        })

    results.sort(
        key=lambda x: (
            order.get(
                x["name"],
                len(order)
            ),
            utf8_key(x["name"])
        )
    )

    admitted = [
        result
        for result in results
        if result["admitted"]
    ]

    winner = None

    if admitted:
        winner = min(
            admitted,
            key=lambda x: (
                x["totalBytes"],
                x["latencyMs"],
                order[x["name"]]
            )
        )

    package_manifest = None

    if winner is not None:
        package_manifest = next(
            candidate
            for candidate in candidates
            if candidate["name"] == winner["name"]
        )

    return {
        "freezeId": freeze_id,
        "selected": (
            winner["name"]
            if winner is not None
            else None
        ),
        "results": results,
        "packageManifest": package_manifest
    }, 200


@app.post("/quantize")
def quantize():
    if not request.is_json:
        return jsonify({
            "error": "INVALID_INPUT"
        }), 400

    body = request.get_json(silent=True)

    if not isinstance(body, dict):
        return jsonify({
            "error": "INVALID_INPUT"
        }), 400

    phase = body.get("phase")

    if phase == "freeze":
        result, status = freeze(body)
        return jsonify(result), status

    if phase == "select":
        result, status = select_phase(body)
        return jsonify(result), status

    return jsonify({
        "error": "INVALID_INPUT"
    }), 400


@app.get("/")
def health():
    return "OK"


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )