from flask import Flask, request, jsonify
import hashlib
import json
import math
import os
import sqlite3

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "quantize_state.db")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS freezes ("
        "freeze_id TEXT PRIMARY KEY,"
        "request_json TEXT NOT NULL,"
        "response_json TEXT NOT NULL)"
    )
    conn.commit()
    return conn


def compact(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":")
    )


def digest_text(text):
    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def digest_json(obj):
    return digest_text(compact(obj))


def utf8_key(value):
    return value.encode("utf-8")


def sorted_unique_strings(values):
    return (
        isinstance(values, list)
        and all(
            isinstance(x, str) and x
            for x in values
        )
        and len(values) == len(set(values))
    )


def safe_int(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 9007199254740991
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


def codes(values):
    return sorted(
        set(values),
        key=utf8_key
    )


def file_inventory(candidate):
    files = candidate.get("files")

    if (
        not isinstance(files, dict)
        or not files
        or len(files) != len(set(files.keys()))
        or any(
            not isinstance(name, str)
            or not name
            or not isinstance(value, str)
            for name, value in files.items()
        )
    ):
        return None

    inventory = []

    for name, content in files.items():
        encoded = content.encode("utf-8")

        inventory.append({
            "name": name,
            "bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest()
        })

    inventory.sort(
        key=lambda x: x["name"].encode("utf-8")
    )

    total = sum(
        item["bytes"]
        for item in inventory
    )

    package_digest = digest_json(inventory)

    return inventory, total, package_digest


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
        or not sorted_unique_strings(allowed)
        or not isinstance(candidates, list)
        or not candidates
    ):
        return None, 400

    names = []

    for candidate in candidates:
        if not isinstance(candidate, dict):
            return None, 400

        name = candidate.get("name")

        if not isinstance(name, str) or not name:
            return None, 400

        names.append(name)

    if len(names) != len(set(names)):
        return None, 400

    response_candidates = []

    for candidate in candidates:
        name = candidate["name"]
        reason = candidate.get("unsupportedReason")

        inventory_result = file_inventory(candidate)

        if inventory_result is None:
            inventory = []
            total = None
            package = None
            file_valid = False
        else:
            inventory, total, package = inventory_result
            file_valid = True

        reason_codes = []

        if not file_valid:
            reason_codes.append("INVALID_INPUT")

        if reason is not None:
            if (
                not isinstance(reason, str)
                or not reason
                or reason not in allowed
            ):
                reason_codes.append(
                    "UNALLOWED_UNSUPPORTED_REASON"
                )

        if candidate.get("loadable") is not True:
            reason_codes.append("NOT_LOADABLE")

        if (
            candidate.get("calibrationDigest")
            != calibration
        ):
            reason_codes.append(
                "CALIBRATION_MISMATCH"
            )

        if (
            candidate.get("tokenizerDigest")
            != tokenizer
        ):
            reason_codes.append(
                "TOKENIZER_MISMATCH"
            )

        reason_codes = codes(reason_codes)

        if reason_codes:
            status = "invalid"
        elif reason is not None:
            status = "unsupported"
        else:
            status = "frozen"

        response_candidates.append({
            "name": name,
            "status": status,
            "inventory": inventory,
            "totalBytes": total,
            "packageDigest": package,
            "reasonCodes": reason_codes
        })

    response_candidates.sort(
        key=lambda x: x["name"].encode("utf-8")
    )

    response = {
        "freezeId": freeze_id,
        "candidates": response_candidates
    }

    request_copy = body

    conn = db()

    existing = conn.execute(
        "SELECT request_json, response_json "
        "FROM freezes WHERE freeze_id = ?",
        (freeze_id,)
    ).fetchone()

    request_json = compact(request_copy)

    if existing is not None:
        if existing[0] == request_json:
            conn.close()
            return json.loads(existing[1]), 200

        conn.close()
        return {
            "error": "FREEZE_ID_CONFLICT"
        }, 409

    response_json = compact(response)

    conn.execute(
        "INSERT INTO freezes "
        "(freeze_id, request_json, response_json) "
        "VALUES (?, ?, ?)",
        (
            freeze_id,
            request_json,
            response_json
        )
    )

    conn.commit()
    conn.close()

    return response, 200


def stored_freeze(freeze_id):
    conn = db()

    row = conn.execute(
        "SELECT response_json "
        "FROM freezes WHERE freeze_id = ?",
        (freeze_id,)
    ).fetchone()

    conn.close()

    if row is None:
        return None

    return json.loads(row[0])


def validate_manifest(candidate):
    inventory_result = file_inventory(candidate)

    if inventory_result is None:
        return False, None, None, None

    inventory, total, package = inventory_result

    recorded_inventory = candidate.get("inventory")
    recorded_total = candidate.get("totalBytes")
    recorded_package = candidate.get("packageDigest")

    if (
        recorded_inventory != inventory
        or recorded_total != total
        or recorded_package != package
    ):
        return False, inventory, total, package

    return True, inventory, total, package


def select(body):
    freeze_id = body.get("freezeId")
    supplied_candidates = body.get("candidates")
    policy = body.get("policy")
    latencies = body.get("latencies")
    rows = body.get("rows")

    if (
        not isinstance(freeze_id, str)
        or not freeze_id
        or not isinstance(supplied_candidates, list)
        or not supplied_candidates
        or not isinstance(rows, list)
        or not rows
        or not isinstance(policy, dict)
        or not isinstance(latencies, dict)
    ):
        return None, 400

    frozen = stored_freeze(freeze_id)

    if frozen is None:
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    if supplied_candidates != frozen["candidates"]:
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    required_policy = [
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder"
    ]

    if not all(
        key in policy
        for key in required_policy
    ):
        return invalid_select(freeze_id)

    if (
        not safe_int(policy["maxBytes"])
        or not finite_unit(policy["aggregateFloor"])
        or not finite_nonnegative(policy["maxLatencyMs"])
        or not isinstance(
            policy["requiredSlices"], dict
        )
        or not sorted_unique_strings(
            policy["candidateOrder"]
        )
    ):
        return invalid_select(freeze_id)

    required_slices = policy["requiredSlices"]

    for name, floor in required_slices.items():
        if (
            not isinstance(name, str)
            or not name
            or not finite_unit(floor)
        ):
            return invalid_select(freeze_id)

    frozen_names = [
        candidate["name"]
        for candidate in frozen["candidates"]
    ]

    order = policy["candidateOrder"]

    if (
        set(order) != set(frozen_names)
        or len(order) != len(frozen_names)
    ):
        return invalid_select(freeze_id)

    results = []

    for candidate in supplied_candidates:
        name = candidate["name"]
        reason_codes = []

        lineage_ok = True

        stored_candidate = next(
            (
                x for x in frozen["candidates"]
                if x["name"] == name
            ),
            None
        )

        if stored_candidate is None:
            reason_codes.append("INVALID_LINEAGE")
            lineage_ok = False
        else:
            if (
                candidate.get("status")
                != stored_candidate["status"]
                or candidate.get("inventory")
                != stored_candidate["inventory"]
                or candidate.get("packageDigest")
                != stored_candidate["packageDigest"]
            ):
                reason_codes.append(
                    "INVALID_LINEAGE"
                )
                lineage_ok = False

        manifest_ok, inventory, total, package = \
            validate_manifest(candidate)

        if not manifest_ok:
            reason_codes.append(
                "INVALID_MANIFEST"
            )

        predictions_valid = True
        aggregate = None
        slices = {}

        slice_rows = {}

        for row in rows:
            if not isinstance(row, dict):
                predictions_valid = False
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
                predictions_valid = False
                break

            slice_rows.setdefault(
                slice_name,
                []
            ).append(
                predictions[name] == label
            )

        if not predictions_valid:
            reason_codes.append(
                "INVALID_PREDICTIONS"
            )
        else:
            correct = sum(
                1
                for row in rows
                if row["predictions"][name]
                == row["label"]
            )

            aggregate = round(
                correct / len(rows),
                12
            )

            for slice_name, values in slice_rows.items():
                slices[slice_name] = round(
                    sum(values) / len(values),
                    12
                )

            if aggregate < policy["aggregateFloor"]:
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

        total_bytes = candidate.get("totalBytes")

        if (
            not safe_int(total_bytes)
            or not manifest_ok
        ):
            total_bytes = None
            if manifest_ok:
                reason_codes.append(
                    "INVALID_MANIFEST"
                )
        elif total_bytes > policy["maxBytes"]:
            reason_codes.append("SIZE_LIMIT")

        latency = latencies.get(name)

        if not finite_nonnegative(latency):
            latency = None
        elif latency > policy["maxLatencyMs"]:
            reason_codes.append("LATENCY_LIMIT")

        admitted = (
            candidate.get("status") == "frozen"
            and lineage_ok
            and manifest_ok
            and predictions_valid
            and aggregate is not None
            and not any(
                code in reason_codes
                for code in (
                    "AGGREGATE_FLOOR",
                    "INVALID_PREDICTIONS"
                )
            )
            and total_bytes is not None
            and total_bytes <= policy["maxBytes"]
            and latency is not None
            and latency <= policy["maxLatencyMs"]
            and all(
                key in slices
                and slices[key] >= value
                for key, value
                in required_slices.items()
            )
        )

        results.append({
            "name": name,
            "aggregate": aggregate,
            "slices": slices if predictions_valid else {},
            "totalBytes": total_bytes,
            "latencyMs": latency,
            "admitted": admitted,
            "reasonCodes": codes(reason_codes)
        })

    order_map = {
        name: index
        for index, name in enumerate(order)
    }

    results.sort(
        key=lambda x: (
            order_map.get(
                x["name"],
                len(order)
            ),
            x["name"].encode("utf-8")
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
                order_map[x["name"]]
            )
        )

    manifest = None

    if winner is not None:
        manifest = next(
            x for x in supplied_candidates
            if x["name"] == winner["name"]
        )

    return {
        "freezeId": freeze_id,
        "selected": (
            winner["name"]
            if winner is not None
            else None
        ),
        "results": results,
        "packageManifest": manifest
    }, 200


def invalid_select(freeze_id):
    return {
        "freezeId": freeze_id,
        "selected": None,
        "results": [],
        "packageManifest": None
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

    if phase not in ("freeze", "select"):
        return jsonify({
            "error": "INVALID_INPUT"
        }), 400

    if phase == "freeze":
        result, status = freeze(body)

        if result is None:
            return jsonify({
                "error": "INVALID_INPUT"
            }), status

        return jsonify(result), status

    result, status = select(body)

    if result is None:
        return jsonify({
            "error": "INVALID_INPUT"
        }), status

    return jsonify(result), status


@app.get("/")
def health():
    return "OK"


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )