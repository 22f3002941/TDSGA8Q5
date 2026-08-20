from flask import Flask, request, jsonify
import hashlib
import json
import math
import os
import sqlite3

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "quantize_state.db")
SAFE_MAX = 9007199254740991


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


def compact(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":")
    )


def sha256_text(value):
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def sha256_json(value):
    return sha256_text(compact(value))


def utf8_key(value):
    return value.encode("utf-8")


def unique_strings(value):
    return (
        isinstance(value, list)
        and all(
            isinstance(x, str) and x
            for x in value
        )
        and len(value) == len(set(value))
    )


def safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_MAX
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


def sorted_codes(items):
    return sorted(
        set(items),
        key=utf8_key
    )


def make_inventory(files):
    if (
        not isinstance(files, dict)
        or not files
    ):
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
            "sha256": hashlib.sha256(raw).hexdigest()
        })

    inventory.sort(
        key=lambda x: x["name"].encode("utf-8")
    )

    total = sum(
        x["bytes"]
        for x in inventory
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
        return {
            "error": "INVALID_INPUT"
        }, 400

    names = []

    for candidate in candidates:
        if not isinstance(candidate, dict):
            return {
                "error": "INVALID_INPUT"
            }, 400

        name = candidate.get("name")

        if not isinstance(name, str) or not name:
            return {
                "error": "INVALID_INPUT"
            }, 400

        names.append(name)

    if len(names) != len(set(names)):
        return {
            "error": "INVALID_INPUT"
        }, 400

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
        else:
            inventory, total_bytes, package_digest = \
                inventory_result

        unsupported_reason = candidate.get(
            "unsupportedReason"
        )

        if unsupported_reason is not None:
            if (
                not isinstance(unsupported_reason, str)
                or not unsupported_reason
                or unsupported_reason not in allowed
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

        if inventory_result is None:
            reason_codes.append("INVALID_INPUT")

        reason_codes = sorted_codes(reason_codes)

        if reason_codes:
            status = "invalid"
        elif unsupported_reason is not None:
            status = "unsupported"
        else:
            status = "frozen"

        output.append({
            "name": name,
            "status": status,
            "inventory": inventory,
            "totalBytes": total_bytes,
            "packageDigest": package_digest,
            "reasonCodes": reason_codes
        })

    output.sort(
        key=lambda x: x["name"].encode("utf-8")
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

    response_json = compact(response)

    conn.execute(
        """
        INSERT INTO freezes
        (freeze_id, request_json, response_json)
        VALUES (?, ?, ?)
        """,
        (
            freeze_id,
            request_json,
            response_json
        )
    )

    conn.commit()
    conn.close()

    return response, 200


def load_freeze(freeze_id):
    conn = get_db()

    row = conn.execute(
        """
        SELECT response_json
        FROM freezes
        WHERE freeze_id = ?
        """,
        (freeze_id,)
    ).fetchone()

    conn.close()

    if row is None:
        return None

    return json.loads(row[0])


def validate_candidate_manifest(candidate):
    result = make_inventory(
        candidate.get("files")
    )

    if result is None:
        return False, None, None, None

    inventory, total, digest = result

    if (
        candidate.get("inventory") != inventory
        or candidate.get("totalBytes") != total
        or candidate.get("packageDigest") != digest
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
        return {
            "error": "INVALID_INPUT"
        }, 400

    frozen = load_freeze(freeze_id)

    if frozen is None:
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    if candidates != frozen["candidates"]:
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    if (
        not safe_integer(policy.get("maxBytes"))
        or not finite_unit(
            policy.get("aggregateFloor")
        )
        or not isinstance(
            policy.get("requiredSlices"),
            dict
        )
        or not finite_nonnegative(
            policy.get("maxLatencyMs")
        )
        or not unique_strings(
            policy.get("candidateOrder")
        )
    ):
        return {
            "error": "INVALID_INPUT"
        }, 400

    required_slices = policy["requiredSlices"]

    for name, floor in required_slices.items():
        if (
            not isinstance(name, str)
            or not name
            or not finite_unit(floor)
        ):
            return {
                "error": "INVALID_INPUT"
            }, 400

    names = [
        x["name"]
        for x in candidates
    ]

    if set(names) != set(policy["candidateOrder"]):
        return {
            "error": "INVALID_INPUT"
        }, 400

    results = []

    order = {
        name: i
        for i, name in enumerate(
            policy["candidateOrder"]
        )
    }

    for candidate in candidates:
        name = candidate["name"]
        reason_codes = []

        frozen_candidate = next(
            x for x in frozen["candidates"]
            if x["name"] == name
        )

        if (
            candidate
            != frozen_candidate
        ):
            reason_codes.append(
                "INVALID_LINEAGE"
            )

        manifest_ok, _, manifest_total, _ = \
            validate_candidate_manifest(
                candidate
            )

        if not manifest_ok:
            reason_codes.append(
                "INVALID_MANIFEST"
            )

        aggregate = None
        slices = {}

        prediction_ok = True
        slice_values = {}

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

            slice_values.setdefault(
                slice_name,
                []
            ).append(correct)

        if not prediction_ok:
            reason_codes.append(
                "INVALID_PREDICTIONS"
            )
        else:
            aggregate = round(
                sum(
                    row["predictions"][name]
                    == row["label"]
                    for row in rows
                ) / len(rows),
                12
            )

            for slice_name, values in \
                    slice_values.items():
                slices[slice_name] = round(
                    sum(values) / len(values),
                    12
                )

            if aggregate < policy["aggregateFloor"]:
                reason_codes.append(
                    "AGGREGATE_FLOOR"
                )

            for slice_name, floor in \
                    required_slices.items():

                if slice_name not in slices:
                    reason_codes.append(
                        "MISSING_SLICE:" + slice_name
                    )
                elif slices[slice_name] < floor:
                    reason_codes.append(
                        "SLICE_FLOOR:" + slice_name
                    )

        total_bytes = None

        if manifest_ok:
            total_bytes = manifest_total

            if total_bytes > policy["maxBytes"]:
                reason_codes.append(
                    "SIZE_LIMIT"
                )

        latency = latencies.get(name)

        if not finite_nonnegative(latency):
            latency = None
        elif latency > policy["maxLatencyMs"]:
            reason_codes.append(
                "LATENCY_LIMIT"
            )

        admitted = (
            candidate["status"] == "frozen"
            and prediction_ok
            and manifest_ok
            and aggregate is not None
            and total_bytes is not None
            and latency is not None
            and total_bytes <= policy["maxBytes"]
            and latency <= policy["maxLatencyMs"]
            and aggregate >= policy["aggregateFloor"]
            and all(
                s in slices and
                slices[s] >= floor
                for s, floor
                in required_slices.items()
            )
            and not any(
                code == "INVALID_LINEAGE"
                for code in reason_codes
            )
        )

        results.append({
            "name": name,
            "aggregate": aggregate,
            "slices": slices,
            "totalBytes": total_bytes,
            "latencyMs": latency,
            "admitted": admitted,
            "reasonCodes": sorted_codes(
                reason_codes
            )
        })

    results.sort(
        key=lambda x: (
            order.get(
                x["name"],
                len(order)
            ),
            x["name"].encode("utf-8")
        )
    )

    eligible = [
        x for x in results
        if x["admitted"]
    ]

    winner = None

    if eligible:
        winner = min(
            eligible,
            key=lambda x: (
                x["totalBytes"],
                x["latencyMs"],
                order[x["name"]]
            )
        )

    manifest = None

    if winner:
        manifest = next(
            x for x in candidates
            if x["name"] == winner["name"]
        )

    return {
        "freezeId": freeze_id,
        "selected": (
            winner["name"]
            if winner
            else None
        ),
        "results": results,
        "packageManifest": manifest
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