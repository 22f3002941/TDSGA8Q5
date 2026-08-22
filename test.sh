#!/bin/bash
set -e

URL="https://tdsga8q5.onrender.com/quantize"

echo "=== FREEZE ==="
FREEZE_RESPONSE=$(curl -s -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d '{
    "phase": "freeze",
    "freezeId": "manual-test-1",
    "calibrationDigest": "cal-1",
    "tokenizerDigest": "tok-1",
    "allowedUnsupportedReasons": [],
    "candidates": [
      {
        "name": "int8",
        "files": { "model.bin": "hello world" },
        "loadable": true,
        "calibrationDigest": "cal-1",
        "tokenizerDigest": "tok-1"
      }
    ]
  }')

echo "$FREEZE_RESPONSE"
echo ""
echo "=== SELECT ==="

python3 -c "
import json, sys
frozen = json.loads('''$FREEZE_RESPONSE''')
select_payload = {
    'phase': 'select',
    'freezeId': 'manual-test-1',
    'candidates': frozen['candidates'],
    'policy': {
        'maxBytes': 1000000,
        'aggregateFloor': 0.5,
        'requiredSlices': {},
        'maxLatencyMs': 1000,
        'candidateOrder': ['int8']
    },
    'latencies': {'int8': 50},
    'rows': [
        {'label': 1, 'slice': 'critical', 'predictions': {'int8': 1}}
    ]
}
print(json.dumps(select_payload))
" > /tmp/select_payload.json

curl -s -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d @/tmp/select_payload.json

echo ""