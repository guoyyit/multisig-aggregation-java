#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
PORT="${1:-18082}"
DATA="/tmp/multisig-demo-$PORT"
CP="target/classes:target/test-classes:$(cat /tmp/multisig-cp.txt)"

nohup env MULTISIG_DATA_DIR="$DATA" MULTISIG_SESSION_TTL_SECONDS=60 \
  java -jar target/multisig-aggregation-java-1.0-SNAPSHOT.jar \
  --server.port="$PORT" > /tmp/multisig-app-$PORT.log 2>&1 &
APP=$!
trap 'kill $APP 2>/dev/null || true' EXIT
sleep 7

tool() {
  MULTISIG_DATA_DIR="$DATA" java -cp "$CP" \
    com.github.guoyyit.multisigaggregationjava.tests.DemoClientTool "$@"
}

OUT=$(tool gen demo2)
PUB=$(echo "$OUT" | grep PUB | cut -d= -f2)
POP=$(echo "$OUT" | grep POP | cut -d= -f2)

curl -s -X POST "localhost:$PORT/api/keys/register" -H 'Content-Type: application/json' \
  -d "{\"keyId\":\"demo2\",\"owner\":\"demo\",\"pubHex\":\"$PUB\",\"popHex\":\"$POP\"}" \
  | sed -n 's/.*"status" : "\([A-Z]*\)".*/register-status=\1/p'

MSG=$(printf 'real local message' | xxd -p | tr -d '\n')
CREATE=$(curl -s -X POST "localhost:$PORT/api/sessions" -H 'Content-Type: application/json' \
  -d "{\"sessionId\":\"demo-s2\",\"messageHex\":\"$MSG\",\"participantKeyIds\":[\"demo2\"]}")
SALT=$(echo "$CREATE" | sed -n 's/.*"saltHex" : "\([0-9a-f]*\)".*/\1/p')

COMMIT=$(tool commitment demo2 demo-s2 "$SALT")
curl -s -X POST "localhost:$PORT/api/sessions/demo-s2/commitments" \
  -H 'Content-Type: application/json' \
  -d "{\"keyId\":\"demo2\",\"commitmentHex\":\"$COMMIT\"}" >/dev/null

NONCE=$(tool nonce demo2 demo-s2)
curl -s -X POST "localhost:$PORT/api/sessions/demo-s2/nonces" \
  -H 'Content-Type: application/json' -d "{\"keyId\":\"demo2\",\"nonceHex\":\"$NONCE\"}" \
  | sed -n 's/.*"state" : "\([A-Z_]*\)".*/nonce-state=\1/p'

PARTIAL=$(tool partial demo2 demo-s2 "$MSG" "$PUB" "$NONCE")
FINAL=$(curl -s -X POST "localhost:$PORT/api/sessions/demo-s2/partials" \
  -H 'Content-Type: application/json' -d "{\"keyId\":\"demo2\",\"partialHex\":\"$PARTIAL\"}")
echo "$FINAL" | sed -n 's/.*"state" : "\([A-Z_]*\)".*/final-state=\1/p'
SIG=$(echo "$FINAL" | sed -n 's/.*"aggregateSignatureHex" : "\([0-9a-f]*\)".*/\1/p')

echo -n "verify-valid="
curl -s -X POST "localhost:$PORT/api/aggregate/verify" -H 'Content-Type: application/json' \
  -d "{\"messageHex\":\"$MSG\",\"aggregatePubHex\":\"$PUB\",\"signatureHex\":\"$SIG\"}"
echo
BAD=$(printf 'tampered message' | xxd -p | tr -d '\n')
echo -n "verify-tampered="
curl -s -X POST "localhost:$PORT/api/aggregate/verify" -H 'Content-Type: application/json' \
  -d "{\"messageHex\":\"$BAD\",\"aggregatePubHex\":\"$PUB\",\"signatureHex\":\"$SIG\"}"
echo
