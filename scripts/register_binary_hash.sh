#!/bin/bash

IMMUDB_ADDR="${IMMUDB_ADDR:-127.0.0.1:8443}"
FULL_HOSTNAME="${FULL_HOSTNAME:-$(hostname)}"
REAL_USER="${SUDO_USER:-$(whoami)}"
DEPLOYMENT_TYPE="${DEPLOYMENT_TYPE:-host}"
COLLECTION_NAME="${COLLECTION_NAME:-binary_hashes_v3}"

echo "[INFO] Will register for hostnames: '$REAL_USER' and '$FULL_HOSTNAME'"
echo "[INFO] Using collection: $COLLECTION_NAME"

BINARY_PATH="./target/release/scaphandre"
if [ -f "$BINARY_PATH" ]; then
    HASH_VALUE=$(sha256sum "$BINARY_PATH" | cut -d' ' -f1)
    echo "[INFO] Calculated hash from binary: $HASH_VALUE"
else
    echo "[ERROR] Binary not found at $BINARY_PATH"
    exit 1
fi

echo "[INFO] Reading PCR values from TPM..."
PCR_OUTPUT=$(tpm2_pcrread sha256:0,7,10 2>/dev/null)
PCR0=$(echo "$PCR_OUTPUT" | grep -E "^\s*0\s*:" | sed 's/.*0x//' | tr '[:upper:]' '[:lower:]')
PCR7=$(echo "$PCR_OUTPUT" | grep -E "^\s*7\s*:" | sed 's/.*0x//' | tr '[:upper:]' '[:lower:]')
PCR10=$(echo "$PCR_OUTPUT" | grep -E "^\s*10\s*:" | sed 's/.*0x//' | tr '[:upper:]' '[:lower:]')

PCR0="${PCR0:-0000000000000000000000000000000000000000000000000000000000000000}"
PCR7="${PCR7:-0000000000000000000000000000000000000000000000000000000000000000}"
PCR10="${PCR10:-0000000000000000000000000000000000000000000000000000000000000000}"

echo "[INFO] PCR0: $PCR0"
echo "[INFO] PCR7: $PCR7"
echo "[INFO] PCR10: $PCR10"

echo ""
echo "[INFO] Connecting to ImmuDB at $IMMUDB_ADDR..."

SESSION_ID=$(curl -sk "https://$IMMUDB_ADDR/api/v2/authorization/session/open" \
    -H "Content-Type: application/json" \
    -d '{"username":"immudb","password":"immudb","database":"defaultdb"}' \
    | grep -o '"sessionID":"[^"]*"' | cut -d'"' -f4)

if [ -z "$SESSION_ID" ]; then
    echo "[ERROR] Failed to open ImmuDB session"
    exit 1
fi
echo "[INFO] Session opened: ${SESSION_ID:0:20}..."

echo "[INFO] Step 1: Deleting existing collection $COLLECTION_NAME..."
DELETE_RESULT=$(curl -sk -X DELETE "https://$IMMUDB_ADDR/api/v2/collection/$COLLECTION_NAME" \
    -H "Grpc-Metadata-SessionID: $SESSION_ID" 2>&1)
echo "[INFO] Delete result: $DELETE_RESULT"

echo "[INFO] Step 2: Creating collection $COLLECTION_NAME with schema..."
RESULT=$(curl -sk "https://$IMMUDB_ADDR/api/v2/collection/$COLLECTION_NAME" \
    -H "Content-Type: application/json" \
    -H "Grpc-Metadata-SessionID: $SESSION_ID" \
    -d '{
        "fields": [
            {"name": "binary_name", "type": "STRING"},
            {"name": "hash_value", "type": "STRING"},
            {"name": "hostname", "type": "STRING"},
            {"name": "deployment_type", "type": "STRING"},
            {"name": "active", "type": "BOOLEAN"},
            {"name": "pcr0", "type": "STRING"},
            {"name": "pcr7", "type": "STRING"},
            {"name": "pcr10", "type": "STRING"}
        ],
        "indexes": [
            {"fields": ["hostname"]},
            {"fields": ["binary_name"]}
        ]
    }')
echo "[INFO] Collection creation result: $RESULT"

echo "[INFO] Step 3: Inserting binary hash documents for both hostnames..."
RESULT=$(curl -sk -X POST "https://$IMMUDB_ADDR/api/v2/collection/$COLLECTION_NAME/documents" \
    -H "Content-Type: application/json" \
    -H "Grpc-Metadata-SessionID: $SESSION_ID" \
    -d "{
        \"documents\": [
            {
                \"binary_name\": \"scaphandre\",
                \"hash_value\": \"$HASH_VALUE\",
                \"hostname\": \"$REAL_USER\",
                \"deployment_type\": \"$DEPLOYMENT_TYPE\",
                \"active\": true,
                \"pcr0\": \"$PCR0\",
                \"pcr7\": \"$PCR7\",
                \"pcr10\": \"$PCR10\"
            },
            {
                \"binary_name\": \"scaphandre\",
                \"hash_value\": \"$HASH_VALUE\",
                \"hostname\": \"$FULL_HOSTNAME\",
                \"deployment_type\": \"$DEPLOYMENT_TYPE\",
                \"active\": true,
                \"pcr0\": \"$PCR0\",
                \"pcr7\": \"$PCR7\",
                \"pcr10\": \"$PCR10\"
            }
        ]
    }")
echo "[INFO] Document insertion result: $RESULT"

echo ""
echo "Binary hash registered in ImmuDB:"
echo "  Binary:     scaphandre"
echo "  Hash:       $HASH_VALUE"
echo "  Hostnames:  $REAL_USER, $FULL_HOSTNAME"
echo "  Deployment: $DEPLOYMENT_TYPE"
