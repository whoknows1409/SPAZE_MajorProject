#!/usr/bin/env bash
# ============================================================
# SPAZE Server — Edge Case Test Suite
# Tests security boundaries, RBAC enforcement, and error handling
#
# Prerequisites:
#   - Server running at http://localhost:8000
#   - Fresh database with admin registered
#
# Usage:
#   chmod +x tests/test_edge_cases.sh
#   ./tests/test_edge_cases.sh
# ============================================================

set -e

BASE_URL="http://localhost:8000"
PASS=0
FAIL=0
TOTAL=0

# Colors
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
NC="\033[0m"

# ============================================================
# Helper Functions
# ============================================================

assert_status() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))

    if [ "$actual" -eq "$expected" ]; then
        echo -e "  ${GREEN}✅ PASS${NC} [$actual] $test_name"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}❌ FAIL${NC} [$actual expected $expected] $test_name"
        FAIL=$((FAIL + 1))
    fi
}

assert_json_contains() {
    local test_name="$1"
    local expected_key="$2"
    local expected_val="$3"
    local body="$4"
    TOTAL=$((TOTAL + 1))

    if echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if str(d.get('$expected_key','')).lower().find('${expected_val}'.lower())>=0 else 1)" 2>/dev/null; then
        echo -e "  ${GREEN}✅ PASS${NC} $test_name"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}❌ FAIL${NC} $test_name (expected $expected_key to contain '$expected_val')"
        FAIL=$((FAIL + 1))
    fi
}

http_post() {
    curl -s -o /tmp/spaze_test_body -w "%{http_code}" \
        -X POST "$BASE_URL$1" \
        -H "Content-Type: application/json" \
        ${2:+-H "Authorization: Bearer $2"} \
        -d "$3"
}

http_get() {
    curl -s -o /tmp/spaze_test_body -w "%{http_code}" \
        -X GET "$BASE_URL$1" \
        ${2:+-H "Authorization: Bearer $2"}
}

http_delete() {
    curl -s -o /tmp/spaze_test_body -w "%{http_code}" \
        -X DELETE "$BASE_URL$1" \
        ${2:+-H "Authorization: Bearer $2"}
}

http_patch() {
    curl -s -o /tmp/spaze_test_body -w "%{http_code}" \
        -X PATCH "$BASE_URL$1" \
        -H "Content-Type: application/json" \
        ${2:+-H "Authorization: Bearer $2"} \
        -d "$3"
}

get_body() {
    cat /tmp/spaze_test_body
}

# ============================================================
# Pre-flight Check
# ============================================================

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   SPAZE Server — Edge Case Test Suite            ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}▸ Pre-flight check...${NC}"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/health")
if [ "$STATUS" != "200" ]; then
    echo -e "${RED}  Server not running at $BASE_URL — aborting.${NC}"
    exit 1
fi
echo -e "  ${GREEN}Server is running.${NC}"
echo ""

# ============================================================
# 1. AUTHENTICATION EDGE CASES
# ============================================================

echo -e "${YELLOW}▸ 1. Authentication Edge Cases${NC}"

# Login as admin to get a valid token
STATUS=$(http_post "/api/auth/login" "" '{"email":"spazeadmin@gmail.com","password":"role1@123"}')
ADMIN_TOKEN=$(cat /tmp/spaze_test_body | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -z "$ADMIN_TOKEN" ]; then
    echo -e "${RED}  Cannot get admin token — make sure admin is registered.${NC}"
    exit 1
fi
echo -e "  ${GREEN}Admin token acquired.${NC}"

# 1.1 Login with wrong password
STATUS=$(http_post "/api/auth/login" "" '{"email":"spazeadmin@gmail.com","password":"wrongpassword"}')
assert_status "Login with wrong password → 401" 401 "$STATUS"

# 1.2 Login with non-existent email
STATUS=$(http_post "/api/auth/login" "" '{"email":"nobody@spaze.io","password":"pass123"}')
assert_status "Login with non-existent email → 401" 401 "$STATUS"

# 1.3 Register duplicate admin
STATUS=$(http_post "/api/auth/register" "" '{"name":"Hacker","email":"hacker@spaze.io","password":"hack123"}')
assert_status "Register when admin exists → 400" 400 "$STATUS"

# 1.4 Login with empty body
STATUS=$(http_post "/api/auth/login" "" '{}')
assert_status "Login with empty body → 422" 422 "$STATUS"

# 1.5 Access admin endpoint with no token
STATUS=$(http_get "/api/admin/badges/" "")
assert_status "Admin endpoint without token → 401" 401 "$STATUS"

# 1.6 Access admin endpoint with garbage token
STATUS=$(http_get "/api/admin/badges/" "this.is.not.a.valid.jwt")
assert_status "Admin endpoint with garbage token → 401" 401 "$STATUS"

# 1.7 Access admin endpoint with tampered token (flip last char)
TAMPERED_TOKEN="${ADMIN_TOKEN%?}X"
STATUS=$(http_get "/api/admin/badges/" "$TAMPERED_TOKEN")
assert_status "Admin endpoint with tampered token → 401" 401 "$STATUS"

echo ""

# ============================================================
# 2. RBAC ENFORCEMENT
# ============================================================

echo -e "${YELLOW}▸ 2. RBAC Enforcement${NC}"

# Login as employee (User1)
STATUS=$(http_post "/api/auth/login" "" '{"email":"user1@spaze.io","password":"role2@123"}')
EMPLOYEE_TOKEN=$(cat /tmp/spaze_test_body | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -z "$EMPLOYEE_TOKEN" ]; then
    echo -e "  ${YELLOW}⚠ User1 not found, creating...${NC}"
    http_post "/api/admin/users/" "$ADMIN_TOKEN" '{"name":"User1","email":"user1@spaze.io","password":"role2@123","role":"employee","badge_id":1}' > /dev/null
    STATUS=$(http_post "/api/auth/login" "" '{"email":"user1@spaze.io","password":"role2@123"}')
    EMPLOYEE_TOKEN=$(cat /tmp/spaze_test_body | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
fi

# 2.1 Employee tries to list badges
STATUS=$(http_get "/api/admin/badges/" "$EMPLOYEE_TOKEN")
assert_status "Employee cannot list badges → 403" 403 "$STATUS"

# 2.2 Employee tries to create a badge
STATUS=$(http_post "/api/admin/badges/" "$EMPLOYEE_TOKEN" '{"mac_address":"FF:FF:FF:FF:FF:FF","badge_name":"Rogue Badge"}')
assert_status "Employee cannot create badge → 403" 403 "$STATUS"

# 2.3 Employee tries to create a user
STATUS=$(http_post "/api/admin/users/" "$EMPLOYEE_TOKEN" '{"name":"Rogue","email":"rogue@spaze.io","password":"r0gue","role":"admin"}')
assert_status "Employee cannot create user → 403" 403 "$STATUS"

# 2.4 Employee tries to create a device
STATUS=$(http_post "/api/admin/devices/" "$EMPLOYEE_TOKEN" '{"hostname":"ROGUE-PC","mac_address":"FF:FF:FF:FF:FF:FE"}')
assert_status "Employee cannot register device → 403" 403 "$STATUS"

# 2.5 Employee tries to view audit logs
STATUS=$(http_get "/api/audit/logs" "$EMPLOYEE_TOKEN")
assert_status "Employee cannot view audit logs → 403" 403 "$STATUS"

# 2.6 Employee tries to create a policy
STATUS=$(http_post "/api/admin/policies/" "$EMPLOYEE_TOKEN" '{"badge_id":1,"device_id":1}')
assert_status "Employee cannot create policy → 403" 403 "$STATUS"

# 2.7 Employee tries to delete a policy
STATUS=$(http_delete "/api/admin/policies/1" "$EMPLOYEE_TOKEN")
assert_status "Employee cannot delete policy → 403" 403 "$STATUS"

echo ""

# ============================================================
# 3. KEY DISTRIBUTION EDGE CASES
# ============================================================

echo -e "${YELLOW}▸ 3. Key Distribution Edge Cases${NC}"

# 3.1 Unregistered badge
STATUS=$(http_post "/api/keys/request" "" '{"badge_mac":"FF:FF:FF:FF:FF:FF","device_hostname":"IMMORTAL"}')
BODY=$(get_body)
assert_status "Unregistered badge → 200" 200 "$STATUS"
assert_json_contains "Unregistered badge → authorized=false" "authorized" "false" "$BODY"
assert_json_contains "Unregistered badge → 'not registered'" "message" "not registered" "$BODY"

# 3.2 Unregistered device
STATUS=$(http_post "/api/keys/request" "" '{"badge_mac":"5c:01:3b:4b:e3:2a","device_hostname":"NONEXISTENT-PC"}')
BODY=$(get_body)
assert_status "Unregistered device → 200" 200 "$STATUS"
assert_json_contains "Unregistered device → authorized=false" "authorized" "false" "$BODY"
assert_json_contains "Unregistered device → 'not registered'" "message" "not registered" "$BODY"

# 3.3 Valid badge + valid device (should work)
STATUS=$(http_post "/api/keys/request" "" '{"badge_mac":"5c:01:3b:4b:e3:2a","device_hostname":"IMMORTAL"}')
BODY=$(get_body)
assert_status "Valid badge+device → 200" 200 "$STATUS"
assert_json_contains "Valid badge+device → authorized=true" "authorized" "true" "$BODY"

# 3.4 Store a test key
STATUS=$(http_post "/api/keys/store" "" '{"badge_mac":"5c:01:3b:4b:e3:2a","device_hostname":"IMMORTAL","file_path":"edge_test.enc","encrypted_fek":"ZWRnZXRlc3Q="}')
assert_status "Store key → 200" 200 "$STATUS"

# 3.5 Verify key is returned
STATUS=$(http_post "/api/keys/request" "" '{"badge_mac":"5c:01:3b:4b:e3:2a","device_hostname":"IMMORTAL"}')
BODY=$(get_body)
assert_json_contains "Key returned after store" "authorized" "true" "$BODY"

# 3.6 Delete the test key
STATUS=$(http_post "/api/keys/delete" "" '{"badge_mac":"5c:01:3b:4b:e3:2a","device_hostname":"IMMORTAL","file_path":"edge_test.enc"}')
assert_status "Delete key → 200" 200 "$STATUS"

# 3.7 Empty badge_mac
STATUS=$(http_post "/api/keys/request" "" '{"badge_mac":"","device_hostname":"IMMORTAL"}')
BODY=$(get_body)
assert_status "Empty badge_mac → 200" 200 "$STATUS"
assert_json_contains "Empty badge_mac → denied" "authorized" "false" "$BODY"

# 3.8 Missing fields
STATUS=$(http_post "/api/keys/request" "" '{}')
assert_status "Missing fields → 422" 422 "$STATUS"

echo ""

# ============================================================
# 4. BADGE STATUS EDGE CASES
# ============================================================

echo -e "${YELLOW}▸ 4. Badge Status Edge Cases${NC}"

# Reset: ensure badge is active before testing
http_patch "/api/admin/badges/1" "$ADMIN_TOKEN" '{"status":"active"}' > /dev/null 2>&1

# 4.1 Mark badge as lost → key request denied
STATUS=$(http_patch "/api/admin/badges/1" "$ADMIN_TOKEN" '{"status":"lost"}')
assert_status "Mark badge lost → 200" 200 "$STATUS"

STATUS=$(http_post "/api/keys/request" "" '{"badge_mac":"5c:01:3b:4b:e3:2a","device_hostname":"IMMORTAL"}')
BODY=$(get_body)
assert_json_contains "Lost badge → denied" "authorized" "false" "$BODY"
assert_json_contains "Lost badge → message" "message" "lost" "$BODY"

# 4.2 Revoke badge → key request denied
STATUS=$(http_patch "/api/admin/badges/1" "$ADMIN_TOKEN" '{"status":"revoked"}')
assert_status "Revoke badge → 200" 200 "$STATUS"

STATUS=$(http_post "/api/keys/request" "" '{"badge_mac":"5c:01:3b:4b:e3:2a","device_hostname":"IMMORTAL"}')
BODY=$(get_body)
assert_json_contains "Revoked badge → denied" "authorized" "false" "$BODY"

# 4.3 Re-activate badge → key request allowed
STATUS=$(http_patch "/api/admin/badges/1" "$ADMIN_TOKEN" '{"status":"active"}')
assert_status "Re-activate badge → 200" 200 "$STATUS"

STATUS=$(http_post "/api/keys/request" "" '{"badge_mac":"5c:01:3b:4b:e3:2a","device_hostname":"IMMORTAL"}')
BODY=$(get_body)
assert_json_contains "Re-activated badge → authorized" "authorized" "true" "$BODY"

echo ""

# ============================================================
# 5. POLICY EDGE CASES
# ============================================================

echo -e "${YELLOW}▸ 5. Policy Edge Cases${NC}"

# Flush Redis to prevent cached keys from bypassing policy check
redis-cli FLUSHDB > /dev/null 2>&1

# Revoke ALL active policies
ALL_ACTIVE=$(curl -s "$BASE_URL/api/admin/policies/" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | \
    python3 -c "import sys,json; ps=[p for p in json.load(sys.stdin) if p['is_active']]; print(' '.join(str(p['id']) for p in ps))" 2>/dev/null)
for PID in $ALL_ACTIVE; do
    http_delete "/api/admin/policies/$PID" "$ADMIN_TOKEN" > /dev/null 2>&1
done

# 5.1 Verify: no policy → key request denied
redis-cli FLUSHDB > /dev/null 2>&1

STATUS=$(http_post "/api/keys/request" "" '{"badge_mac":"5c:01:3b:4b:e3:2a","device_hostname":"IMMORTAL"}')
BODY=$(get_body)
assert_json_contains "Revoked policy → denied" "authorized" "false" "$BODY"
assert_json_contains "Revoked policy → 'No access'" "message" "No access" "$BODY"

# 5.2 Re-create policy → key request allowed
STATUS=$(http_post "/api/admin/policies/" "$ADMIN_TOKEN" '{"badge_id":1,"device_id":1}')
assert_status "Re-create policy → 200" 200 "$STATUS"

STATUS=$(http_post "/api/keys/request" "" '{"badge_mac":"5c:01:3b:4b:e3:2a","device_hostname":"IMMORTAL"}')
BODY=$(get_body)
assert_json_contains "New policy → authorized" "authorized" "true" "$BODY"

# 5.3 Create policy for non-existent badge
STATUS=$(http_post "/api/admin/policies/" "$ADMIN_TOKEN" '{"badge_id":999,"device_id":1}')
assert_status "Policy with bad badge → 400" 400 "$STATUS"

# 5.4 Create policy for non-existent device
STATUS=$(http_post "/api/admin/policies/" "$ADMIN_TOKEN" '{"badge_id":1,"device_id":999}')
assert_status "Policy with bad device → 400" 400 "$STATUS"

echo ""

# ============================================================
# 6. DUPLICATE & VALIDATION EDGE CASES
# ============================================================

echo -e "${YELLOW}▸ 6. Duplicate & Validation Edge Cases${NC}"

# 6.1 Duplicate badge MAC
STATUS=$(http_post "/api/admin/badges/" "$ADMIN_TOKEN" '{"mac_address":"5c:01:3b:4b:e3:2a","badge_name":"Duplicate"}')
assert_status "Duplicate badge MAC → 400" 400 "$STATUS"

# 6.2 Duplicate user email
STATUS=$(http_post "/api/admin/users/" "$ADMIN_TOKEN" '{"name":"Dup","email":"spazeadmin@gmail.com","password":"test","role":"employee"}')
assert_status "Duplicate user email → 400" 400 "$STATUS"

# 6.3 Invalid role
STATUS=$(http_post "/api/admin/users/" "$ADMIN_TOKEN" '{"name":"Bad","email":"bad@spaze.io","password":"test","role":"superadmin"}')
assert_status "Invalid role → 400" 400 "$STATUS"

# 6.4 Invalid badge status
STATUS=$(http_patch "/api/admin/badges/1" "$ADMIN_TOKEN" '{"status":"invalid_status"}')
assert_status "Invalid badge status → 400" 400 "$STATUS"

# 6.5 Update non-existent badge
STATUS=$(http_patch "/api/admin/badges/999" "$ADMIN_TOKEN" '{"badge_name":"Ghost"}')
assert_status "Update non-existent badge → 404" 404 "$STATUS"

# 6.6 Update non-existent user
STATUS=$(http_patch "/api/admin/users/999" "$ADMIN_TOKEN" '{"name":"Ghost"}')
assert_status "Update non-existent user → 404" 404 "$STATUS"

# 6.7 Delete non-existent policy
STATUS=$(http_delete "/api/admin/policies/999" "$ADMIN_TOKEN")
assert_status "Delete non-existent policy → 404" 404 "$STATUS"

echo ""

# ============================================================
# 7. AUDIT EDGE CASES
# ============================================================

echo -e "${YELLOW}▸ 7. Audit Edge Cases${NC}"

# 7.1 Log an event
STATUS=$(http_post "/api/audit/log" "" '{"badge_mac":"5c:01:3b:4b:e3:2a","device_hostname":"IMMORTAL","action":"test_event","details":"Edge case test"}')
assert_status "Log audit event → 200" 200 "$STATUS"

# 7.2 Log geofence event
STATUS=$(http_post "/api/audit/geofence" "" '{"badge_mac":"5c:01:3b:4b:e3:2a","anchor_id":"ANCHOR_WS_01","event_type":"enter","rssi_value":-65}')
assert_status "Log geofence event → 200" 200 "$STATUS"

# 7.3 Audit logs accessible by admin
STATUS=$(http_get "/api/audit/logs" "$ADMIN_TOKEN")
assert_status "Admin can view audit logs → 200" 200 "$STATUS"

# 7.4 Audit stats accessible by admin
STATUS=$(http_get "/api/audit/stats" "$ADMIN_TOKEN")
assert_status "Admin can view audit stats → 200" 200 "$STATUS"

echo ""

# ============================================================
# RESULTS
# ============================================================

echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  RESULTS: ${PASS}/${TOTAL} passed, ${FAIL} failed${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════${NC}"

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}  🎉 ALL TESTS PASSED!${NC}"
else
    echo -e "${RED}  ⚠️  ${FAIL} test(s) failed — review output above.${NC}"
fi

echo ""

# Cleanup
rm -f /tmp/spaze_test_body

exit $FAIL
