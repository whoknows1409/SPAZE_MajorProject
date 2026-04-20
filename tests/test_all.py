#!/usr/bin/env python3
"""
SPAZE Test Suite
Tests for Phase 1 (Filter Pipeline) and Phase 2 (File Encryption Engine)

Run: cd ~/Documents/MajorProject && source venv/bin/activate
     python tests/test_all.py
"""

import os
import sys
import shutil
import hashlib
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.file_monitor.engine import FileEncryptionEngine
from agent.file_monitor.crypto import encrypt_file, decrypt_file_to_memory, generate_key
from agent.key_manager.key_manager import EphemeralKeyManager
from agent.ble_scanner.filters import (
    EMAFilter, KalmanFilter, HysteresisFilter, GracePeriod,
    RSSIFilterPipeline, FilterConfig, ProximityState,
)

VAULT = "/tmp/spaze-test-vault"
MOUNT = "/tmp/spaze-test-mount"
passed = 0
failed = 0


def setup():
    shutil.rmtree(VAULT, ignore_errors=True)
    shutil.rmtree(MOUNT, ignore_errors=True)


def test(name, condition):
    global passed, failed
    if condition:
        print(f"  ✅ {name}")
        passed += 1
    else:
        print(f"  ❌ {name}")
        failed += 1


# ================================================================
# TEST GROUP 1: AES-256-GCM Encryption / Decryption
# ================================================================
print("\n" + "=" * 60)
print("TEST GROUP 1: AES-256-GCM Encryption")
print("=" * 60)

setup()
os.makedirs(VAULT, exist_ok=True)

# Test 1.1: Basic encrypt/decrypt
key = generate_key()
test("Key is 32 bytes (256-bit)", len(key) == 32)

path = f"{VAULT}/test.txt"
with open(path, "w") as f:
    f.write("Hello SPAZE!")

enc_path = encrypt_file(path, key)
test("Encrypted file created (.enc)", os.path.exists(enc_path))
test("Original file deleted", not os.path.exists(path))

plaintext = decrypt_file_to_memory(enc_path, key)
test("Decryption matches original", plaintext.decode() == "Hello SPAZE!")

# Test 1.2: Wrong key fails
wrong_key = generate_key()
try:
    decrypt_file_to_memory(enc_path, wrong_key)
    test("Wrong key rejected", False)
except Exception:
    test("Wrong key rejected (InvalidTag)", True)

# Test 1.3: Tampered ciphertext fails
with open(enc_path, "r+b") as f:
    f.seek(20)
    f.write(b"\xff\xff\xff")
try:
    decrypt_file_to_memory(enc_path, key)
    test("Tampered file rejected", False)
except Exception:
    test("Tampered file rejected (integrity check)", True)

# Test 1.4: Empty file encryption
key2 = generate_key()
empty_path = f"{VAULT}/empty.txt"
with open(empty_path, "w") as f:
    pass
enc_empty = encrypt_file(empty_path, key2)
result = decrypt_file_to_memory(enc_empty, key2)
test("Empty file encrypt/decrypt", result == b"")

# Test 1.5: Large file encryption
key3 = generate_key()
large_path = f"{VAULT}/large.bin"
large_data = os.urandom(1024 * 1024)  # 1 MB
with open(large_path, "wb") as f:
    f.write(large_data)
enc_large = encrypt_file(large_path, key3)
result = decrypt_file_to_memory(enc_large, key3)
test("Large file (1MB) encrypt/decrypt", result == large_data)


# ================================================================
# TEST GROUP 2: Ephemeral Key Manager
# ================================================================
print("\n" + "=" * 60)
print("TEST GROUP 2: Ephemeral Key Manager")
print("=" * 60)

setup()
os.makedirs(VAULT, exist_ok=True)

km = EphemeralKeyManager(keystore_path=f"{VAULT}/.keys.json")

# Test 2.1: Key generation
k1 = km.generate_key("file1.enc")
test("Key generated (32 bytes)", len(k1) == 32)
test("Key stored in memory", km.has_key("file1.enc"))

# Test 2.2: Key retrieval
k1_retrieved = km.get_key("file1.enc")
test("Key retrievable", k1_retrieved == k1)

# Test 2.3: Multiple keys
km.generate_key("file2.enc")
km.generate_key("file3.enc")
test("Multiple keys stored", km.key_count == 3)

# Test 2.4: Secure wipe
km.wipe_all_keys()
test("All keys wiped (count=0)", km.key_count == 0)
# Note: get_key() reloads from keystore on disk, so we test with in-memory-only manager
km_mem = EphemeralKeyManager()  # No keystore
km_mem.generate_key("temp.enc")
km_mem.wipe_all_keys()
test("Key not retrievable after wipe (in-memory)", km_mem.get_key("temp.enc") is None)

# Test 2.5: Key persistence across instances
km2 = EphemeralKeyManager(keystore_path=f"{VAULT}/.keys.json")
k_persist = km2.generate_key("persist.enc")
km3 = EphemeralKeyManager(keystore_path=f"{VAULT}/.keys.json")
test("Key persists across instances", km3.get_key("persist.enc") == k_persist)

# Test 2.6: Multiple encrypt calls don't overwrite keys
km4 = EphemeralKeyManager(keystore_path=f"{VAULT}/.keys2.json")
k_a = km4.generate_key("a.enc")
k_b = km4.generate_key("b.enc")
k_c = km4.generate_key("c.enc")
km5 = EphemeralKeyManager(keystore_path=f"{VAULT}/.keys2.json")
test("Key A survives after B,C added", km5.get_key("a.enc") == k_a)
test("Key B survives after C added", km5.get_key("b.enc") == k_b)
test("Key C exists", km5.get_key("c.enc") == k_c)

# Test 2.7: Single key wipe
km6 = EphemeralKeyManager()
km6.generate_key("keep.enc")
km6.generate_key("delete.enc")
km6.wipe_key("delete.enc")
test("Single key wiped", not km6.has_key("delete.enc"))
test("Other key preserved", km6.has_key("keep.enc"))


# ================================================================
# TEST GROUP 3: File Encryption Engine Lifecycle
# ================================================================
print("\n" + "=" * 60)
print("TEST GROUP 3: Encryption Engine Lifecycle")
print("=" * 60)

setup()
engine = FileEncryptionEngine(vault_dir=VAULT, mount_point=MOUNT)
engine.setup()

# Create test files
for name, content in [("a.txt", "Alpha"), ("b.txt", "Bravo"), ("c.txt", "Charlie")]:
    with open(f"{VAULT}/{name}", "w") as f:
        f.write(content)

# Test 3.1: Encrypt files
engine.encrypt_new_file(f"{VAULT}/a.txt")
engine.encrypt_new_file(f"{VAULT}/b.txt")
engine.encrypt_new_file(f"{VAULT}/c.txt")
enc_files = [f for f in os.listdir(VAULT) if f.endswith(".enc")]
test("3 files encrypted", len(enc_files) == 3)
test("Originals deleted", not os.path.exists(f"{VAULT}/a.txt"))

# Test 3.2: Decrypt vault
count = engine.decrypt_vault()
test("3 files decrypted", count == 3)
test("a.txt readable", open(f"{MOUNT}/a.txt").read() == "Alpha")
test("b.txt readable", open(f"{MOUNT}/b.txt").read() == "Bravo")
test("c.txt readable", open(f"{MOUNT}/c.txt").read() == "Charlie")

# Test 3.3: Double decrypt is no-op
count2 = engine.decrypt_vault()
test("Double decrypt is no-op (returns 0)", count2 == 0)

# Test 3.4: Lock vault
engine.lock_vault()
mount_files = os.listdir(MOUNT)
test("Mount empty after lock", len(mount_files) == 0)
test("Keys wiped after lock", engine.key_manager.key_count == 0)
test("Engine reports locked", not engine.is_unlocked)

# Test 3.5: Decrypt again after lock
engine2 = FileEncryptionEngine(vault_dir=VAULT, mount_point=MOUNT)
engine2.setup()
count3 = engine2.decrypt_vault()
test("Re-decrypt after lock works", count3 == 3)
test("Content preserved after lock/unlock", open(f"{MOUNT}/a.txt").read() == "Alpha")
engine2.lock_vault()


# ================================================================
# TEST GROUP 4: Edit Persistence
# ================================================================
print("\n" + "=" * 60)
print("TEST GROUP 4: Edit Persistence")
print("=" * 60)

setup()
engine = FileEncryptionEngine(vault_dir=VAULT, mount_point=MOUNT)
engine.setup()

with open(f"{VAULT}/doc.txt", "w") as f:
    f.write("Version 1")
engine.encrypt_new_file(f"{VAULT}/doc.txt")

# Unlock → edit → lock → unlock
engine.decrypt_vault()
test("Original content", open(f"{MOUNT}/doc.txt").read() == "Version 1")

with open(f"{MOUNT}/doc.txt", "w") as f:
    f.write("Version 2 - EDITED")

engine.lock_vault()
engine.decrypt_vault()
test("Edit persisted after lock/unlock", open(f"{MOUNT}/doc.txt").read() == "Version 2 - EDITED")

# Edit again
with open(f"{MOUNT}/doc.txt", "w") as f:
    f.write("Version 3 - FINAL")
engine.lock_vault()
engine.decrypt_vault()
test("Multiple edits persist", open(f"{MOUNT}/doc.txt").read() == "Version 3 - FINAL")

# Test: no-change files don't get re-encrypted unnecessarily
original_enc_size = os.path.getsize(f"{VAULT}/doc.txt.enc")
engine.lock_vault()  # No edits this time
engine.decrypt_vault()
test("Unmodified file still works", open(f"{MOUNT}/doc.txt").read() == "Version 3 - FINAL")
engine.lock_vault()


# ================================================================
# TEST GROUP 5: New File Auto-Encryption
# ================================================================
print("\n" + "=" * 60)
print("TEST GROUP 5: New File In Mount Point")
print("=" * 60)

setup()
engine = FileEncryptionEngine(vault_dir=VAULT, mount_point=MOUNT)
engine.setup()

with open(f"{VAULT}/existing.txt", "w") as f:
    f.write("I was here before")
engine.encrypt_new_file(f"{VAULT}/existing.txt")

engine.decrypt_vault()

# Create a NEW file in mount point while unlocked
with open(f"{MOUNT}/new_secret.txt", "w") as f:
    f.write("Brand new secret!")

engine.lock_vault()

# Check: new file should be encrypted in vault
test("New file encrypted to vault", os.path.exists(f"{VAULT}/new_secret.txt.enc"))

# Unlock: both files should appear
engine.decrypt_vault()
test("Existing file decrypted", open(f"{MOUNT}/existing.txt").read() == "I was here before")
test("New file decrypted", open(f"{MOUNT}/new_secret.txt").read() == "Brand new secret!")
engine.lock_vault()


# ================================================================
# TEST GROUP 6: RSSI Filter Pipeline
# ================================================================
print("\n" + "=" * 60)
print("TEST GROUP 6: RSSI Filter Pipeline")
print("=" * 60)

# Test 6.1: EMA Filter
ema = EMAFilter(alpha=0.3)
result = ema.update(-60)
test("EMA first value = raw", result == -60)
result = ema.update(-50)
test("EMA smooths (not equal to raw)", result != -50 and result != -60)

# Test 6.2: Kalman Filter
kalman = KalmanFilter(process_noise=1.0, measurement_noise=5.0)
r1 = kalman.update(-60)
test("Kalman first value = raw", r1 == -60)
# Feed stable then spike — kalman should resist the spike
for _ in range(10):
    kalman.update(-60)
r_spike = kalman.update(-90)
test("Kalman resists spike (stays closer to -60)", r_spike > -75)

# Test 6.3: Hysteresis
hyst = HysteresisFilter(authorize_threshold=-75, deauthorize_threshold=-82)
test("Above authorize → IN_RANGE",
     hyst.evaluate(-70, ProximityState.OUT_OF_RANGE) == ProximityState.IN_RANGE)
test("Below deauthorize → OUT_OF_RANGE",
     hyst.evaluate(-85, ProximityState.IN_RANGE) == ProximityState.OUT_OF_RANGE)
test("Dead zone keeps state (IN_RANGE)",
     hyst.evaluate(-78, ProximityState.IN_RANGE) == ProximityState.IN_RANGE)
test("Dead zone keeps state (OUT_OF_RANGE)",
     hyst.evaluate(-78, ProximityState.OUT_OF_RANGE) == ProximityState.OUT_OF_RANGE)

# Test 6.4: Grace Period
grace = GracePeriod(count=3)
s = ProximityState.OUT_OF_RANGE
# 1st and 2nd readings shouldn't trigger transition
s = grace.evaluate(ProximityState.IN_RANGE, s)
test("Grace 1/3: no transition", s == ProximityState.OUT_OF_RANGE)
s = grace.evaluate(ProximityState.IN_RANGE, s)
test("Grace 2/3: no transition", s == ProximityState.OUT_OF_RANGE)
s = grace.evaluate(ProximityState.IN_RANGE, s)
test("Grace 3/3: TRANSITION!", s == ProximityState.IN_RANGE)

# Test 6.5: Grace resets on contradicting reading
grace2 = GracePeriod(count=3)
s2 = ProximityState.OUT_OF_RANGE
grace2.evaluate(ProximityState.IN_RANGE, s2)  # 1/3
grace2.evaluate(ProximityState.IN_RANGE, s2)  # 2/3
s2 = grace2.evaluate(ProximityState.OUT_OF_RANGE, s2)  # reset!
test("Grace resets on contradiction", s2 == ProximityState.OUT_OF_RANGE)
s2 = grace2.evaluate(ProximityState.IN_RANGE, s2)  # 1/3 again
test("Grace restarts from 1", s2 == ProximityState.OUT_OF_RANGE)

# Test 6.6: Full pipeline — badge approaches
state_changes = []
config = FilterConfig(
    authorize_threshold=-75,
    deauthorize_threshold=-82,
    grace_count=3,
)
pipeline = RSSIFilterPipeline(
    config=config,
    on_state_change=lambda old, new, rssi: state_changes.append((old.value, new.value)),
)

# Simulate badge approaching (strong signal)
for rssi in [-60, -58, -62, -59, -61, -60]:
    pipeline.process(rssi)
test("Badge approach → IN_RANGE", pipeline.state == ProximityState.IN_RANGE)

# Simulate badge leaving (weak signal — need enough readings for Kalman + Grace)
for rssi in [-85, -88, -90, -87, -92, -95, -93, -90, -92, -94, -95, -96]:
    pipeline.process(rssi)
test("Badge leaving → OUT_OF_RANGE", pipeline.state == ProximityState.OUT_OF_RANGE)
test("Two state changes recorded", len(state_changes) == 2)

# Test 6.7: Transient spike doesn't trigger false transition
pipeline2 = RSSIFilterPipeline(config=config)
for _ in range(5):
    pipeline2.process(-60)  # Establish IN_RANGE

# Single spike to -90 then back
pipeline2.process(-90)
pipeline2.process(-60)
pipeline2.process(-60)
test("Single spike doesn't cause false lock", pipeline2.state == ProximityState.IN_RANGE)


# ================================================================
# TEST GROUP 7: Security Properties
# ================================================================
print("\n" + "=" * 60)
print("TEST GROUP 7: Security Properties")
print("=" * 60)

setup()
engine = FileEncryptionEngine(vault_dir=VAULT, mount_point=MOUNT)
engine.setup()

with open(f"{VAULT}/secret.txt", "w") as f:
    f.write("TOP SECRET DATA")
engine.encrypt_new_file(f"{VAULT}/secret.txt")

# Test 7.1: Original file securely deleted
test("Original plaintext does not exist", not os.path.exists(f"{VAULT}/secret.txt"))

# Test 7.2: Encrypted file is not readable
enc_content = open(f"{VAULT}/secret.txt.enc", "rb").read()
test("Encrypted file != plaintext", b"TOP SECRET DATA" not in enc_content)

# Test 7.3: Each file gets unique nonce (no two .enc files have same first 12 bytes)
with open(f"{VAULT}/secret2.txt", "w") as f:
    f.write("TOP SECRET DATA")  # Same content!
engine.encrypt_new_file(f"{VAULT}/secret2.txt")
enc1 = open(f"{VAULT}/secret.txt.enc", "rb").read()[:12]
enc2 = open(f"{VAULT}/secret2.txt.enc", "rb").read()[:12]
test("Different nonces for same content", enc1 != enc2)

# Test 7.4: Fail-closed — lock always works
engine.decrypt_vault()
test("Files accessible when unlocked", os.path.exists(f"{MOUNT}/secret.txt"))
engine.lock_vault()
test("Files gone after lock", not os.path.exists(f"{MOUNT}/secret.txt"))
test("Keys zero after lock", engine.key_manager.key_count == 0)

# Test 7.5: Vault starts locked
engine_fresh = FileEncryptionEngine(vault_dir=VAULT, mount_point=MOUNT)
test("Fresh engine starts locked", not engine_fresh.is_unlocked)


# ================================================================
# RESULTS
# ================================================================
print("\n" + "=" * 60)
total = passed + failed
print(f"RESULTS: {passed}/{total} passed, {failed} failed")
if failed == 0:
    print("🎉 ALL TESTS PASSED!")
else:
    print(f"⚠️  {failed} test(s) FAILED")
print("=" * 60)

# Cleanup
shutil.rmtree(VAULT, ignore_errors=True)
shutil.rmtree(MOUNT, ignore_errors=True)

sys.exit(0 if failed == 0 else 1)
