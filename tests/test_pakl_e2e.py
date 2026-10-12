#!/usr/bin/env python3
"""
End-to-end test of the PAKL server protocol (no hardware needed).

Runs the FastAPI app in-process against TEMPORARY copies of the tables
(they live on a single private connection, shadow the real tables for that
connection only, and vanish when it closes) and Redis DB 15, with a simulated badge
(rolling tokens) and a simulated agent (signed requests built by the real
agent ServerKeyManager). The production tables are never touched.

Run from the project root:
  python tests/test_pakl_e2e.py
"""

import asyncio
import base64
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

os.environ["SECURITY_MODE"] = "pakl"
os.environ["MASTER_KEY"] = "11" * 32
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ["LEASE_TTL_S"] = "2.0"
os.environ["DEBUG"] = "false"

import httpx  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.schema import CreateIndex, CreateTable  # noqa: E402

from server.config import get_settings  # noqa: E402
from server.db import database  # noqa: E402
from server.db.models import (  # noqa: E402
    AccessPolicy, Badge, BadgeStatus, Base, Device, FileKey, User, UserRole,
)
from server.main import app  # noqa: E402
from server.security import pakl  # noqa: E402
from agent.key_manager.server_key_manager import ServerKeyManager  # noqa: E402

settings = get_settings()
BADGE_KEY = os.urandom(32)
DEVICE_KEY = os.urandom(32)
ANCHOR_KEY = os.urandom(32)
MAC = "aa:bb:cc:dd:ee:01"
HOST = "e2e-host"

results = []


def check(name, cond, info=""):
    results.append(cond)
    print(f"  {'PASS' if cond else 'FAIL'}  {name} {info}")


class Badge_:
    """Simulated badge: counter = epoch<<20 | seconds since boot."""
    def __init__(self, epoch=5):
        self.epoch, self.boot = epoch, time.time()

    def counter(self, at=None):
        return (self.epoch << 20) + int((at or time.time()) - self.boot)

    def token(self, at=None, badge_id=1):
        return pakl.make_token(BADGE_KEY, badge_id, self.counter(at))


def signed_request(path: str, payload: dict, token_provider=None):
    """Build the exact request the real agent sends (headers + body)."""
    km = ServerKeyManager("http://test", MAC, HOST, security_mode="pakl", device_key=DEVICE_KEY)
    km.token_provider = token_provider
    captured = {}

    def fake_post(url, content=None, headers=None):
        captured.update(url=url, content=content, headers=headers)
        return httpx.Response(200, json={})

    km._client.post = fake_post
    km._post(path, payload)
    return captured["content"], captured["headers"]


async def main():
    # One pooled connection: temp tables exist only on it
    engine = create_async_engine(settings.DATABASE_URL, pool_size=1, max_overflow=0)
    async with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            ddl = str(CreateTable(table).compile(dialect=engine.dialect))
            await conn.execute(text(ddl.replace("CREATE TABLE", "CREATE TEMP TABLE", 1)))
            for index in table.indexes:
                await conn.execute(text(str(CreateIndex(index).compile(dialect=engine.dialect))))
        n = (await conn.execute(text(
            "select count(*) from pg_class where relpersistence='t' and relname='badges'"))).scalar()
        assert n == 1, "temp tables not created"

    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def test_db():
        async with Session() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    app.dependency_overrides[database.get_db] = test_db

    async with Session() as s:
        admin = User(name="a", email="a@x", password_hash="x", role=UserRole.ADMIN)
        badge = Badge(mac_address=MAC, badge_name="b")
        device = Device(hostname=HOST, mac_address="00:00:00:00:00:01")
        s.add_all([admin, badge, device])
        await s.flush()
        # secrets stored wrapped under MASTER_KEY, bound to the row id
        mk = bytes.fromhex(os.environ["MASTER_KEY"])
        badge.hmac_secret = pakl.wrap_secret(mk, BADGE_KEY, f"badge|{badge.id}")
        device.api_secret = pakl.wrap_secret(mk, DEVICE_KEY, f"device|{device.id}")
        device.anchor_secret = pakl.wrap_secret(mk, ANCHOR_KEY, f"anchor|{device.id}")
        s.add(AccessPolicy(badge_id=badge.id, device_id=device.id, granted_by=admin.id))
        await s.commit()
        badge_id = badge.id

    from server.cache import get_redis
    await (await get_redis()).flushdb()

    b = Badge_()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:

        async def post(path, payload, token_provider=None, signed=True):
            if not signed:
                return await client.post(path, json=payload)
            body, headers = signed_request(path, payload, token_provider)
            return await client.post(path, content=body, headers=headers)

        req = {"badge_mac": MAC, "device_hostname": HOST}
        fek = os.urandom(32)

        print("\n[1] Key storage")
        r = await post("/api/keys/store", {**req, "file_path": "doc.pdf.enc",
                                           "encrypted_fek": base64.b64encode(fek).decode()})
        check("signed store accepted", r.status_code == 200, r.text[:80])
        async with Session() as s:
            stored = (await s.execute(text("select encrypted_fek from file_keys"))).scalar()
        check("FEK wrapped at rest", pakl.is_wrapped(bytes(stored)))

        print("\n[2] Network attacker (no device key)")
        r = await post("/api/keys/request", req, signed=False)
        check("unsigned key request rejected", r.status_code == 401, str(r.status_code))
        body, headers = signed_request("/api/keys/request", req)
        headers = {**headers, "X-SPAZE-Signature": "0" * 64}
        r = await client.post("/api/keys/request", content=body, headers=headers)
        check("forged signature rejected", r.status_code == 401)

        print("\n[3] Compromised device key, no badge present")
        r = await post("/api/keys/request", req)  # no token
        check("request without presence token denied", r.json()["authorized"] is False, r.json()["message"])
        forged = pakl.make_token(os.urandom(32), badge_id, b.counter())
        r = await post("/api/keys/request", {**req, "presence_token": forged})
        check("token with wrong key denied", r.json()["authorized"] is False, r.json()["message"])

        print("\n[4] Legitimate unlock")
        tok = b.token(badge_id=badge_id)
        t0 = time.perf_counter()
        r = await post("/api/keys/request", {**req, "presence_token": tok})
        data = r.json()
        check("keys released with fresh token", data["authorized"] is True, data["message"])
        check("FEK returned unwrapped and correct",
              base64.b64decode(data["keys"]["doc.pdf.enc"]) == fek)
        check("lease issued", bool(data.get("lease_id")), f"ttl={data.get('lease_ttl')}")
        print(f"      in-process key request: {(time.perf_counter() - t0) * 1000:.1f} ms")
        lease = data["lease_id"]

        print("\n[5] Replay of a captured signed request")
        body, headers = signed_request("/api/keys/request", {**req, "presence_token": tok})
        r1 = await client.post("/api/keys/request", content=body, headers=headers)
        r2 = await client.post("/api/keys/request", content=body, headers=headers)
        check("first copy accepted, second rejected", r1.status_code == 200 and r2.status_code == 401,
              f"{r1.status_code}/{r2.status_code}")

        print("\n[6] Lease renewal")
        b.boot -= 3  # badge time advances 3 s
        r = await post("/api/keys/renew", {**req, "lease_id": lease,
                                           "presence_token": b.token(badge_id=badge_id)})
        check("renewal with fresh token", r.json()["renewed"] is True, r.json()["message"])
        old = pakl.make_token(BADGE_KEY, badge_id, b.counter() - 30)
        r = await post("/api/keys/renew", {**req, "lease_id": lease, "presence_token": old})
        check("renewal with old (replayed) token denied", r.json()["renewed"] is False, r.json()["message"])
        r = await post("/api/keys/renew", {**req, "lease_id": lease,
                                           "presence_token": b.token(badge_id=badge_id)})
        check("denied lease cannot be revived", r.json()["renewed"] is False, r.json()["message"])

        print("\n[7] Lease expiry")
        b.boot -= 1
        r = await post("/api/keys/request", {**req, "presence_token": b.token(badge_id=badge_id)})
        lease = r.json()["lease_id"]
        await asyncio.sleep(settings.LEASE_TTL_S + 0.5)
        b.boot -= 3
        r = await post("/api/keys/renew", {**req, "lease_id": lease,
                                           "presence_token": b.token(badge_id=badge_id)})
        check("expired lease not renewable", r.json()["renewed"] is False, r.json()["message"])

        print("\n[8] Revocation mid-session")
        b.boot -= 1
        r = await post("/api/keys/request", {**req, "presence_token": b.token(badge_id=badge_id)})
        lease = r.json()["lease_id"]
        async with Session() as s:
            await s.execute(text("update badges set status='REVOKED'"))
            await s.commit()
        b.boot -= 1
        r = await post("/api/keys/renew", {**req, "lease_id": lease,
                                           "presence_token": b.token(badge_id=badge_id)})
        check("renewal denied after revocation", r.json()["renewed"] is False, r.json()["message"])
        async with Session() as s:
            await s.execute(text("update badges set status='ACTIVE'"))
            await s.commit()

        print("\n[9] Challenge-response with anchor-measured RTT (PAKL-CR)")
        settings.CR_REQUIRED = True
        settings.CR_MAX_RTT_US = 30000

        def answer(nonce_hex, rtt_us, key=BADGE_KEY, akey=ANCHOR_KEY):
            n = bytes.fromhex(nonce_hex)
            resp = pakl.cr_response(key, n)
            return {"nonce": nonce_hex, "resp": resp.hex(), "rtt_us": rtt_us,
                    "att": pakl.cr_attestation(akey, n, resp, rtt_us).hex()}

        async def fresh_challenge():
            r = await post("/api/keys/challenge", req)
            return r.json()["challenge"]

        b.boot -= 2
        r = await post("/api/keys/request", {**req, "presence_token": b.token(badge_id=badge_id)})
        check("CR on: request without answer denied", r.json()["authorized"] is False, r.json()["message"])
        c1 = await fresh_challenge()
        b.boot -= 1
        r = await post("/api/keys/request", {**req, "presence_token": b.token(badge_id=badge_id),
                                             "cr": answer(c1, 12000)})
        d = r.json()
        check("CR on: legitimate answer (12 ms) releases keys", d["authorized"] is True and bool(d.get("challenge")),
              d["message"])
        lease, nxt = d["lease_id"], d["challenge"]
        b.boot -= 3
        r = await post("/api/keys/renew", {**req, "lease_id": lease, "presence_token": b.token(badge_id=badge_id),
                                           "cr": answer(nxt, 11000)})
        check("CR on: renewal with fresh answer", r.json()["renewed"] is True, r.json()["message"])
        nxt2 = r.json()["challenge"]
        b.boot -= 3
        r = await post("/api/keys/renew", {**req, "lease_id": lease, "presence_token": b.token(badge_id=badge_id),
                                           "cr": answer(nxt2, 35000)})
        j = r.json()
        check("CR on: one slow answer gets a retry, lease not extended",
              j["renewed"] is False and j.get("retry") is True and bool(j.get("challenge")), j["message"])
        b.boot -= 1
        r = await post("/api/keys/renew", {**req, "lease_id": lease, "presence_token": b.token(badge_id=badge_id),
                                           "cr": answer(j["challenge"], 12000)})
        check("CR on: fast retry renews the lease", r.json()["renewed"] is True, r.json()["message"])
        nxt2 = r.json()["challenge"]
        b.boot -= 3
        r = await post("/api/keys/renew", {**req, "lease_id": lease, "presence_token": b.token(badge_id=badge_id),
                                           "cr": answer(nxt2, 45000)})
        j = r.json()
        check("CR on: retry allowed again after a successful renewal", j.get("retry") is True, j["message"])
        b.boot -= 1
        r = await post("/api/keys/renew", {**req, "lease_id": lease, "presence_token": b.token(badge_id=badge_id),
                                           "cr": answer(j["challenge"], 45000)})
        check("CR on: relayed answer (45 ms > bound) denied after its one retry",
              r.json()["renewed"] is False and not r.json().get("retry"), r.json()["message"])
        c2 = await fresh_challenge()
        tampered = answer(c2, 45000)
        tampered["rtt_us"] = 9000      # agent lowers the RTT: attestation breaks
        b.boot -= 1
        r = await post("/api/keys/request", {**req, "presence_token": b.token(badge_id=badge_id), "cr": tampered})
        check("CR on: RTT edited by agent detected", r.json()["authorized"] is False, r.json()["message"])
        c3 = await fresh_challenge()
        ok_ans = answer(c3, 10000)
        b.boot -= 1
        r1 = await post("/api/keys/request", {**req, "presence_token": b.token(badge_id=badge_id), "cr": ok_ans})
        b.boot -= 1
        r2 = await post("/api/keys/request", {**req, "presence_token": b.token(badge_id=badge_id), "cr": ok_ans})
        check("CR on: answer cannot be reused", r1.json()["authorized"] is True and r2.json()["authorized"] is False,
              r2.json()["message"])
        b.boot -= 3
        r = await post("/api/keys/renew", {**req, "lease_id": r1.json()["lease_id"],
                                           "presence_token": b.token(badge_id=badge_id),
                                           "cr": answer(r1.json()["challenge"], 10000, key=os.urandom(32))})
        check("CR on: wrong answer at renewal denied without retry",
              r.json()["renewed"] is False and not r.json().get("retry"), r.json()["message"])
        c4 = await fresh_challenge()
        b.boot -= 1
        r = await post("/api/keys/request", {**req, "presence_token": b.token(badge_id=badge_id),
                                             "cr": answer(c4, 10000, key=os.urandom(32))})
        check("CR on: answer from wrong badge key denied", r.json()["authorized"] is False, r.json()["message"])
        settings.CR_REQUIRED = False

        print("\n[10] Baseline mode (original design) for comparison")
        settings.SECURITY_MODE = "baseline"
        r = await post("/api/keys/request", req, signed=False)
        leaked = r.json().get("keys", {})
        check("baseline: unsigned request WITHOUT badge gets keys (vulnerability)",
              r.json()["authorized"] is True and len(leaked) == 1)
        settings.SECURITY_MODE = "pakl"

    await (await get_redis()).flushdb()
    await engine.dispose()  # closes the connection; temp tables disappear

    print(f"\n{sum(results)}/{len(results)} checks passed")
    return all(results)


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
