"""Minimal admin API client used by the security experiments."""

import os

import httpx


class Admin:
    def __init__(self, server, ca_cert=None):
        self.server = server.rstrip("/")
        self.c = httpx.Client(timeout=10, verify=ca_cert if ca_cert else True)
        email = os.environ.get("SPAZE_ADMIN_EMAIL")
        password = os.environ.get("SPAZE_ADMIN_PASSWORD")
        if not (email and password):
            raise SystemExit("Set SPAZE_ADMIN_EMAIL and SPAZE_ADMIN_PASSWORD first")
        r = self.c.post(f"{self.server}/api/auth/login", json={"email": email, "password": password})
        r.raise_for_status()
        self.c.headers["Authorization"] = f"Bearer {r.json()['access_token']}"

    def set_badge_status(self, badge_id, status):
        r = self.c.patch(f"{self.server}/api/admin/badges/{badge_id}", json={"status": status})
        r.raise_for_status()
        return r.json()
