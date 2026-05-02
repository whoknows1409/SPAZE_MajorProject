<p align="center">
  <img src="https://img.shields.io/badge/status-active-success?style=flat-square" alt="Status" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python" alt="Python" />
  <img src="https://img.shields.io/badge/react-19-61DAFB?style=flat-square&logo=react" alt="React" />
  <img src="https://img.shields.io/badge/fastapi-0.110+-009688?style=flat-square&logo=fastapi" alt="FastAPI" />
  <img src="https://img.shields.io/badge/license-academic-lightgrey?style=flat-square" alt="License" />
</p>

# SPAZE 🔐

**Spatially Constrained Zero-Trust File Encryption System**

> A proximity-based data loss prevention (DLP) architecture that binds digital file access rights to verifiable, continuous physical presence — using BLE proximity badges, AES-256-GCM encryption, and an ephemeral key management protocol.

---

## The Problem

Insider threats account for **60% of data breaches** in enterprise environments. Traditional access control (passwords, VPNs) verifies identity *once* and then trusts the session indefinitely. An authenticated user can:

- Copy sensitive files to a USB drive
- Email documents from an unlocked workstation
- Access data after physically leaving the secure area

**SPAZE eliminates this gap** by enforcing *continuous physical authorization* — files are only readable when the authorized badge is physically within 2 meters of the workstation, and are instantly re-encrypted when the user walks away.

---

## How It Works

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                    SPAZE Architecture                    │
                    └─────────────────────────────────────────────────────────┘

  ┌──────────────┐        BLE 5.0         ┌──────────────────┐      TLS 1.3      ┌──────────────┐
  │              │   advertisement (2m)    │                  │    key request     │              │
  │  BLE Badge   │ ─────────────────────► │  SPAZE Agent     │ ────────────────► │  SPAZE Server │
  │  (ESP32)     │   RSSI monitoring      │  (Python Daemon) │   RBAC + policy   │  (FastAPI)   │
  │              │                         │                  │ ◄──────────────── │              │
  └──────────────┘                         └────────┬─────────┘   ephemeral FEKs  └──────┬───────┘
                                                     │                                    │
                                              ┌──────▼───────┐                    ┌───────▼──────┐
                                              │  tmpfs Vault  │                    │  PostgreSQL  │
                                              │  (RAM-only)   │                    │  + Redis     │
                                              │  AES-256-GCM  │                    │              │
                                              └──────────────┘                    └──────────────┘
```

### Flow

1. **Badge enters range** → Agent detects authorized BLE badge within ~2m via RSSI threshold
2. **Policy check** → Server validates badge MAC, device hostname, and RBAC policy
3. **Key delivery** → Server sends per-file AES-256-GCM encryption keys (FEKs) over TLS
4. **Vault unlock** → Files decrypted into RAM-backed `tmpfs` mount (never touches disk)
5. **Continuous monitoring** → Agent polls RSSI every second; badge must stay in range
6. **Badge leaves** → All processes killed, files synced back, re-encrypted, keys wiped from memory
7. **Mount locked** → `tmpfs` unmounted, directory permissions set to `chmod 000`

---

## Features

### Core Security
- **AES-256-GCM** file encryption at rest with per-file unique keys
- **Ephemeral keys** — never stored locally, fetched from server per session
- **RAM-only decryption** via `tmpfs` — plaintext never touches persistent storage
- **Fail-closed design** — any failure (network, badge, crash) locks the vault
- **Process protection** — applications holding file handles (LibreOffice, etc.) force-killed before lock
- **Shadow directory mitigation** — `chmod 000` on mount point when vault is locked
- **Rogue file detection** — files created while vault is locked are automatically encrypted on next unlock

### Access Control
- **BLE proximity gating** — continuous RSSI monitoring, not just one-time auth
- **Badge MAC filtering** — only the configured badge triggers unlock
- **RBAC hierarchy** — Admin → Manager → Employee role enforcement
- **Access policies** — granular badge-to-device binding with expiration support
- **Badge lifecycle** — active, revoked, and lost status management

### Admin Dashboard
- **7 management pages** — Dashboard, Badges, Users, Devices, Policies, Audit Logs
- **Real-time audit logs** — color-coded event timeline with auto-refresh
- **Dark/Light theme** — Vercel-inspired professional UI with theme persistence
- **JWT authentication** — role-gated admin access

### Infrastructure
- **Redis caching** — 5-minute TTL key cache with instant invalidation on changes
- **PostgreSQL** — relational data with async SQLAlchemy
- **Comprehensive audit trail** — every vault lock/unlock, key request, and policy change logged

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **IoT Badge** | ESP32-WROOM-32 | BLE 5.0 advertisement |
| **Agent** | Python 3.11+ | BLE scanning, file encryption, vault management |
| **Server** | FastAPI + Uvicorn | REST API, RBAC, key management |
| **Database** | PostgreSQL 15 | Users, badges, policies, audit logs |
| **Cache** | Redis 7 | FEK caching with TTL |
| **Dashboard** | React 19 + Vite | Admin management UI |
| **Crypto** | `cryptography` lib | AES-256-GCM encryption/decryption |
| **Auth** | JWT (PyJWT) | Stateless token-based authentication |

---

## Project Structure

```
SPAZE/
├── agent/                          # Workstation daemon
│   ├── main.py                     # Entry point — serial listener, proximity engine
│   ├── ble_scanner/                # BLE RSSI reader (serial port)
│   ├── file_monitor/
│   │   ├── engine.py               # Lock/unlock orchestrator
│   │   ├── vault.py                # tmpfs mount, process killing, chmod
│   │   ├── crypto.py               # AES-256-GCM encrypt/decrypt
│   │   └── watcher.py              # Filesystem event watcher
│   └── key_manager/                # Server-side key fetching
│
├── server/                         # Backend API
│   ├── main.py                     # FastAPI app, CORS, middleware
│   ├── config.py                   # Environment settings
│   ├── cache.py                    # Redis key cache layer
│   ├── api/
│   │   ├── auth.py                 # Login, registration, JWT
│   │   ├── keys.py                 # FEK store/retrieve/delete
│   │   ├── badges.py               # Badge CRUD + status
│   │   ├── users.py                # User management
│   │   ├── devices.py              # Device registration
│   │   ├── policies.py             # Access policy CRUD
│   │   └── audit.py                # Audit log query + stats
│   ├── auth/                       # JWT helpers, RBAC dependencies
│   ├── crypto/                     # Server-side key generation
│   ├── db/                         # SQLAlchemy models, migrations
│   └── rbac/                       # Role-based access control
│
├── dashboard/                      # React admin frontend
│   └── src/
│       ├── api/client.js           # Axios + JWT interceptor
│       ├── context/
│       │   ├── AuthContext.jsx      # Login/logout state
│       │   └── ThemeContext.jsx     # Dark/light theme
│       ├── components/             # Layout, Sidebar, Modal, StatCard, StatusPill
│       └── pages/                  # Login, Dashboard, Badges, Users, Devices, Policies, AuditLogs
│
├── firmware/                       # ESP32 firmware
│   ├── badge/                      # BLE advertiser
│   └── anchor/                     # Door/zone anchors
│
├── scripts/                        # Utility scripts
├── tests/                          # Test suite
├── docs/                           # Research documentation
└── config/                         # Environment configs
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 15+
- Redis 7+
- ESP32 development board (for badge)

### 1. Database Setup

```bash
# Create PostgreSQL database
sudo -u postgres psql -c "CREATE USER spaze_user WITH PASSWORD 'spaze_pass';"
sudo -u postgres psql -c "CREATE DATABASE spaze OWNER spaze_user;"
```

### 2. Server

```bash
# Create virtual environment
python -m venv venv && source venv/bin/activate

# Install dependencies
pip install -r server/requirements.txt

# Initialize database tables
python -c "from server.db.database import init_db; import asyncio; asyncio.run(init_db())"

# Seed admin user
python scripts/seed_admin.py

# Start server
uvicorn server.main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Dashboard

```bash
cd dashboard
npm install
npm run dev
# → http://localhost:5173
```

### 4. Agent

```bash
# Ensure badge is powered on and advertising

python -m agent.main \
  --port /dev/ttyACM0 \
  --server http://localhost:8000 \
  --badge-mac AA:BB:CC:DD:EE:FF
```

### 5. Redis

```bash
# Start Redis (if not running as service)
redis-server
```

---

## Environment Variables

Create a `.env` file in the project root:

```env
DATABASE_URL=postgresql+asyncpg://spaze_user:spaze_pass@localhost:5432/spaze
REDIS_URL=redis://localhost:6379/0
JWT_SECRET=your-secret-key-change-in-production
```

---

## Security Model

```
┌──────────────────────────────────────────────────────────────┐
│                     SPAZE Security Layers                     │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  Layer 1: Physical Proximity (BLE RSSI)                       │
│  ├─ Badge must be within ~2m continuously                     │
│  └─ RSSI threshold enforced every 1 second                   │
│                                                                │
│  Layer 2: Identity Verification (Badge MAC)                   │
│  ├─ Only configured badge MAC triggers proximity pipeline     │
│  └─ Unknown badges silently ignored                           │
│                                                                │
│  Layer 3: Authorization (RBAC + Policies)                     │
│  ├─ Server validates badge→device policy before key delivery  │
│  └─ Admin/Manager/Employee role hierarchy                     │
│                                                                │
│  Layer 4: Encryption at Rest (AES-256-GCM)                    │
│  ├─ Per-file unique encryption keys (FEKs)                    │
│  └─ 256-bit keys with authenticated encryption                │
│                                                                │
│  Layer 5: Ephemeral Decryption (tmpfs)                        │
│  ├─ Plaintext exists only in RAM-backed filesystem            │
│  ├─ Keys wiped from memory on vault lock                      │
│  └─ Mount point locked (chmod 000) when vault is sealed       │
│                                                                │
│  Layer 6: Audit Trail                                          │
│  ├─ Every key request, lock/unlock, and denial logged         │
│  └─ Tamper-evident audit log in PostgreSQL                    │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Badge cloning | MAC filtering + server-side policy check |
| USB exfiltration | Files only exist in RAM while badge is in range |
| Unattended workstation | Auto-lock within seconds of badge departure |
| Shadow directory attack | `chmod 000` + rogue file wipe on re-unlock |
| Process holding files | Force-kill via `lsof`/`fuser` before sync |
| Stale key cache | Redis invalidation on every key store/delete |
| Network failure | Fail-closed — vault stays locked without server |

---

## API Documentation

With the server running, visit:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints

| Method | Endpoint | Description |
|--------|---------|-------------|
| `POST` | `/api/auth/login` | JWT authentication |
| `POST` | `/api/auth/register` | User registration |
| `GET` | `/api/keys/request` | Fetch FEKs for a badge+device |
| `POST` | `/api/keys/store` | Store a new FEK |
| `GET/POST` | `/api/admin/badges/` | List/create badges |
| `PATCH` | `/api/admin/badges/{id}` | Update badge status |
| `GET/POST` | `/api/admin/users/` | List/create users |
| `GET/POST` | `/api/admin/devices/` | List/register devices |
| `GET/POST` | `/api/admin/policies/` | List/create policies |
| `DELETE` | `/api/admin/policies/{id}` | Revoke a policy |
| `GET` | `/api/audit/logs` | Query audit logs |
| `GET` | `/api/audit/stats` | System-wide statistics |

---

## Dashboard

The admin dashboard provides a web-based management interface:

| Page | Functionality |
|------|--------------|
| **Dashboard** | System stats, recent activity feed, service health |
| **Badges** | Register, search, activate/revoke BLE badges |
| **Users** | Create users with role assignment and badge binding |
| **Devices** | Register workstations with location metadata |
| **Policies** | Grant/revoke badge→device access with filters |
| **Audit Logs** | Filterable event timeline with 5s auto-refresh |

**Theme**: Dark/Light mode toggle with localStorage persistence.

---

## Project Info

- **Type**: College Major Project (2026)
- **Domain**: IoT Security, Zero-Trust Architecture, Data Loss Prevention
- **Architecture**: Microservices (Agent + Server + Dashboard)

## License

This project is part of academic research. All rights reserved.
