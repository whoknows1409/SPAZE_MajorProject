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
- Take screenshots, print files, or upload via browsers

**SPAZE eliminates this gap** by enforcing *continuous physical authorization* — files are only readable when the authorized badge is physically within 2 meters of the workstation, and are instantly re-encrypted when the user walks away. A full DLP guard suite prevents all exfiltration channels while the vault is active.

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
                                              └──────┬────────┘                    └──────────────┘
                                                     │
                                              ┌──────▼───────┐
                                              │  DLP Guards   │
                                              │  7 active     │
                                              │  modules      │
                                              └──────────────┘
```

### Flow

1. **Badge enters range** → Agent detects authorized BLE badge within ~2m via RSSI threshold
2. **Policy check** → Server validates badge MAC, device hostname, and RBAC policy
3. **Key delivery** → Server sends per-file AES-256-GCM encryption keys (FEKs) over TLS
4. **Vault unlock** → Files decrypted into RAM-backed `tmpfs` mount (never touches disk)
5. **DLP guards activate** → 7 guards start monitoring for data exfiltration attempts
6. **Continuous monitoring** → Agent polls RSSI every second; badge must stay in range
7. **Badge leaves** → DLP guards stopped, processes killed, files re-encrypted, keys wiped
8. **Session locked** → `tmpfs` unmounted, `chmod 000`, screen locked via `loginctl`

---

## Features

### Core Security
- **AES-256-GCM** file encryption at rest with per-file unique keys
- **Ephemeral keys** — never stored locally, fetched from server per session
- **RAM-only decryption** via `tmpfs` — plaintext never touches persistent storage
- **Fail-closed design** — any failure (network, badge, crash) locks the vault
- **Process protection** — applications holding file handles force-killed before lock
- **Shadow directory mitigation** — `chmod 000` on mount point when vault is locked
- **Rogue file detection** — files created while vault is locked are automatically encrypted on next unlock
- **Screen lock on departure** — `loginctl lock-session` when badge goes out of range

### Data Loss Prevention (DLP) Guards

All guards activate when the vault unlocks and terminate when it locks.

| # | Guard | Threat | Method |
|---|-------|--------|--------|
| 1 | **Clipboard Guard** | Copy-paste exfiltration | Polls every 0.5s, clears clipboard if vault data detected |
| 2 | **Screen Capture Guard** | Screenshot leakage | **Layer 1**: Kills screen capture processes (`gnome-screenshot`, OBS, Flameshot, etc.). **Layer 2**: Watches `~/Pictures/Screenshots/` for new files and deletes them instantly (catches GNOME Shell PrtSc) |
| 3 | **App Sandbox Guard** | Browser upload / email attachment | Uses `inotify` for instant kernel-level detection when vault files are opened. Kills unauthorized browsers/network apps before upload completes. Whitelisted apps (LibreOffice, VS Code, editors) are allowed |
| 4 | **Exfiltration Watcher** | File copy to external locations | Monitors system directories for copied plaintext vault files |
| 5 | **USB Storage Guard** | Data theft via USB drive | Detects removable/USB block devices (baseline vs. current comparison). Unmounts via `udisksctl`, powers off USB port. Re-unmounts if GNOME auto-remounts. Blocks devices already plugged in at vault unlock |
| 6 | **Print Guard** | Printing vault files | Scans `/proc` for print spooler processes with vault file descriptors. Kills `cupsd`/printer processes and cancels CUPS queue jobs |
| 7 | **Screen Lock** | Unattended workstation | `loginctl lock-session` when badge RSSI drops below threshold |

### Access Control
- **BLE proximity gating** — continuous RSSI monitoring, not just one-time auth
- **Badge MAC filtering** — only the configured badge triggers unlock
- **RBAC hierarchy** — Admin → Manager → Employee role enforcement
- **Access policies** — granular badge-to-device binding with expiration support
- **Badge lifecycle** — active, revoked, and lost status management

### Admin Dashboard
- **7 management pages** — Dashboard, Badges, Users, Devices, Policies, Audit Logs, Login
- **Real-time audit logs** — color-coded event timeline with auto-refresh and DLP event types (`usb_blocked`, `print_blocked`, `clipboard_cleared`, `screenshot_blocked`, `app_blocked`)
- **Dark/Light theme** — Vercel-inspired professional UI with theme persistence
- **JWT authentication** — role-gated admin access

### Infrastructure
- **Redis caching** — 5-minute TTL key cache with instant invalidation on changes
- **PostgreSQL** — relational data with async SQLAlchemy
- **Comprehensive audit trail** — every vault lock/unlock, key request, DLP block, and policy change logged
- **ESP32 auto-reset** — DTR toggle on serial connect eliminates manual EN button press

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------:|
| **IoT Badge** | ESP32-WROOM-32 | BLE 5.0 advertisement |
| **IoT Anchor** | ESP32-WROOM-32 | BLE scanner, USB-serial bridge to agent |
| **Agent** | Python 3.11+ | BLE scanning, file encryption, DLP guards, vault management |
| **Server** | FastAPI + Uvicorn | REST API, RBAC, key management |
| **Database** | PostgreSQL 15 | Users, badges, policies, audit logs |
| **Cache** | Redis 7 | FEK caching with TTL |
| **Dashboard** | React 19 + Vite | Admin management UI |
| **Crypto** | `cryptography` lib | AES-256-GCM encryption/decryption |
| **Auth** | JWT (PyJWT) | Stateless token-based authentication |
| **DLP** | `inotify` + `/proc` + `udisksctl` | Kernel-level file access monitoring & device control |

---

## Project Structure

```
SPAZE/
├── agent/                              # Workstation daemon
│   ├── main.py                         # Entry point — serial listener, proximity engine, screen lock
│   ├── ble_scanner/
│   │   └── serial_reader.py            # ESP32 USB-serial reader with DTR auto-reset
│   ├── file_monitor/
│   │   ├── engine.py                   # Lock/unlock orchestrator, DLP guard lifecycle
│   │   ├── vault.py                    # tmpfs mount, process killing, chmod
│   │   ├── crypto.py                   # AES-256-GCM encrypt/decrypt
│   │   ├── clipboard_guard.py          # Clipboard content clearing (0.5s poll)
│   │   ├── screen_guard.py             # Screenshot process killer + file watcher
│   │   ├── sandbox_guard.py            # inotify-based browser/app blocker
│   │   ├── exfil_watcher.py            # File copy detection
│   │   ├── usb_guard.py               # USB device unmount + power-off
│   │   └── print_guard.py             # Print spooler killer + CUPS queue cancel
│   └── key_manager/                    # Server-side key fetching
│
├── server/                             # Backend API
│   ├── main.py                         # FastAPI app, CORS, middleware
│   ├── config.py                       # Environment settings
│   ├── cache.py                        # Redis key cache layer
│   ├── api/
│   │   ├── auth.py                     # Login, registration, JWT
│   │   ├── keys.py                     # FEK store/retrieve/delete
│   │   ├── badges.py                   # Badge CRUD + status
│   │   ├── users.py                    # User management
│   │   ├── devices.py                  # Device registration
│   │   ├── policies.py                 # Access policy CRUD
│   │   └── audit.py                    # Audit log query + stats
│   ├── auth/                           # JWT helpers, RBAC dependencies
│   ├── crypto/                         # Server-side key generation
│   ├── db/                             # SQLAlchemy models, migrations
│   └── rbac/                           # Role-based access control
│
├── dashboard/                          # React admin frontend
│   └── src/
│       ├── api/client.js               # Axios + JWT interceptor
│       ├── context/
│       │   ├── AuthContext.jsx          # Login/logout state
│       │   └── ThemeContext.jsx         # Dark/light theme
│       ├── components/                 # Layout, Sidebar, Modal, StatCard, StatusPill
│       └── pages/
│           ├── Login.jsx               # JWT authentication page
│           ├── Dashboard.jsx           # System stats, activity feed, service health
│           ├── Badges.jsx              # Badge registration and management
│           ├── Users.jsx               # User creation with role assignment
│           ├── Devices.jsx             # Workstation registration
│           ├── Policies.jsx            # Access policy management
│           └── AuditLogs.jsx           # Color-coded DLP event timeline
│
├── firmware/                           # ESP32 firmware
│   ├── badge/                          # BLE advertiser (wearable badge)
│   └── anchor/                         # BLE scanner (workstation anchor)
│
├── guardian/                           # Root vault guardian: dead-man wipe, fanotify access gate
├── scripts/                            # Utility scripts (database, sudoers, PAKL provisioning)
├── tests/                              # Test suite
├── evaluation/                         # Experiment scripts, measurement data and analysis
└── config/                             # Environment configs
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 15+
- Redis 7+
- ESP32 development board × 2 (badge + anchor)
- `udisksctl` (pre-installed on Ubuntu Desktop)
- `xclip` (for clipboard guard: `sudo apt install xclip`)

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
# Ensure the ESP32 anchor node is plugged in via USB
# The agent auto-resets the ESP32 on connect (no manual EN press needed)

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

### 6. Presence-attested key leasing, relay detection and vault guardian

The steps above run the original protocol. To run the hardened version (PAKL with
anchor-attested challenge–response and the vault guardian):

```bash
# Master key, device key, TLS certificate and badge/anchor keys; wraps stored keys
python scripts/provision_pakl.py --badge-mac AA:BB:CC:DD:EE:FF --wrap-existing
# Re-flash firmware/badge and firmware/anchor (they now include the generated *_secrets.h)

# Vault guardian (root systemd service)
sudo bash guardian/install.sh

# Server: PAKL with challenge-response (16 ms bound, calibrated in evaluation/)
set -a; source secrets/pakl.env; set +a
SECURITY_MODE=pakl CR_REQUIRED=true CR_MAX_RTT_US=16000 \
  uvicorn server.main:app --host 0.0.0.0 --port 8443 \
  --ssl-keyfile secrets/tls/server.key --ssl-certfile secrets/tls/server.crt

# Agent
python -m agent.main --port /dev/ttyACM0 --server https://localhost:8443 \
  --ca-cert secrets/tls/server.crt --badge-mac AA:BB:CC:DD:EE:FF --badge-id 1 \
  --security pakl --device-key-file secrets/device.key --challenge-response --guardian
```

Experiment scripts, measurement data and the analysis are in [`evaluation/`](evaluation/README.md).

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
│  Layer 6: Data Loss Prevention (7 Guards)                     │
│  ├─ Clipboard clearing (0.5s poll)                            │
│  ├─ Screenshot blocking (process kill + file deletion)        │
│  ├─ Browser/app upload blocking (inotify + SIGKILL)           │
│  ├─ USB storage blocking (unmount + power-off)                │
│  ├─ Print blocking (spooler kill + CUPS cancel)               │
│  ├─ File copy detection (exfiltration watcher)                │
│  └─ Screen lock on badge departure (loginctl)                 │
│                                                                │
│  Layer 7: Audit Trail                                          │
│  ├─ Every key request, lock/unlock, and DLP event logged      │
│  └─ Tamper-evident audit log in PostgreSQL                    │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Badge cloning | MAC filtering + server-side policy check |
| USB exfiltration | USB guard detects, unmounts, and powers off removable drives |
| Browser upload | inotify detects vault file access → kills browser before upload completes |
| Screenshot capture | Process-level kill + GNOME Shell screenshot file deletion |
| Clipboard leak | 0.5s polling clears clipboard contents |
| Printing vault files | Kill print spoolers, cancel CUPS jobs |
| Unattended workstation | Auto-lock screen + vault re-encryption within seconds of departure |
| Shadow directory attack | `chmod 000` + rogue file wipe on re-unlock |
| Process holding files | Force-kill via `lsof`/`fuser` before sync |
| Stale key cache | Redis invalidation on every key store/delete |
| Network failure | Fail-closed — vault stays locked without server |
| Encrypted file sharing | Only decrypted vault (`~/spaze/`) files are blocked; encrypted blobs (`~/spaze-vault/`) can be freely transferred |

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
|------|--------------:|
| **Dashboard** | System stats, recent activity feed, service health |
| **Badges** | Register, search, activate/revoke BLE badges |
| **Users** | Create users with role assignment and badge binding |
| **Devices** | Register workstations with location metadata |
| **Policies** | Grant/revoke badge→device access with filters |
| **Audit Logs** | Filterable event timeline with 5s auto-refresh, DLP event color-coding |

**Theme**: Dark/Light mode toggle with localStorage persistence.

---

## Project Info

- **Type**: College Major Project (2026)
- **Domain**: IoT Security, Zero-Trust Architecture, Data Loss Prevention
- **Architecture**: Microservices (Agent + Server + Dashboard + IoT Firmware)
- **OS Support**: Linux (Ubuntu 24.04 LTS — tested)

## License

This project is part of academic research. All rights reserved.
