# OpenWA catalog on WormNETBot

Vendored from [paavohuhtala/OpenWA](https://github.com/paavohuhtala/OpenWA) `re/` (2026-05-28).

| Path | Purpose |
|------|---------|
| `third_party/OpenWA-re/` | 408 TOML shards — canonical WA.exe RE |
| `third_party/OpenWA-re/wa_import.json` | Ghidra import manifest (5222 symbols) |
| `third_party/OpenWA-re/ghidra_scripts/` | `OpenWAImport.java` etc. |
| `third_party/OpenWA-re/openwa-re` | Linux x86_64 exporter binary |
| `scripts/openwa_re_crosscheck.py` | Anchor VA cross-check vs `WA.txt` |

## Ghidra HTTP API (VM 101, LaurieWired GhidraMCP)

Base URL: `http://192.168.1.59:8080`

| Action | Method | Endpoint | Params |
|--------|--------|----------|--------|
| List functions | GET | `/list_functions` | — |
| Search by name | GET | `/searchFunctions` | `query=` |
| Decompile | GET | `/decompile_function` | `address=0x...` |
| Lookup function | GET | `/get_function_by_address` | `address=0x...` |
| **Rename** | **POST** | **`/rename_function_by_address`** | **`function_address=0x...&new_name=...`** |

**Do not use** `renameFunction` — wrong parameter names, always returns "Rename failed".

Bulk OpenWA import from CT 104:

```bash
python3 scripts/ghidra_openwa_http_import.py          # all symbols (preflight skip)
python3 scripts/ghidra_openwa_http_import.py --anchors-only
python3 scripts/ghidra_openwa_http_import.py --query GameRuntime
```

OpenWA lists ~5200 function symbols; ~20% have no Ghidra function at that VA (thunks/data) — those are skipped, not errors.

## Ghidra VM 101 (192.168.1.59) — import catalog

1. Copy to the Windows Ghidra machine:
   - `wa_import.json`
   - `ghidra_scripts/OpenWAImport.java` → `%USERPROFILE%\ghidra_scripts\`

2. In Ghidra with **WA.exe** open: **Tools → OpenWA → Import catalog**
   Or headless: `OpenWAImport.java C:\path\to\wa_import.json`

3. Re-test HTTP decompile — names should match OpenWA (`EntityMessage__msg_expand`, `GameRuntime__BeginNetworkGameEnd`, …).

## Refresh manifest after editing TOML

On a host with the full OpenWA git checkout + Rust:

```bash
cargo run -p openwa-re-data --release -- validate
cargo run -p openwa-re-data --release -- export /path/to/scratch
```

Or on CT 104 (vendored catalog only): re-run export from a synced checkout; the bundled `openwa-re` binary reads `third_party/OpenWA-re/*.toml`.

## Key facts for WormNETBot

- **EntityMessage::Surrender** = `0x2B` → task type **1043** on wire (`msg_expand`: type = byte + 1000)
- **EntityMessage::TeamVictory** = `0x14` → task type **1020**
- **EntityMessage::MachineQuit** = `0x0D` — payload of `BeginNetworkGameEnd` 12-byte net handshake (not surrender)
- **EntityMessage::TurnEndMaybe** = `0x75` — broadcast when entering `ROUND_ENDING`
- Network end UI **"PLEASE WAIT %d SEC"** = `GameRuntime__RenderNetworkEndWaitTextbox` @ `0x534E00`
- `game_state`: 3=`NETWORK_END_STARTED`, 2=`NETWORK_END_AWAITING_PEERS`, 4=`ROUND_ENDING`, 5=`EXIT`

See `Findings.md` § OpenWA integration.


Note: the bundled `openwa-re` binary was built on PVE (glibc 2.39). On CT 104, re-export requires rebuilding on the container or running export on the PVE host and copying `wa_import.json`.
