# Halo: CE 4-Player Co-op Roadmap

**Goal for `v2.0.0`:** All 10 campaign missions in Halo: Combat Evolved (MCC) playable from start to finish in 3–4 player online co-op without soft-locks, missing weapons, stuck spawns, or mission-transition drops.

---

## Milestones

- **`v1.0.x` — Core 3–4 Player Networking & Lobby** *(Done)*
  - Unlocked 3–4 player MCC campaign lobby, Mission Select, and Transport0 multi-peer delivery.
  - Fixed subsequent mission reloads (`LdrRegisterDllNotification`) so `halo1.dll` hooks survive rapid mission transitions.
- **`v1.1.x` — Per-Mission Spawn & Script Fixes** *(In Progress)*
  - Added host-authoritative [`ce_4player_spawns.ini`](ce_4player_spawns.ini) (hot-reloaded on mission launch and synced to clients in lockstep) with per-mission and per-player (`.p1`–`.p4`) `eject` / `separate` rules.
  - Fixed `p2`–`p4` catchup teleports, late-spawn catchup (`LateSpawnTeleport` / `LateSpawnEquip`), and equipment mirroring (`Hook_PlayerAddEquipment`).
  - Playing through and verifying every mission 1–10 one by one, fixing any mission-specific spawn, cutscene, door/trigger, or checkpoint issues as we go.
- **`v2.0.0` — Full Campaign Playable** *(Target)*
  - All 10 missions verified start-to-finish in 3–4 player co-op with working spawns, teleports, checkpoints, equipment grants, and seamless mission-to-mission progression.

---

## 10-Mission Campaign Status

| # | Map | Mission | Default Rules (`ce_4player_spawns.ini`) | Status |
|---|---|---|---|---|
| 1 | `a10` | The Pillar of Autumn | `p1`: `eject, x=0.0, y=-1.3, z=0.0, delay=1.5`; `p3`/`p4`: `eject, y=-0.8 / -1.2` | Playable past bridge (`v1.1.3`); finishing `a10` test |
| 2 | `a30` | Halo | `p3`/`p4`: `separate, x=0.8 / -0.8, y=0.0, z=0.05, cutscene=true` | Playable (host/peer overlap in cutscene) |
| 3 | `a50` | The Truth and Reconciliation | `p1`: `eject, y=0.8`; `p3`/`p4`: `eject, y=0.8 / 1.2` | Built-in default; untested in 3p |
| 4 | `b30` | The Silent Cartographer | `p3`/`p4`: `none` | Untested in 3p |
| 5 | `b40` | Assault on the Control Room | `p3`/`p4`: `none` | Untested in 3p |
| 6 | `c10` | 343 Guilty Spark | `p3`/`p4`: `eject, x=0.0, y=0.8 / 1.2, z=0.05, delay=1.5` | Built-in default; untested in 3p |
| 7 | `c20` | The Library | `p3`/`p4`: `none` | Untested in 3p |
| 8 | `c40` | Two Betrayals | `p3`/`p4`: `separate, x=0.8 / -0.8, y=0.0, z=0.05, cutscene=false` | Built-in default; untested in 3p |
| 9 | `d20` | Keyes | `p3`/`p4`: `none` | Untested in 3p |
| 10 | `d40` | The Maw | `p3`/`p4`: `none` | Untested in 3p |
