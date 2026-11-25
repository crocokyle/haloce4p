# Architecture Overview

## High-Level Design

Enabling 4-player online campaign co-op in MCC Halo: Combat Evolved requires coordinating two distinct layers:

1. **MCC Frontend & Session Layer (`MCC-Win64-Shipping.exe`)**
   - Unreal Engine 4 lobby/party UI and session manager.
   - Enforces a 2-player party cap when Halo: CE Campaign is selected.
   - Constructs the launch configuration struct passed into `halo1.dll` and manages Steamworks P2P transport between peers.

2. **Halo 1 Engine Layer (`halo1.dll`)**
   - Dynamically loaded by MCC when entering a Halo: CE mission and unloaded on return to the main menu.
   - Campaign mode uses deterministic lockstep networking (unlike multiplayer's client-server model), with several hardcoded `2`-player assumptions:
     - Campaign player count cap (`<= 2`).
     - Per-tick lockstep input/action buffers sized for 2 players.
     - `game_create_player` / `player_spawn` indexing into `player_starting_locations` (vanilla `.scenario` tags typically define 1–2 spawns).
     - Co-op respawn safety checks, catch-up teleports, and HUD navpoints.

## Hybrid Mod Strategy

- **Runtime DLL (`version.dll`)**: Handles all lobby caps, engine player limits, lockstep buffer expansion, and runtime spawn cloning (cloning Player 0/1's spawn with a collision-safe radial offset when `player_index >= 2`).
- **Optional `.map` / Tag Patches**: For campaign missions with strict 2-player HSC scripts (e.g., *Pillar of Autumn* cryotube sequence, *Truth and Reconciliation* gravity lift, *The Maw* Warthog run), optional `.scenario` / script patches can be paired with the DLL.

## Code Layout

- `src/proxy/`: `version.dll` export forwarding (`version.def`, `version_proxy.cpp`).
- `src/core/`:
  - `logger.*`: File + console + `OutputDebugStringA` logging.
  - `pattern_scanner.*`: Portable AOB scanner and RIP-relative resolver.
  - `module_watcher.*`: Polls for `halo1.dll` load/unload and reads PE headers.
  - `hook_manager.*`: MinHook lifecycle wrapper.
- `src/hooks/`:
  - `lobby_hooks.*`: `MCC-Win64-Shipping.exe` probes and detours.
  - `h1_engine_hooks.*`: `halo1.dll` probes and detours.
