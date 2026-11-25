# Reverse-Engineering Guide

This guide outlines the exact targets to locate in `MCC-Win64-Shipping.exe` and `halo1.dll` using Ghidra, IDA Pro, or x64dbg, and how to wire their AOB signatures into the mod.

## Workflow

1. Drop the built `version.dll` into `MCC/Binaries/Win64/` and launch MCC with **EAC Disabled**.
2. Verify `ce_4player.log` records:
   - `MCC-Win64-Shipping.exe` base address and size.
   - `halo1.dll` load event with base address, size, and PE timestamp when starting a Halo 1 campaign mission.
3. Load the corresponding binary into Ghidra/IDA (for `halo1.dll`, rebase to the logged base or use relative offsets).

## Target 1: `MCC-Win64-Shipping.exe` (`src/hooks/lobby_hooks.cpp`)

| Target | What to Look For | Goal |
| :--- | :--- | :--- |
| `CampaignMaxPlayersCheck` | Game-specific max co-op player table or switch on `EngineId == Halo1` returning `2` | Return `4` for Halo 1 Campaign |
| `LaunchSettingsPlayerCount` | Struct passed to `halo1.dll` entry point containing `player_count`, local player slots, and peer IDs | Ensure all 4 peer slots are populated |
| `LobbyReadyValidation` | UE4 party/squad readiness check disabling "Start" when `PartySize > MaxCoopPlayers` | Allow launch with 3–4 players |

## Target 2: `halo1.dll` (`src/hooks/h1_engine_hooks.cpp`)

| Target | What to Look For | Goal |
| :--- | :--- | :--- |
| `CampaignPlayerCap` | Assertions/checks comparing campaign player count against `2` (often near `"too many players"` or `players_globals` init) | Raise cap to `4` |
| `LockstepInputBuffer` | Per-tick input/action array stride/count in campaign simulation update | Expand/remap for 4 player slots |
| `GameCreatePlayer` | `game_create_player` / `player_spawn` reading `scenario->player_starting_locations[player_index]` | If `player_index >= count`, clone index `0` or `1` with a safe radial offset |
| `CoopRespawnCheck` | Co-op teammate-safe respawn & catch-up teleport loop (`for (i = 0; i < 2; ++i)`) | Iterate up to `4` players |

## Adding a Signature

Once you identify a stable function prologue or instruction sequence:
1. Create an IDA-style AOB string with `?` wildcards for relocatable displacements/immediates.
2. Paste it into the corresponding `kSig*` constant in `src/hooks/lobby_hooks.cpp` or `src/hooks/h1_engine_hooks.cpp`.
3. Rebuild and verify `ce_4player.log` logs `Found '<Name>' @ 0x...`.
4. Wire the detour via `HookManager::Instance().InstallHook(...)`.
