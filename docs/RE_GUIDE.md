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

## Verified Findings (MCC + Halo: CE + Halo 2 Notes)

### 1. Unified MCC Party & Per-Engine Campaign Cap (`MCC-Win64-Shipping.exe`)
MCC uses a single `Squad` / `PartyManager` system across all titles, then checks per-game limits by `engine_id` (`0` = Halo: CE, `1` = Halo 2, `2` = Halo 3, `3` = Halo 4, `5` = ODST, `6` = Reach):

- **`Squad::GetTotalPlayerCount()` @ `0x14025119C`**
  - Calls `PartyManager::GetLocalPlayerCount()` (`0x140389DEC`) and compares with `*(uint32_t*)(squad + 0xD20)`, returning the maximum.
  - Hooked by `ForceTestPartySize` in `src/hooks/lobby_hooks.cpp` to simulate 3–4 player parties in the lobby.
- **Lobby Launch & Party-Change Validation @ `0x1404B2770`** (AOB `83 FD 01 76 1E 83 FE 02 76 10` at `0x1404B27BF`):
  1. Calls `PartyManager::GetLocalPlayerCount()` (`esi`) and `Squad::GetTotalPlayerCount()` (stored to `[0x144001724]`).
  2. Calls `0x14025116C` and compares against `[0x144001722]` — if the party roster changed since the game mode was selected, it triggers the "party size has changed" warning dialog (`0x1432B94E0` / `0x1432B93C0`).
  3. Checks `cmp ebp, 0x1; jbe 0x1404B27E2` (`ebp` = `engine_id`):
     - **Engines `0` (Halo: CE) and `1` (Halo 2)** branch to `0x1404B27E2`, which checks local players `<= 2` and remote/total players `[0x144001724] <= 2` (`0x1404B27E7`: `83 3D 36 EF B4 03 02`), triggering `$DIALOG_TOO_MANY_REMOTE_PLAYERS_*` if `> 2`.
     - **Engines `>= 2`** (Halo 3, ODST, Reach, Halo 4) fall through to `0x1404B27D9` (`cmp dword ptr [0x144001724], 4`).
  - **Key takeaway for Halo 2:** Patching `0x1404B27ED` (`0x02` → `0x04`) unlocks the MCC lobby remote-player cap for **both Halo: CE (`0`) and Halo 2 (`1`)** simultaneously. To mod Halo 2 in the future, you would mainly need the `halo2.dll` engine cap + spawn/teleport hooks alongside these existing MCC lobby hooks.
- **UI Launch/Player-Count Selector @ `0x1404B8CE7`:** Calls `Squad::GetTotalPlayerCount()` and branches on `2`, `3`, and `>= 4`.
- **`MCC::GetGameInstance(uint32_t engine_id)` @ `0x1401E2CCC`** and **`DeserializeGameDef` @ `0x1420A7554`:** Hooked to track `Halo1` context and raise `MaxCampaignPlayers` in parsed game definitions.

### 2. Halo: CE Engine (`halo1.dll`, PE timestamp `0x68A0E4CF`)
- **`InitGameSession` @ RVA `0x66DF0`:** Receives MCC's session/peer array (stride `0x58`) and writes `game_coop_player_count` (`0x181B7B910`). Note: `game_coop_player_count` tracks *local* players (`1` per PC in online co-op), while remote peers are passed through the session array.
- **`CampaignPlayerCap` @ RVA `0x6747A`:** Checks `r13d <= 2` (`0x02` at `+5` = RVA `0x6747F`); patched to `4`.
- **Player Slot Creation @ RVA `0xB54E1C`:** Already supports player slots `0..3` (`cmp di, 0x3`).
- **Map Starting Locations:** All 10 Halo: CE campaign `.map` files (`a10`–`d40`) have `player_starting_locations` count = `2` in `scenario` (`0x354`), yet `halo1.dll` spawns 4 Spartans cleanly on `a10` when `CampaignPlayerCap` is raised.
- **Cutscenes & Elevators (Remaining Work):** Physical elevators move all players via collision, but vanilla `.map` BlamScript cutscenes only call `object_teleport` on `(player0)` and `(player1)`. Wiring `EnableCatchupTeleport` in `src/hooks/h1_engine_hooks.cpp` will teleport straggling players 2 & 3 near player 0 on cutscene/BSP transitions without requiring `.map` edits.
