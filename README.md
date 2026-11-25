# Halo: Combat Evolved — 4-Player Online Co-op Mod (MCC PC)

Play Halo: Combat Evolved's campaign online with up to **4 players** in **Halo: The Master Chief Collection (Steam PC)** on both **Windows** and **Linux (Proton / Steam Deck / CachyOS)**.

> **Important:** All players in the co-op session must have this mod installed and launch MCC with **Easy Anti-Cheat (EAC) Disabled**.

---

## Installation (Players)

### Prerequisites
- **Halo: The Master Chief Collection** on Steam, with the **Halo: Combat Evolved** campaign DLC installed.
- **Easy Anti-Cheat Disabled:** You must use Steam's **"Play Halo: MCC Anti-Cheat Disabled (Mods and Limited Services)"** launch option.

### Step 1: Locate your MCC `Win64` folder
- **Windows (default Steam path):**
  ```text
  C:\Program Files (x86)\Steam\steamapps\common\Halo The Master Chief Collection\MCC\Binaries\Win64\
  ```
- **Linux / Steam Deck / CachyOS (default Steam path):**
  ```text
  ~/.local/share/Steam/steamapps/common/Halo The Master Chief Collection/MCC/Binaries/Win64/
  ```
  *(Tip: In Steam, right-click **Halo: The Master Chief Collection** → **Manage** → **Browse local files**, then open `MCC` → `Binaries` → `Win64`.)*

### Step 2: Copy the mod files
Download or build `version.dll` and copy **both** of these files into the `Win64` folder (right next to `MCC-Win64-Shipping.exe`):
- `version.dll`
- `ce_4player.ini`

### Step 3: Linux / Proton / SteamOS only
If you are playing on Linux (via Proton), Steam/Wine will ignore local `version.dll` files unless you tell it to load them:
1. In Steam, right-click **Halo: The Master Chief Collection** → **Properties...** → **General**.
2. Under **Launch Options**, paste:
   ```text
   WINEDLLOVERRIDES="version=n,b" %command%
   ```
*(Windows users can skip this step—Windows loads `version.dll` from the game folder automatically.)*

### Step 4: Launch the game
1. Click **Play** in Steam.
2. When prompted, select **"Play Halo: MCC Anti-Cheat Disabled (Mods and Limited Services)"**.
3. If `AllocConsole = true` in `ce_4player.ini`, a diagnostic console window will open and a `ce_4player.log` file will be created in the `Win64` folder to confirm the mod is active.

---

## Configuration (`ce_4player.ini`)

You can customize the mod by editing `ce_4player.ini` in your `Win64` folder:

| Setting | Default | Description |
| :--- | :--- | :--- |
| `AllocConsole` | `true` | Opens a diagnostic console window on startup (`false` to hide it). |
| `TargetMaxPlayers` | `4` | Maximum co-op party size. |
| `EnableSpawnCloning` | `true` | Automatically spawns Players 3 & 4 around Player 1/2 if a level only defines 1–2 spawns. |
| `SpawnCloneRadius` | `1.25` | Distance offset (in world units) for cloned player spawns. |
| `EnableCatchupTeleport` | `true` | Enables automatic co-op catch-up teleports for extra players. |

---

## Uninstalling

Delete `version.dll`, `ce_4player.ini`, and `ce_4player.log` from `MCC/Binaries/Win64/`. If you added `WINEDLLOVERRIDES` on Linux, you can remove it from Steam Launch Options.

---

## Building from Source (Developers)

### Windows (MSVC + CMake)
```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```
Output: `build/Release/version.dll`

### Linux Cross-Compile (MinGW-w64)
Install `mingw-w64-gcc` (e.g., `sudo pacman -S mingw-w64-gcc` on Arch/CachyOS), then:
```bash
cmake -B build-win64 -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake -DBUILD_TESTS=OFF
cmake --build build-win64
```
Output: `build-win64/version.dll`

### Portable Unit Tests
```bash
cmake -B build-tests -G Ninja
cmake --build build-tests
ctest --test-dir build-tests --output-on-failure
```

## Developer Documentation
- [Architecture Overview](docs/ARCHITECTURE.md)
- [Reverse-Engineering Guide](docs/RE_GUIDE.md)
