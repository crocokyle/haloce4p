#include "hooks/h1_engine_hooks.hpp"

#include "core/hook_manager.hpp"
#include "core/logger.hpp"
#include "core/memory_patch.hpp"
#include "core/pattern_scanner.hpp"

#include <cstdint>
#include <mutex>
#include <optional>

namespace ce4p::h1 {

namespace {

// halo1.dll: Co-op/local player count cap in game initialization.
// 75 08 41 83 FD [02] 7F 08 EB 28 41 83 FD 04 7E 22
constexpr const char* kSigCampaignPlayerCap =
    "75 08 41 83 FD 02 7F 08 EB 28 41 83 FD 04 7E 22";

// halo1.dll: InitGameSession (sets game_coop_player_count at 0x181B7B910, RVA 0x01B7B910)
constexpr const char* kSigInitGameSession =
    "40 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 B0 EE FF FF B8 50 12 00 00";

// halo1.dll: volume_teleport_players_not_inside_impl @ 0x180C57200
// Resolves players_array (+0x19), object_teleport_to_flag (+0x60), post_teleport (+0x67), datum_next (+0x78)
constexpr const char* kSigVolumeTeleport =
    "48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 EC 20 48 8B 1D ? ? ? ? 0F B7 EA";

// halo1.dll: IGameEngine::vtable[+10] (StartGame) @ 0x1800939D0
constexpr const char* kSigIGameEngineStart =
    "40 53 56 57 48 81 EC 50 02 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 40 02 00 00 48 8B 05 ? ? ? ? 49 8B D8";

// halo1.dll: SessionReadyCheck callback @ 0x180080D80 (sets 0x181B7AA80)
constexpr const char* kSigSessionReadyCheck =
    "48 83 EC 28 48 8B 0D ? ? ? ? 45 33 C9 45 33 C0 BA F0 00 00 00 FF 15";

// halo1.dll: WaitForPeers (state 8) @ 0x180B26EF0 (45s timeout waiting for connected_peers == expected)
constexpr const char* kSigWaitForPeers =
    "40 53 48 83 EC 20 E8 ? ? ? ? 8B D8 2B 1D ? ? ? ? E8 ? ? ? ? 81 FB C8 AF 00 00";

constexpr const char* kSigLockstepInputBuffer = "";
constexpr const char* kSigGameCreatePlayer = "";
constexpr const char* kSigCoopRespawnCheck = "";

constexpr uintptr_t kRvaCoopPlayerCount = 0x01B7B910;
constexpr uintptr_t kRvaMccGameInterface = 0x02E3B9A0;
constexpr size_t kPlayerDatumStride = 0xC20;
constexpr size_t kPlayerDatumUnitOffset = 0x64;
constexpr size_t kDataArrayOffsetToData = 0x34;

std::mutex g_state_mutex;
std::optional<ModuleSnapshot> g_active_snapshot;
PatchRegistry g_h1_patches;

uintptr_t g_h1_base = 0;
int g_force_test_players = 0;
bool g_enable_catchup_teleport = true;
uintptr_t g_hooked_create_engine = 0;
uintptr_t g_hooked_init_session = 0;
uintptr_t g_hooked_has_player = 0;
uintptr_t g_hooked_object_teleport = 0;
uintptr_t g_hooked_engine_start = 0;
uintptr_t g_hooked_session_ready = 0;
uintptr_t g_hooked_wait_for_peers = 0;

const uint8_t* const* g_players_array_ptr = nullptr;
const uint32_t* g_session_ready_flag_ptr = nullptr;
uint32_t g_last_session_ready_logged = 0xFFFFFFFFu;
const uint32_t* g_expected_peers_ptr = nullptr;
uint32_t g_last_connected_peers_logged = 0xFFFFFFFFu;

using FnCreateGameEngine = int(__fastcall*)(void** out_engine);
FnCreateGameEngine g_orig_create_game_engine = nullptr;

using FnInitGameSession = uint64_t(__fastcall*)(void* a1, void* a2, void* a3, uint32_t a4);
FnInitGameSession g_orig_init_game_session = nullptr;

using FnHasPlayer = bool(__fastcall*)(void* self, uint64_t a2, uint64_t a3, uint64_t a4, uint32_t slot);
FnHasPlayer g_orig_has_player = nullptr;

using FnObjectTeleportToFlag = void(__fastcall*)(uint32_t object_index, uint16_t flag_index, bool reset);
FnObjectTeleportToFlag g_orig_object_teleport_to_flag = nullptr;

using FnPostTeleportReset = void(__fastcall*)(uint32_t object_index);
FnPostTeleportReset g_fn_post_teleport = nullptr;

using FnDatumArrayNext = int32_t(__fastcall*)(const void* data_array, int32_t prev_datum);
FnDatumArrayNext g_fn_datum_next = nullptr;

using FnIGameEngineStart = void(__fastcall*)(void* self, void* mcc_iface, const uint8_t* launch_settings, void* a4);
FnIGameEngineStart g_orig_engine_start = nullptr;

using FnSessionReadyCheck = void(__fastcall*)();
FnSessionReadyCheck g_orig_session_ready_check = nullptr;

using FnWaitForPeers = void(__fastcall*)();
FnWaitForPeers g_orig_wait_for_peers = nullptr;

using FnGetConnectedPeers = uint32_t(__fastcall*)();
FnGetConnectedPeers g_fn_get_connected_peers = nullptr;

void __fastcall Hook_IGameEngineStart(void* self, void* mcc_iface, const uint8_t* launch_settings, void* a4) {
    if (launch_settings) {
        uint8_t f0 = launch_settings[0];
        uint8_t f2 = launch_settings[2];
        uint32_t mode = *reinterpret_cast<const uint32_t*>(launch_settings + 0x0C);
        int16_t map_id = *reinterpret_cast<const int16_t*>(launch_settings + 0x14);
        uint32_t submode = *reinterpret_cast<const uint32_t*>(launch_settings + 0xE8);
        uint32_t f2f0 = *reinterpret_cast<const uint32_t*>(launch_settings + 0x2F0);
        CE4P_LOG_INFO(
            "[H1] IGameEngineStart(f0=0x%02X, f2=0x%02X, mode=%u, map_id=%d, +0xE8=%u, +0x2F0=%u)",
            f0, f2, mode, static_cast<int>(map_id), submode, f2f0
        );
    } else {
        CE4P_LOG_INFO("[H1] IGameEngineStart(launch_settings=null)");
    }
    g_orig_engine_start(self, mcc_iface, launch_settings, a4);
}

void __fastcall Hook_SessionReadyCheck() {
    g_orig_session_ready_check();
    if (g_session_ready_flag_ptr) {
        uint32_t ready = *g_session_ready_flag_ptr;
        if (ready != g_last_session_ready_logged) {
            g_last_session_ready_logged = ready;
            CE4P_LOG_INFO("[H1] SessionReadyCheck -> session_ready_flag=%u", ready);
        }
    }
}

void __fastcall Hook_WaitForPeers() {
    if (g_fn_get_connected_peers && g_expected_peers_ptr) {
        uint32_t conn = g_fn_get_connected_peers();
        uint32_t exp = *g_expected_peers_ptr;
        if (conn != g_last_connected_peers_logged) {
            g_last_connected_peers_logged = conn;
            CE4P_LOG_INFO("[H1] WaitForPeers: connected=%u, expected=%u", conn, exp);
        }
    }
    g_orig_wait_for_peers();
}

void __fastcall Hook_ObjectTeleportToFlag(uint32_t object_index, uint16_t flag_index, bool reset) {
    g_orig_object_teleport_to_flag(object_index, flag_index, reset);

    static thread_local bool in_catchup = false;
    if (!g_enable_catchup_teleport || in_catchup || object_index == 0xFFFFFFFF) {
        return;
    }
    if (!g_players_array_ptr || !g_fn_datum_next || !g_fn_post_teleport) {
        return;
    }
    const uint8_t* players_arr = *g_players_array_ptr;
    if (!players_arr) {
        return;
    }
    int32_t data_off = *reinterpret_cast<const int32_t*>(players_arr + kDataArrayOffsetToData);
    const uint8_t* data_base = players_arr + data_off;

    int32_t datum = g_fn_datum_next(players_arr, -1);
    if (datum == -1) {
        return;
    }
    const uint8_t* p0 = data_base + static_cast<size_t>(datum & 0xFFFF) * kPlayerDatumStride;
    uint32_t p0_unit = *reinterpret_cast<const uint32_t*>(p0 + kPlayerDatumUnitOffset);
    if (object_index != p0_unit) {
        return;
    }

    in_catchup = true;
    int slot = 1;
    while ((datum = g_fn_datum_next(players_arr, datum)) != -1) {
        if (slot >= 2) {
            const uint8_t* pi = data_base + static_cast<size_t>(datum & 0xFFFF) * kPlayerDatumStride;
            uint32_t unit_obj = *reinterpret_cast<const uint32_t*>(pi + kPlayerDatumUnitOffset);
            if (unit_obj != 0xFFFFFFFF && unit_obj != object_index) {
                g_orig_object_teleport_to_flag(unit_obj, flag_index, reset);
                g_fn_post_teleport(unit_obj);
                CE4P_LOG_INFO(
                    "[H1] CatchupTeleport: player[%d] unit=0x%X -> flag=%u",
                    slot,
                    unit_obj,
                    flag_index
                );
            }
        }
        ++slot;
    }
    in_catchup = false;
}

bool __fastcall Hook_HasPlayer(void* self, uint64_t a2, uint64_t a3, uint64_t a4, uint32_t slot) {
    bool real = g_orig_has_player(self, a2, a3, a4, slot);
    if (g_force_test_players > 1 && slot < static_cast<uint32_t>(g_force_test_players)) {
        if (!real) {
            CE4P_LOG_INFO("[H1] ForceTestPlayerCount: spoofing HasPlayer(slot=%u) -> true", slot);
        }
        return true;
    }
    return real;
}

int __fastcall Hook_CreateGameEngine(void** out_engine) {
    int ret = g_orig_create_game_engine(out_engine);
    void* engine = out_engine ? *out_engine : nullptr;
    CE4P_LOG_INFO(
        "[H1] CreateGameEngine() -> ret=0x%X, engine=0x%llX",
        ret,
        reinterpret_cast<unsigned long long>(engine)
    );
    return ret;
}

uint64_t __fastcall Hook_InitGameSession(void* a1, void* a2, void* a3, uint32_t a4) {
    if (g_h1_base && g_force_test_players > 1 && !g_hooked_has_player) {
        void* iface = *reinterpret_cast<void**>(g_h1_base + kRvaMccGameInterface);
        if (iface) {
            uintptr_t* vtable = *reinterpret_cast<uintptr_t**>(iface);
            uintptr_t target = vtable[0x2C0 / 8];
            if (HookManager::Instance().InstallHook(
                    "MCC::HasPlayer",
                    target,
                    reinterpret_cast<void*>(&Hook_HasPlayer),
                    reinterpret_cast<void**>(&g_orig_has_player)
                )) {
                g_hooked_has_player = target;
            }
        }
    }

    uint64_t ret = g_orig_init_game_session(a1, a2, a3, a4);
    if (g_h1_base) {
        auto* coop_count = reinterpret_cast<const int16_t*>(g_h1_base + kRvaCoopPlayerCount);
        CE4P_LOG_INFO(
            "[H1] InitGameSession(a4=%u) -> ret=0x%llX, game_coop_player_count=%d",
            a4,
            static_cast<unsigned long long>(ret),
            static_cast<int>(*coop_count)
        );
    }
    return ret;
}

std::optional<uintptr_t> ProbePattern(MemorySpan span, const ModConfig& config, const char* key, const char* fallback) {
    std::string pattern = config.GetSignature(key, fallback);
    if (pattern.empty()) {
        CE4P_LOG_DEBUG("[H1] Signature '%s' not yet populated.", key);
        return std::nullopt;
    }
    auto match = FindPattern(span, pattern);
    if (match.has_value()) {
        CE4P_LOG_INFO("[H1] Found '%s' @ 0x%llX", key, static_cast<unsigned long long>(*match));
    } else {
        CE4P_LOG_WARN("[H1] Pattern NOT found for '%s'.", key);
    }
    return match;
}

void ScanSnapshot(const ModuleSnapshot& snapshot, const ModConfig& config) {
    g_h1_base = snapshot.base;
    g_force_test_players = config.force_test_player_count;
    g_enable_catchup_teleport = config.enable_catchup_teleport;

    MemorySpan span{
        reinterpret_cast<const uint8_t*>(snapshot.base),
        snapshot.size,
    };

    CE4P_LOG_INFO(
        "[H1] Probing halo1.dll (timestamp=0x%08X, target_players=%d, spawn_cloning=%s, radius=%.2f)...",
        snapshot.pe_timestamp,
        config.target_max_players,
        config.enable_spawn_cloning ? "on" : "off",
        config.spawn_clone_radius
    );

    if (auto addr = ProbePattern(span, config, "CampaignPlayerCap", kSigCampaignPlayerCap)) {
        if (g_h1_patches.Count() == 0 && config.target_max_players > 2) {
            g_h1_patches.PatchByte(
                "CampaignPlayerCap",
                *addr + 5,
                static_cast<uint8_t>(config.target_max_players)
            );
        }
    }

    if (!g_hooked_create_engine && snapshot.handle) {
        if (auto* proc = reinterpret_cast<void*>(GetProcAddress(snapshot.handle, "CreateGameEngine"))) {
            uintptr_t target = reinterpret_cast<uintptr_t>(proc);
            if (HookManager::Instance().InstallHook(
                    "H1::CreateGameEngine",
                    target,
                    reinterpret_cast<void*>(&Hook_CreateGameEngine),
                    reinterpret_cast<void**>(&g_orig_create_game_engine)
                )) {
                g_hooked_create_engine = target;
            }
        }
    }

    if (!g_hooked_init_session) {
        if (auto addr = ProbePattern(span, config, "InitGameSession", kSigInitGameSession)) {
            if (HookManager::Instance().InstallHook(
                    "H1::InitGameSession",
                    *addr,
                    reinterpret_cast<void*>(&Hook_InitGameSession),
                    reinterpret_cast<void**>(&g_orig_init_game_session)
                )) {
                g_hooked_init_session = *addr;
            }
        }
    }

    ProbePattern(span, config, "LockstepInputBuffer", kSigLockstepInputBuffer);
    ProbePattern(span, config, "GameCreatePlayer", kSigGameCreatePlayer);
    ProbePattern(span, config, "CoopRespawnCheck", kSigCoopRespawnCheck);

    if (!g_hooked_object_teleport) {
        if (auto vol_tp = ProbePattern(span, config, "VolumeTeleport", kSigVolumeTeleport)) {
            if (uintptr_t players_ptr = ResolveRipRelative(*vol_tp + 0x19, 3, 7)) {
                g_players_array_ptr = reinterpret_cast<const uint8_t* const*>(players_ptr);
            }
            if (uintptr_t post_tp = ResolveRipRelative(*vol_tp + 0x67, 1, 5)) {
                g_fn_post_teleport = reinterpret_cast<FnPostTeleportReset>(post_tp);
            }
            if (uintptr_t datum_next = ResolveRipRelative(*vol_tp + 0x78, 1, 5)) {
                g_fn_datum_next = reinterpret_cast<FnDatumArrayNext>(datum_next);
            }
            if (uintptr_t obj_tp = ResolveRipRelative(*vol_tp + 0x60, 1, 5)) {
                if (HookManager::Instance().InstallHook(
                        "H1::ObjectTeleportToFlag",
                        obj_tp,
                        reinterpret_cast<void*>(&Hook_ObjectTeleportToFlag),
                        reinterpret_cast<void**>(&g_orig_object_teleport_to_flag)
                    )) {
                    g_hooked_object_teleport = obj_tp;
                }
            }
        }
    }

    if (!g_hooked_engine_start) {
        if (auto addr = ProbePattern(span, config, "IGameEngineStart", kSigIGameEngineStart)) {
            if (HookManager::Instance().InstallHook(
                    "H1::IGameEngineStart",
                    *addr,
                    reinterpret_cast<void*>(&Hook_IGameEngineStart),
                    reinterpret_cast<void**>(&g_orig_engine_start)
                )) {
                g_hooked_engine_start = *addr;
            }
        }
    }

    if (!g_hooked_session_ready) {
        if (auto addr = ProbePattern(span, config, "SessionReadyCheck", kSigSessionReadyCheck)) {
            // At +0x35: `44 89 05 [disp32]` writing session_ready_flag (0x181B7AA80)
            if (uintptr_t flag_ptr = ResolveRipRelative(*addr + 0x35, 3, 7)) {
                g_session_ready_flag_ptr = reinterpret_cast<const uint32_t*>(flag_ptr);
            }
            if (HookManager::Instance().InstallHook(
                    "H1::SessionReadyCheck",
                    *addr,
                    reinterpret_cast<void*>(&Hook_SessionReadyCheck),
                    reinterpret_cast<void**>(&g_orig_session_ready_check)
                )) {
                g_hooked_session_ready = *addr;
            }
        }
    }

    if (!g_hooked_wait_for_peers) {
        if (auto addr = ProbePattern(span, config, "WaitForPeers", kSigWaitForPeers)) {
            if (uintptr_t fn_peers = ResolveRipRelative(*addr + 0x13, 1, 5)) {
                g_fn_get_connected_peers = reinterpret_cast<FnGetConnectedPeers>(fn_peers);
            }
            if (uintptr_t exp_ptr = ResolveRipRelative(*addr + 0x4A, 2, 6)) {
                g_expected_peers_ptr = reinterpret_cast<const uint32_t*>(exp_ptr);
            }
            if (HookManager::Instance().InstallHook(
                    "H1::WaitForPeers",
                    *addr,
                    reinterpret_cast<void*>(&Hook_WaitForPeers),
                    reinterpret_cast<void**>(&g_orig_wait_for_peers)
                )) {
                g_hooked_wait_for_peers = *addr;
            }
        }
    }
}

}  // namespace

void OnModuleLoaded(const ModuleSnapshot& snapshot, const ModConfig& config) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    g_active_snapshot = snapshot;
    ScanSnapshot(snapshot, config);
}

void RescanIfLoaded(const ModConfig& config) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (!g_active_snapshot.has_value()) {
        CE4P_LOG_INFO("[H1] halo1.dll is not currently loaded.");
        return;
    }
    ScanSnapshot(*g_active_snapshot, config);
}

void OnModuleUnloaded(const ModuleSnapshot& /*snapshot*/) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    if (g_hooked_wait_for_peers) {
        HookManager::Instance().RemoveHook(g_hooked_wait_for_peers);
        g_hooked_wait_for_peers = 0;
        g_orig_wait_for_peers = nullptr;
    }
    g_fn_get_connected_peers = nullptr;
    g_expected_peers_ptr = nullptr;
    g_last_connected_peers_logged = 0xFFFFFFFFu;
    if (g_hooked_session_ready) {
        HookManager::Instance().RemoveHook(g_hooked_session_ready);
        g_hooked_session_ready = 0;
        g_orig_session_ready_check = nullptr;
    }
    g_session_ready_flag_ptr = nullptr;
    g_last_session_ready_logged = 0xFFFFFFFFu;
    if (g_hooked_engine_start) {
        HookManager::Instance().RemoveHook(g_hooked_engine_start);
        g_hooked_engine_start = 0;
        g_orig_engine_start = nullptr;
    }
    if (g_hooked_object_teleport) {
        HookManager::Instance().RemoveHook(g_hooked_object_teleport);
        g_hooked_object_teleport = 0;
        g_orig_object_teleport_to_flag = nullptr;
    }
    g_players_array_ptr = nullptr;
    g_fn_post_teleport = nullptr;
    g_fn_datum_next = nullptr;
    if (g_hooked_has_player) {
        HookManager::Instance().RemoveHook(g_hooked_has_player);
        g_hooked_has_player = 0;
        g_orig_has_player = nullptr;
    }
    if (g_hooked_init_session) {
        HookManager::Instance().RemoveHook(g_hooked_init_session);
        g_hooked_init_session = 0;
        g_orig_init_game_session = nullptr;
    }
    if (g_hooked_create_engine) {
        HookManager::Instance().RemoveHook(g_hooked_create_engine);
        g_hooked_create_engine = 0;
        g_orig_create_game_engine = nullptr;
    }
    g_h1_patches.RevertAll();
    g_h1_base = 0;
    g_active_snapshot.reset();
    CE4P_LOG_INFO("[H1] Cleaned up halo1.dll hooks and patches.");
}

}  // namespace ce4p::h1
