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

constexpr const char* kSigLockstepInputBuffer = "";
constexpr const char* kSigGameCreatePlayer = "";
constexpr const char* kSigCoopRespawnCheck = "";

constexpr uintptr_t kRvaCoopPlayerCount = 0x01B7B910;

std::mutex g_state_mutex;
std::optional<ModuleSnapshot> g_active_snapshot;
PatchRegistry g_h1_patches;

uintptr_t g_h1_base = 0;
uintptr_t g_hooked_create_engine = 0;
uintptr_t g_hooked_init_session = 0;

using FnCreateGameEngine = void*(__fastcall*)(void* host);
FnCreateGameEngine g_orig_create_game_engine = nullptr;

using FnInitGameSession = uint64_t(__fastcall*)(void* a1, void* a2, void* a3, uint32_t a4);
FnInitGameSession g_orig_init_game_session = nullptr;

void* __fastcall Hook_CreateGameEngine(void* host) {
    void* engine = g_orig_create_game_engine(host);
    CE4P_LOG_INFO(
        "[H1] CreateGameEngine(host=0x%llX) -> engine=0x%llX",
        reinterpret_cast<unsigned long long>(host),
        reinterpret_cast<unsigned long long>(engine)
    );
    return engine;
}

uint64_t __fastcall Hook_InitGameSession(void* a1, void* a2, void* a3, uint32_t a4) {
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
