#include "hooks/h1_engine_hooks.hpp"

#include "core/logger.hpp"
#include "core/memory_patch.hpp"
#include "core/pattern_scanner.hpp"

#include <mutex>
#include <optional>

namespace ce4p::h1 {

namespace {

// halo1.dll: Co-op/local player count cap in game initialization.
// 75 08 41 83 FD [02] 7F 08 EB 28 41 83 FD 04 7E 22
// At +5 is the immediate `2` in `cmp r13d, 2` for campaign mode.
constexpr const char* kSigCampaignPlayerCap =
    "75 08 41 83 FD 02 7F 08 EB 28 41 83 FD 04 7E 22";
constexpr const char* kSigLockstepInputBuffer = "";
constexpr const char* kSigGameCreatePlayer = "";
constexpr const char* kSigCoopRespawnCheck = "";

std::mutex g_state_mutex;
std::optional<ModuleSnapshot> g_active_snapshot;
PatchRegistry g_h1_patches;

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
    g_h1_patches.RevertAll();
    g_active_snapshot.reset();
    CE4P_LOG_INFO("[H1] Cleaned up halo1.dll hooks and patches.");
}

}  // namespace ce4p::h1
