#include "hooks/h1_engine_hooks.hpp"

#include "core/logger.hpp"
#include "core/memory_patch.hpp"
#include "core/pattern_scanner.hpp"

#include <mutex>
#include <optional>

namespace ce4p::h1 {

namespace {

std::mutex g_state_mutex;
std::optional<ModuleSnapshot> g_active_snapshot;
PatchRegistry g_h1_patches;

void ProbePattern(MemorySpan span, const ModConfig& config, const char* key) {
    std::string pattern = config.GetSignature(key, "");
    if (pattern.empty()) {
        CE4P_LOG_DEBUG("[H1] Signature '%s' not yet populated.", key);
        return;
    }
    auto match = FindPattern(span, pattern);
    if (match.has_value()) {
        CE4P_LOG_INFO("[H1] Found '%s' @ 0x%llX", key, static_cast<unsigned long long>(*match));
    } else {
        CE4P_LOG_WARN("[H1] Pattern NOT found for '%s'.", key);
    }
}

void ScanSnapshot(const ModuleSnapshot& snapshot, const ModConfig& config) {
    MemorySpan span{
        reinterpret_cast<const uint8_t*>(snapshot.base),
        snapshot.size,
    };

    CE4P_LOG_INFO(
        "[H1] Probing halo1.dll (timestamp=0x%08X, spawn_cloning=%s, radius=%.2f)...",
        snapshot.pe_timestamp,
        config.enable_spawn_cloning ? "on" : "off",
        config.spawn_clone_radius
    );

    ProbePattern(span, config, "CampaignPlayerCap");
    ProbePattern(span, config, "LockstepInputBuffer");
    ProbePattern(span, config, "GameCreatePlayer");
    ProbePattern(span, config, "CoopRespawnCheck");
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
