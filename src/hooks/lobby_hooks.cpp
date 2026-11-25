#include "hooks/lobby_hooks.hpp"

#include "core/logger.hpp"
#include "core/memory_patch.hpp"
#include "core/pattern_scanner.hpp"

namespace ce4p::lobby {

namespace {

constexpr const char* kSigCampaignMaxPlayersCheck = "";
constexpr const char* kSigLaunchSettingsPlayerCount = "";
constexpr const char* kSigLobbyReadyValidation = "";

PatchRegistry g_lobby_patches;

void ProbePattern(MemorySpan span, const ModConfig& config, const char* key) {
    std::string pattern = config.GetSignature(key, "");
    if (pattern.empty()) {
        CE4P_LOG_DEBUG("[Lobby] Signature '%s' not yet populated.", key);
        return;
    }
    auto match = FindPattern(span, pattern);
    if (match.has_value()) {
        CE4P_LOG_INFO("[Lobby] Found '%s' @ 0x%llX", key, static_cast<unsigned long long>(*match));
    } else {
        CE4P_LOG_WARN("[Lobby] Pattern NOT found for '%s'.", key);
    }
}

}  // namespace

bool Initialize(const ModConfig& config) {
    Rescan(config);
    return true;
}

void Rescan(const ModConfig& config) {
    auto mcc_span = GetModuleSpan(nullptr);
    if (!mcc_span.has_value()) {
        CE4P_LOG_ERROR("[Lobby] Failed to resolve main module span (MCC-Win64-Shipping.exe).");
        return;
    }

    CE4P_LOG_INFO(
        "[Lobby] Main module @ 0x%llX (size=0x%zX, target_players=%d)",
        reinterpret_cast<unsigned long long>(mcc_span->data),
        mcc_span->size,
        config.target_max_players
    );

    ProbePattern(*mcc_span, config, "CampaignMaxPlayersCheck");
    ProbePattern(*mcc_span, config, "LaunchSettingsPlayerCount");
    ProbePattern(*mcc_span, config, "LobbyReadyValidation");
}

void Shutdown() {
    g_lobby_patches.RevertAll();
    CE4P_LOG_INFO("[Lobby] Shut down lobby hooks.");
}

}  // namespace ce4p::lobby
