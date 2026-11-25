#include "hooks/lobby_hooks.hpp"

#include "core/hook_manager.hpp"
#include "core/logger.hpp"
#include "core/memory_patch.hpp"
#include "core/pattern_scanner.hpp"

#include <cstdint>

namespace ce4p::lobby {

namespace {

// MCC-Win64-Shipping.exe: DeserializeGameDef (reads MaxCampaignPlayersOverride into def+0x50)
constexpr const char* kSigCampaignMaxPlayersCheck =
    "48 89 5C 24 18 48 89 74 24 20 57 48 83 EC 30 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 28 48 8B FA 48 8B D9 4C 8B C1 48 8D 15";
constexpr const char* kSigLaunchSettingsPlayerCount = "";
constexpr const char* kSigLobbyReadyValidation = "";

PatchRegistry g_lobby_patches;
int g_target_max_players = 4;

using FnDeserializeGameDef = bool(__fastcall*)(void* def, void* json);
FnDeserializeGameDef g_orig_deserialize_game_def = nullptr;

bool __fastcall Hook_DeserializeGameDef(void* def, void* json) {
    bool ok = g_orig_deserialize_game_def(def, json);
    if (ok && def) {
        auto* max_campaign_players = reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(def) + 0x50);
        uint32_t orig_val = *max_campaign_players;
        if (orig_val < static_cast<uint32_t>(g_target_max_players)) {
            *max_campaign_players = static_cast<uint32_t>(g_target_max_players);
        }
        CE4P_LOG_INFO(
            "[Lobby] DeserializeGameDef(def=0x%llX): MaxCampaignPlayersOverride %u -> %u",
            reinterpret_cast<unsigned long long>(def),
            orig_val,
            *max_campaign_players
        );
    }
    return ok;
}

std::optional<uintptr_t> ProbePattern(MemorySpan span, const ModConfig& config, const char* key, const char* fallback) {
    std::string pattern = config.GetSignature(key, fallback);
    if (pattern.empty()) {
        CE4P_LOG_DEBUG("[Lobby] Signature '%s' not yet populated.", key);
        return std::nullopt;
    }
    auto match = FindPattern(span, pattern);
    if (match.has_value()) {
        CE4P_LOG_INFO("[Lobby] Found '%s' @ 0x%llX", key, static_cast<unsigned long long>(*match));
    } else {
        CE4P_LOG_WARN("[Lobby] Pattern NOT found for '%s'.", key);
    }
    return match;
}

}  // namespace

bool Initialize(const ModConfig& config) {
    g_target_max_players = config.target_max_players;
    Rescan(config);
    return true;
}

void Rescan(const ModConfig& config) {
    g_target_max_players = config.target_max_players;

    auto mcc_span = GetModuleTextSpan(nullptr);
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

    if (auto addr = ProbePattern(*mcc_span, config, "CampaignMaxPlayersCheck", kSigCampaignMaxPlayersCheck)) {
        if (!g_orig_deserialize_game_def) {
            HookManager::Instance().InstallHook(
                "DeserializeGameDef",
                *addr,
                reinterpret_cast<void*>(&Hook_DeserializeGameDef),
                reinterpret_cast<void**>(&g_orig_deserialize_game_def)
            );
        }
    }

    ProbePattern(*mcc_span, config, "LaunchSettingsPlayerCount", kSigLaunchSettingsPlayerCount);
    ProbePattern(*mcc_span, config, "LobbyReadyValidation", kSigLobbyReadyValidation);
}

void Shutdown() {
    g_lobby_patches.RevertAll();
    CE4P_LOG_INFO("[Lobby] Shut down lobby hooks.");
}

}  // namespace ce4p::lobby
