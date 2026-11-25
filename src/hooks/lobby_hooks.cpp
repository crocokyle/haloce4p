#include "hooks/lobby_hooks.hpp"

#include "core/hook_manager.hpp"
#include "core/logger.hpp"
#include "core/memory_patch.hpp"
#include "core/pattern_scanner.hpp"

#include <cstdint>
#include <mutex>

namespace ce4p::lobby {

namespace {

// MCC-Win64-Shipping.exe: DeserializeGameDef (Mod manifest / GameDef JSON)
constexpr const char* kSigCampaignMaxPlayersCheck =
    "48 89 5C 24 18 48 89 74 24 20 57 48 83 EC 30 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 28 48 8B FA 48 8B D9 4C 8B C1 48 8D 15";

// MCC-Win64-Shipping.exe: GetGameInstance(uint32_t engine_id) @ 0x1401E2CCC
constexpr const char* kSigGetGameInstance =
    "4C 8B DC 49 89 5B 10 57 48 83 EC 40 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 30 44 8B C9 33 FF 48 8B 0D";

constexpr const char* kSigLaunchSettingsPlayerCount = "";
constexpr const char* kSigLobbyReadyValidation = "";

constexpr size_t kVtableIdxGetMaxCampaignPlayers = 0x238 / 8;

PatchRegistry g_lobby_patches;
std::mutex g_lobby_mutex;
int g_target_max_players = 4;

void* g_halo1_instance = nullptr;
uintptr_t g_hooked_get_max_campaign_players = 0;

using FnDeserializeGameDef = bool(__fastcall*)(void* def, void* json);
FnDeserializeGameDef g_orig_deserialize_game_def = nullptr;

using FnGetGameInstance = void*(__fastcall*)(uint32_t engine_id);
FnGetGameInstance g_orig_get_game_instance = nullptr;

using FnGetMaxCampaignPlayers = int(__fastcall*)(void* self);
FnGetMaxCampaignPlayers g_orig_get_max_campaign_players = nullptr;

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

int __fastcall Hook_GetMaxCampaignPlayers(void* self) {
    int orig = g_orig_get_max_campaign_players(self);
    if (self == g_halo1_instance && orig < g_target_max_players) {
        static bool logged_override = false;
        if (!logged_override) {
            logged_override = true;
            CE4P_LOG_INFO(
                "[Lobby] Halo1 GetMaxCampaignPlayers(self=0x%llX): %d -> %d",
                reinterpret_cast<unsigned long long>(self),
                orig,
                g_target_max_players
            );
        }
        return g_target_max_players;
    }
    return orig;
}

void* __fastcall Hook_GetGameInstance(uint32_t engine_id) {
    void* inst = g_orig_get_game_instance(engine_id);
    if (inst && engine_id == 0) {
        std::lock_guard<std::mutex> lock(g_lobby_mutex);
        if (!g_halo1_instance) {
            g_halo1_instance = inst;
            uintptr_t* vtable = *reinterpret_cast<uintptr_t**>(inst);
            uintptr_t fn_addr = vtable[kVtableIdxGetMaxCampaignPlayers];
            CE4P_LOG_INFO(
                "[Lobby] Captured Halo1 GameInstance @ 0x%llX (GetMaxCampaignPlayers @ 0x%llX)",
                reinterpret_cast<unsigned long long>(inst),
                static_cast<unsigned long long>(fn_addr)
            );
            if (!g_hooked_get_max_campaign_players && fn_addr) {
                if (HookManager::Instance().InstallHook(
                        "Halo1::GetMaxCampaignPlayers",
                        fn_addr,
                        reinterpret_cast<void*>(&Hook_GetMaxCampaignPlayers),
                        reinterpret_cast<void**>(&g_orig_get_max_campaign_players)
                    )) {
                    g_hooked_get_max_campaign_players = fn_addr;
                }
            }
        }
    }
    return inst;
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

    if (auto addr = ProbePattern(*mcc_span, config, "GetGameInstance", kSigGetGameInstance)) {
        if (!g_orig_get_game_instance) {
            HookManager::Instance().InstallHook(
                "MCC::GetGameInstance",
                *addr,
                reinterpret_cast<void*>(&Hook_GetGameInstance),
                reinterpret_cast<void**>(&g_orig_get_game_instance)
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
