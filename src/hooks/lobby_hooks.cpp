#include "hooks/lobby_hooks.hpp"

#include <windows.h>

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
// MCC-Win64-Shipping.exe: $DIALOG_TOO_MANY_REMOTE_PLAYERS gate @ 0x1404B27BF
// At +0x2E (0x1404B27ED): `83 3D 36 EF B4 03 02` (cmp dword ptr [global], 2)
constexpr const char* kSigLobbyReadyValidation = "83 FD 01 76 1E 83 FE 02 76 10";
// MCC-Win64-Shipping.exe: secondary engine_id <= 1 cap @ 0x1404BAE13 (inside 0x1404BAD04)
// At +0x2E (0x1404BAE41): `41 83 FE 02` (cmp r14d, 2)
constexpr const char* kSigLobbySecondaryCap =
    "41 83 FF 01 76 1F 45 84 E4 75 1A 41 83 FD 02 77 20 41 83 FE 04";
// MCC-Win64-Shipping.exe: Squad::GetTotalPlayerCount() @ 0x14025119C
constexpr const char* kSigGetTotalPlayerCount =
    "40 53 48 83 EC 20 48 8B D9 48 8B 0D ? ? ? ? E8 ? ? ? ? 8B 8B 20 0D 00 00 3B C1 0F 47 C8 8B C1";
// MCC-Win64-Shipping.exe: ShowConnectionLostDialog(rcx) @ 0x14039CA4C
constexpr const char* kSigShowConnectionLostDialog =
    "40 53 48 83 EC 30 8B 51 24 48 8B D9 83 EA 01 74 29 83 FA 01 75 62 45 33";
// MCC-Win64-Shipping.exe: OnGameEngineExit(rcx, dl) @ 0x14039CAD0
constexpr const char* kSigOnGameEngineExit =
    "48 89 5C 24 08 57 48 83 EC 30 83 79 20 07 40 8A FA 48 8B D9 0F 84 BB 00";

constexpr size_t kVtableIdxGetMaxCampaignPlayers = 0x238 / 8;

PatchRegistry g_lobby_patches;
std::mutex g_lobby_mutex;
int g_target_max_players = 4;
int g_force_test_party_size = 0;
bool g_logged_party_size_spoof = false;

void* g_halo1_instance = nullptr;
uintptr_t g_hooked_get_max_campaign_players = 0;

using FnDeserializeGameDef = bool(__fastcall*)(void* def, void* json);
FnDeserializeGameDef g_orig_deserialize_game_def = nullptr;

using FnGetGameInstance = void*(__fastcall*)(uint32_t engine_id);
FnGetGameInstance g_orig_get_game_instance = nullptr;

using FnGetMaxCampaignPlayers = int(__fastcall*)(void* self);
FnGetMaxCampaignPlayers g_orig_get_max_campaign_players = nullptr;

using FnGetTotalPlayerCount = uint32_t(__fastcall*)(void* squad);
FnGetTotalPlayerCount g_orig_get_total_player_count = nullptr;

using FnShowConnectionLostDialog = void(__fastcall*)(const uint8_t* session_ui);
FnShowConnectionLostDialog g_orig_show_connection_lost = nullptr;

using FnOnGameEngineExit = void(__fastcall*)(const uint8_t* session_ui, uint8_t flag);
FnOnGameEngineExit g_orig_on_game_engine_exit = nullptr;

void __fastcall Hook_ShowConnectionLostDialog(const uint8_t* session_ui) {
    uint32_t state = session_ui ? *reinterpret_cast<const uint32_t*>(session_ui + 0x20) : 0;
    uint32_t reason = session_ui ? *reinterpret_cast<const uint32_t*>(session_ui + 0x24) : 0;
    CE4P_LOG_WARN("[Lobby] ShowConnectionLostDialog(reason=%u, state=%u)", reason, state);
    g_orig_show_connection_lost(session_ui);
}

void __fastcall Hook_OnGameEngineExit(const uint8_t* session_ui, uint8_t flag) {
    uint32_t state = session_ui ? *reinterpret_cast<const uint32_t*>(session_ui + 0x20) : 0;
    uint32_t reason = session_ui ? *reinterpret_cast<const uint32_t*>(session_ui + 0x24) : 0;
    CE4P_LOG_INFO("[Lobby] OnGameEngineExit(flag=%u, state=%u, reason=%u)", flag, state, reason);
    g_orig_on_game_engine_exit(session_ui, flag);
}

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
            CE4P_LOG_INFO(
                "[Lobby] Captured Halo1 GameContext @ 0x%llX",
                reinterpret_cast<unsigned long long>(inst)
            );
        }
    }
    return inst;
}

uint32_t __fastcall Hook_GetTotalPlayerCount(void* squad) {
    uint32_t real_count = g_orig_get_total_player_count(squad);
    if (g_force_test_party_size > 0) {
        if (!g_logged_party_size_spoof) {
            g_logged_party_size_spoof = true;
            CE4P_LOG_INFO(
                "[Lobby] Spoofing Squad::GetTotalPlayerCount(): real=%u -> forced=%d",
                real_count,
                g_force_test_party_size
            );
        }
        return static_cast<uint32_t>(g_force_test_party_size);
    }
    return real_count;
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
    g_force_test_party_size = config.force_test_party_size;

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

    if (auto addr = ProbePattern(*mcc_span, config, "LobbyReadyValidation", kSigLobbyReadyValidation)) {
        // Patch `83 3D 36 EF B4 03 02` (cmp dword ptr [global], 2) -> target_max_players
        g_lobby_patches.PatchByte(
            "LobbyRemotePlayerCap",
            *addr + 0x2E,
            static_cast<uint8_t>(config.target_max_players)
        );
    }

    if (auto addr = ProbePattern(*mcc_span, config, "LobbySecondaryCap", kSigLobbySecondaryCap)) {
        // Patch `41 83 FE 02` (cmp r14d, 2) -> target_max_players
        g_lobby_patches.PatchByte(
            "LobbySecondaryPlayerCap",
            *addr + 0x2E,
            static_cast<uint8_t>(config.target_max_players)
        );
    }

    if (auto addr = ProbePattern(*mcc_span, config, "GetTotalPlayerCount", kSigGetTotalPlayerCount)) {
        if (!g_orig_get_total_player_count) {
            HookManager::Instance().InstallHook(
                "Squad::GetTotalPlayerCount",
                *addr,
                reinterpret_cast<void*>(&Hook_GetTotalPlayerCount),
                reinterpret_cast<void**>(&g_orig_get_total_player_count)
            );
        }
    }

    if (auto addr = ProbePattern(*mcc_span, config, "ShowConnectionLostDialog", kSigShowConnectionLostDialog)) {
        if (!g_orig_show_connection_lost) {
            HookManager::Instance().InstallHook(
                "MCC::ShowConnectionLostDialog",
                *addr,
                reinterpret_cast<void*>(&Hook_ShowConnectionLostDialog),
                reinterpret_cast<void**>(&g_orig_show_connection_lost)
            );
        }
    }

    if (auto addr = ProbePattern(*mcc_span, config, "OnGameEngineExit", kSigOnGameEngineExit)) {
        if (!g_orig_on_game_engine_exit) {
            HookManager::Instance().InstallHook(
                "MCC::OnGameEngineExit",
                *addr,
                reinterpret_cast<void*>(&Hook_OnGameEngineExit),
                reinterpret_cast<void**>(&g_orig_on_game_engine_exit)
            );
        }
    }
}

void Shutdown() {
    g_lobby_patches.RevertAll();
    CE4P_LOG_INFO("[Lobby] Shut down lobby hooks.");
}

}  // namespace ce4p::lobby
