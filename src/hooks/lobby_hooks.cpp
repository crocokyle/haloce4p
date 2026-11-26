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
// MCC-Win64-Shipping.exe: Halo1 IGameHost::Notify (+0x18) @ 0x1401E65B4
constexpr const char* kSigGHNotify =
    "48 8B C4 57 48 83 EC 30 48 C7 40 E8 FE FF FF FF 48 89 58 08 48 89 68 18 48 89 70 20 8B F2 48 8D 2D 17 4A D9";
// MCC-Win64-Shipping.exe: Halo1 IGameHost::OnGameExit (+0x20) @ 0x1401E6424
constexpr const char* kSigGHOnGameExit =
    "48 8B C4 55 56 57 48 8B EC 48 81 EC 80 00 00 00 48 C7 45 B0 FE FF FF FF 48 89 58 20 48 8B 05 11 69 A9 03 48";
// MCC-Win64-Shipping.exe: Halo1 IGameHost::UpdateProgress (+0xB8) @ 0x1401E8C6C
constexpr const char* kSigGHUpdateProgress =
    "40 53 48 83 EC 30 48 8B 05 DF 89 E1 03 8B DA 0F 29 74 24 20 0F 28 F2 48";
// MCC-Win64-Shipping.exe: Halo1 IGameHost::SendP2PUnreliable (+0x148) @ 0x1401EA298
constexpr const char* kSigGHSendP2PUnreliable =
    "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 41 8B F9 49 8B F0 48 8B DA E8 8F 94 28 00";
// MCC-Win64-Shipping.exe: Halo1 IGameHost::SendP2P (+0x150) @ 0x1401EA2E4
constexpr const char* kSigGHSendP2P =
    "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 41 8B F9 49 8B F0 48 8B DA E8 43 94 28 00";
// MCC-Win64-Shipping.exe: Halo1 IGameHost::RecvP2P (+0x158) @ 0x1401EA334
constexpr const char* kSigGHRecvP2P =
    "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 49 8B D9 41 8B F8 48 8B F2 E8 F3 93 28 00";

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

using FnGHNotify = void(__fastcall*)(void* self, uint32_t code, uint64_t a3, uint64_t a4);
FnGHNotify g_orig_gh_notify = nullptr;

using FnGHOnGameExit = void(__fastcall*)(void* self, uint32_t code, uint64_t a3);
FnGHOnGameExit g_orig_gh_exit = nullptr;

using FnGHUpdateProgress = void(__fastcall*)(void* self, uint32_t state, float progress);
FnGHUpdateProgress g_orig_gh_progress = nullptr;

using FnGHSendP2P = int(__fastcall*)(void* self, uint64_t peer_or_type, const void* buf, uint32_t len, uint32_t port);
FnGHSendP2P g_orig_gh_send_p2p = nullptr;
FnGHSendP2P g_orig_gh_send_p2p_unrel = nullptr;

using FnGHRecvP2P = int(__fastcall*)(void* self, void* buf, uint32_t len, uint64_t* out_peer_id, uint32_t port);
FnGHRecvP2P g_orig_gh_recv_p2p = nullptr;

uint32_t g_last_gh_progress_state = 0xFFFFFFFFu;
std::mutex g_p2p_log_mutex;
uint64_t g_seen_p2p_keys[64]{};
size_t g_seen_p2p_count = 0;

bool RecordP2PKey(uint64_t key) {
    std::lock_guard<std::mutex> lock(g_p2p_log_mutex);
    for (size_t i = 0; i < g_seen_p2p_count; ++i) {
        if (g_seen_p2p_keys[i] == key) {
            return false;
        }
    }
    if (g_seen_p2p_count < 64) {
        g_seen_p2p_keys[g_seen_p2p_count++] = key;
    }
    return true;
}

int __fastcall Hook_GHSendP2P(void* self, uint64_t peer_or_type, const void* buf, uint32_t len, uint32_t port) {
    int ret = g_orig_gh_send_p2p(self, peer_or_type, buf, len, port);
    uint64_t key = (0x1ull << 62) ^ (peer_or_type * 0x9E3779B97F4A7C15ull) ^
                   (static_cast<uint64_t>(port) << 16) ^ (ret >= 0 ? 1ull : 0ull);
    if (RecordP2PKey(key)) {
        CE4P_LOG_INFO(
            "[IGameHost] SendP2P(arg2=0x%llX, len=%u, port=%u) -> ret=%d",
            static_cast<unsigned long long>(peer_or_type),
            len,
            port,
            ret
        );
    }
    return ret;
}

int __fastcall Hook_GHSendP2PUnrel(void* self, uint64_t peer_or_type, const void* buf, uint32_t len, uint32_t port) {
    int ret = g_orig_gh_send_p2p_unrel(self, peer_or_type, buf, len, port);
    uint64_t key = (0x3ull << 62) ^ (peer_or_type * 0x9E3779B97F4A7C15ull) ^
                   (static_cast<uint64_t>(port) << 16) ^ (ret >= 0 ? 1ull : 0ull) ^
                   (port == 1002 ? (static_cast<uint64_t>(len) << 32) : 0ull);
    if (RecordP2PKey(key)) {
        CE4P_LOG_INFO(
            "[IGameHost] SendP2PUnrel(arg2=0x%llX, len=%u, port=%u) -> ret=%d",
            static_cast<unsigned long long>(peer_or_type),
            len,
            port,
            ret
        );
        if (port == 1002 && len >= 100 && buf) {
            const auto* b = static_cast<const uint8_t*>(buf);
            uint32_t n = len < 16 ? len : 16;
            char hexbuf[64]{};
            for (uint32_t i = 0; i < n; ++i) {
                snprintf(hexbuf + i * 3, 4, "%02X ", b[i]);
            }
            HMODULE h1 = GetModuleHandleA("halo1.dll");
            uintptr_t h1_base = reinterpret_cast<uintptr_t>(h1);
            void* frames[10]{};
            USHORT fc = CaptureStackBackTrace(1, 10, frames, nullptr);
            CE4P_LOG_INFO("[IGameHost] SendP2PUnrel hdr=[%s] h1=0x%llX", hexbuf, static_cast<unsigned long long>(h1_base));
            for (USHORT i = 0; i < fc; ++i) {
                uintptr_t a = reinterpret_cast<uintptr_t>(frames[i]);
                if (h1_base && a >= h1_base && a < h1_base + 0x4000000) {
                    CE4P_LOG_INFO("[IGameHost]   stk[%u] -> halo1+0x%llX", static_cast<unsigned>(i),
                                  static_cast<unsigned long long>(a - h1_base));
                }
            }
        }
    }
    return ret;
}

int __fastcall Hook_GHRecvP2P(void* self, void* buf, uint32_t len, uint64_t* out_peer_id, uint32_t port) {
    int ret = g_orig_gh_recv_p2p(self, buf, len, out_peer_id, port);
    if (ret > 0) {
        uint64_t peer = out_peer_id ? *out_peer_id : 0;
        uint64_t key = (0x2ull << 62) ^ (peer * 0x9E3779B97F4A7C15ull) ^
                       (static_cast<uint64_t>(port) << 16) ^
                       (port == 1002 ? (static_cast<uint64_t>(ret) << 32) : 0ull);
        if (RecordP2PKey(key)) {
            CE4P_LOG_INFO(
                "[IGameHost] RecvP2P(port=%u, len=%u) -> ret=%d, peer_id=0x%llX",
                port,
                len,
                ret,
                static_cast<unsigned long long>(peer)
            );
        }
    }
    return ret;
}

void __fastcall Hook_GHNotify(void* self, uint32_t code, uint64_t a3, uint64_t a4) {
    CE4P_LOG_INFO(
        "[IGameHost] Notify(code=%u, a3=0x%llX, a4=0x%llX)",
        code,
        static_cast<unsigned long long>(a3),
        static_cast<unsigned long long>(a4)
    );
    g_orig_gh_notify(self, code, a3, a4);
}

void __fastcall Hook_GHOnGameExit(void* self, uint32_t code, uint64_t a3) {
    CE4P_LOG_INFO(
        "[IGameHost] OnGameExit(code=%u, a3=0x%llX)",
        code,
        static_cast<unsigned long long>(a3)
    );
    g_orig_gh_exit(self, code, a3);
}

void __fastcall Hook_GHUpdateProgress(void* self, uint32_t state, float progress) {
    if (state != g_last_gh_progress_state) {
        g_last_gh_progress_state = state;
        CE4P_LOG_INFO("[IGameHost] UpdateProgress(state=%u, progress=%.2f)", state, progress);
    }
    g_orig_gh_progress(self, state, progress);
}

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

    if (auto addr = ProbePattern(*mcc_span, config, "GHNotify", kSigGHNotify)) {
        if (!g_orig_gh_notify) {
            HookManager::Instance().InstallHook(
                "IGameHost::Notify",
                *addr,
                reinterpret_cast<void*>(&Hook_GHNotify),
                reinterpret_cast<void**>(&g_orig_gh_notify)
            );
        }
    }

    if (auto addr = ProbePattern(*mcc_span, config, "GHOnGameExit", kSigGHOnGameExit)) {
        if (!g_orig_gh_exit) {
            HookManager::Instance().InstallHook(
                "IGameHost::OnGameExit",
                *addr,
                reinterpret_cast<void*>(&Hook_GHOnGameExit),
                reinterpret_cast<void**>(&g_orig_gh_exit)
            );
        }
    }

    if (auto addr = ProbePattern(*mcc_span, config, "GHUpdateProgress", kSigGHUpdateProgress)) {
        if (!g_orig_gh_progress) {
            HookManager::Instance().InstallHook(
                "IGameHost::UpdateProgress",
                *addr,
                reinterpret_cast<void*>(&Hook_GHUpdateProgress),
                reinterpret_cast<void**>(&g_orig_gh_progress)
            );
        }
    }

    if (auto addr = ProbePattern(*mcc_span, config, "GHSendP2PUnrel", kSigGHSendP2PUnreliable)) {
        if (!g_orig_gh_send_p2p_unrel) {
            HookManager::Instance().InstallHook(
                "IGameHost::SendP2PUnrel",
                *addr,
                reinterpret_cast<void*>(&Hook_GHSendP2PUnrel),
                reinterpret_cast<void**>(&g_orig_gh_send_p2p_unrel)
            );
        }
    }

    if (auto addr = ProbePattern(*mcc_span, config, "GHSendP2P", kSigGHSendP2P)) {
        if (!g_orig_gh_send_p2p) {
            HookManager::Instance().InstallHook(
                "IGameHost::SendP2P",
                *addr,
                reinterpret_cast<void*>(&Hook_GHSendP2P),
                reinterpret_cast<void**>(&g_orig_gh_send_p2p)
            );
        }
    }

    if (auto addr = ProbePattern(*mcc_span, config, "GHRecvP2P", kSigGHRecvP2P)) {
        if (!g_orig_gh_recv_p2p) {
            HookManager::Instance().InstallHook(
                "IGameHost::RecvP2P",
                *addr,
                reinterpret_cast<void*>(&Hook_GHRecvP2P),
                reinterpret_cast<void**>(&g_orig_gh_recv_p2p)
            );
        }
    }
}

void Shutdown() {
    g_lobby_patches.RevertAll();
    CE4P_LOG_INFO("[Lobby] Shut down lobby hooks.");
}

}  // namespace ce4p::lobby
