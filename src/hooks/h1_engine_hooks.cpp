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

// halo1.dll: GetNetworkSessionInfo @ 0x180BE9448 (loads c_network_session* at +0x11)
constexpr const char* kSigNetworkSession =
    "4C 8B DC 48 83 EC 68 33 C0 38 05 ? ? ? ? 74 66 48 8B 0D";

// halo1.dll: Co-op client handshake state machine @ 0x180AEEDD4 (loads client* at +0x04)
constexpr const char* kSigClientHandshakeTick =
    "48 83 EC 28 48 8B 0D ? ? ? ? 45 33 C0 0F B7 91 6E 14 00 00 85 D2 74";

// halo1.dll: Co-op host accept new client @ 0x180B5BED8
constexpr const char* kSigServerAcceptClient =
    "48 89 5C 24 18 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 50 48 8B 05";

// halo1.dll: Co-op host validate client @ 0x180B5BDCC
constexpr const char* kSigServerValidateClient =
    "48 89 5C 24 08 57 48 83 EC 20 33 DB 48 8B F9 48 85 D2 74 05 48 8B 0A EB";

// halo1.dll: MatchMake_campaign_net @ 0x180065F70 (loads net_active at +0x42, is_host at +0x4F)
constexpr const char* kSigMatchMakeCampaignNet =
    "48 8B C4 55 41 54 41 55 41 56 41 57 48 8D A8 C8 FC FF FF 48 81 EC 10 04 00 00 "
    "48 C7 45 18 FE FF FF FF 48 89 58 08 48 89 70 18 48 89 78 20 "
    "48 8B 05 ? ? ? ? 48 33 C4 48 89 85 00 03 00 00 48 8B DA "
    "83 3D ? ? ? ? 00 0F 84 ? ? ? ? 83 3D ? ? ? ? 00 41 0F 95 C5";

// halo1.dll: MatchMake_campaign_net peer channel wait cap @ 0x1800664BC
// 83 BF 28 01 00 00 [02] 0F 8D -> cmp dword ptr [rdi+0x128], 2; jge ...
constexpr const char* kSigMatchMakePeerCap =
    "83 BF 28 01 00 00 02 0F 8D";

// halo1.dll: Transport channel cap @ 0x1802284BF (gates 0x180227ED0 PlayerUID/session tick)
// 83 BA 28 01 00 00 [02] 7D 0F -> cmp dword ptr [rdx+0x128], 2; jge +0x0F
constexpr const char* kSigTransportAdvertCap =
    "83 BA 28 01 00 00 02 7D 0F";

// halo1.dll: HasChannelForSlot @ 0x1803F3290 (checks [transport+0x120] for slot key;
// buggy: checks `slot` instead of `slot * 2`, causing slot 2 to collide with slot 1's key 2)
constexpr const char* kSigHasChannelForSlot =
    "40 57 44 8B 81 28 01 00 00 33 FF 44 8B DA 44 8B CF 45 85 C0 74 5E 48 89";

constexpr const char* kSigLockstepInputBuffer = "";
constexpr const char* kSigGameCreatePlayer = "";
constexpr const char* kSigCoopRespawnCheck = "";

constexpr uintptr_t kRvaCoopPlayerCount = 0x01B7B910;
constexpr uintptr_t kRvaMccGameInterface = 0x02E3B9A0;
constexpr uintptr_t kRvaGameModeFlags = 0x02E3B821;
constexpr uintptr_t kRvaDisconnectReason = 0x02EA3358;
constexpr uintptr_t kRvaClientReadyFlag = 0x02EA33A7;
constexpr uintptr_t kRvaH1ServerPtr = 0x02EA33C0;
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
uintptr_t g_hooked_get_connected_peers = 0;
uintptr_t g_hooked_client_handshake = 0;
uintptr_t g_hooked_server_accept = 0;
uintptr_t g_hooked_server_validate = 0;
uintptr_t g_hooked_matchmake_campaign_net = 0;
uintptr_t g_hooked_has_channel_for_slot = 0;
uintptr_t g_matchmake_peer_cmp_addr = 0;
uintptr_t g_transport_advert_cmp_addr = 0;
int g_launch_expected_players = 0;

const uint32_t* g_net_active_ptr = nullptr;
const uint32_t* g_is_host_ptr = nullptr;
const uint8_t* const* g_players_array_ptr = nullptr;
const uint32_t* g_session_ready_flag_ptr = nullptr;
uint32_t g_last_session_ready_logged = 0xFFFFFFFFu;
const uint32_t* g_expected_peers_ptr = nullptr;
uint32_t g_last_connected_peers_logged = 0xFFFFFFFFu;
const uint8_t* const* g_network_session_ptr = nullptr;
uint32_t g_last_net_state_logged = 0xFFFFFFFFu;
uint32_t g_last_net_conn_logged = 0xFFFFFFFFu;
const uint8_t* const* g_h1_client_ptr = nullptr;
uint64_t g_last_client_hs_key = 0xFFFFFFFFFFFFFFFFull;

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

using FnMatchMakeCampaignNet = uint64_t(__fastcall*)(void* a1, void* a2, void* a3, void* a4);
FnMatchMakeCampaignNet g_orig_matchmake_campaign_net = nullptr;

using FnHasChannelForSlot = bool(__fastcall*)(void* transport, int32_t slot);
FnHasChannelForSlot g_orig_has_channel_for_slot = nullptr;

using FnSessionReadyCheck = void(__fastcall*)();
FnSessionReadyCheck g_orig_session_ready_check = nullptr;

using FnWaitForPeers = void(__fastcall*)();
FnWaitForPeers g_orig_wait_for_peers = nullptr;

using FnGetConnectedPeers = uint32_t(__fastcall*)();
FnGetConnectedPeers g_fn_get_connected_peers = nullptr;
FnGetConnectedPeers g_orig_get_connected_peers = nullptr;

using FnClientHandshakeTick = bool(__fastcall*)();
FnClientHandshakeTick g_orig_client_handshake = nullptr;

using FnServerAcceptClient = bool(__fastcall*)(const uint8_t* server, const void* peer_addr);
FnServerAcceptClient g_orig_server_accept = nullptr;

using FnServerValidateClient = bool(__fastcall*)(const uint8_t* server, const void* slot_ptr);
FnServerValidateClient g_orig_server_validate = nullptr;

int CountActiveServerSlots(const uint8_t* server) {
    if (!server) {
        return -1;
    }
    int active = 0;
    for (int i = 0; i < 17; ++i) {
        int16_t slot_id = *reinterpret_cast<const int16_t*>(server + 0xC60 + static_cast<size_t>(i) * 0x200);
        if (slot_id != -1) {
            ++active;
        }
    }
    return active;
}

bool __fastcall Hook_ClientHandshakeTick() {
    bool ok = g_orig_client_handshake();
    if (g_h1_client_ptr && g_h1_base) {
        const uint8_t* client = *g_h1_client_ptr;
        uint16_t state = client ? *reinterpret_cast<const uint16_t*>(client + 0x146E) : 0xFFFFu;
        uint16_t sub = client ? *reinterpret_cast<const uint16_t*>(client + 0x1470) : 0xFFFFu;
        uint8_t ready = *reinterpret_cast<const uint8_t*>(g_h1_base + kRvaClientReadyFlag);
        int16_t reason = *reinterpret_cast<const int16_t*>(g_h1_base + kRvaDisconnectReason);
        uint32_t conn_flags = 0;
        if (client) {
            const uint8_t* conn = *reinterpret_cast<const uint8_t* const*>(client + 0x7D8);
            if (conn) {
                conn_flags = *reinterpret_cast<const uint32_t*>(conn + 0x9DC);
            }
        }
        uint64_t key = (static_cast<uint64_t>(state) << 48) |
                       (static_cast<uint64_t>(sub) << 32) |
                       (static_cast<uint64_t>(static_cast<uint16_t>(reason)) << 16) |
                       (static_cast<uint64_t>(ready) << 8) |
                       (ok ? 1ull : 0ull);
        if (key != g_last_client_hs_key) {
            g_last_client_hs_key = key;
            CE4P_LOG_INFO(
                "[H1] ClientHandshake(state=%u, sub=%u, ready=%u, reason=%d, conn_flags=0x%X) -> ok=%d",
                state,
                sub,
                ready,
                static_cast<int>(reason),
                conn_flags,
                ok ? 1 : 0
            );
        }
    }
    return ok;
}

bool __fastcall Hook_ServerAcceptClient(const uint8_t* server, const void* peer_addr) {
    bool ok = g_orig_server_accept(server, peer_addr);
    uint16_t s_state = server ? *reinterpret_cast<const uint16_t*>(server + 0x08) : 0xFFFFu;
    uint8_t s_flags = server ? *reinterpret_cast<const uint8_t*>(server + 0x0A) : 0;
    int active = CountActiveServerSlots(server);
    CE4P_LOG_INFO(
        "[H1] ServerAcceptClient(peer=0x%llX) -> ok=%d, srv_state=%u, srv_flags=0x%02X, active_slots=%d",
        reinterpret_cast<unsigned long long>(peer_addr),
        ok ? 1 : 0,
        s_state,
        s_flags,
        active
    );
    return ok;
}

bool __fastcall Hook_ServerValidateClient(const uint8_t* server, const void* slot_ptr) {
    bool ok = g_orig_server_validate(server, slot_ptr);
    CE4P_LOG_INFO(
        "[H1] ServerValidateClient(slot=0x%llX) -> ok=%d",
        reinterpret_cast<unsigned long long>(slot_ptr),
        ok ? 1 : 0
    );
    return ok;
}

void __fastcall Hook_IGameEngineStart(void* self, void* mcc_iface, const uint8_t* launch_settings, void* a4) {
    if (launch_settings) {
        uint8_t f0 = launch_settings[0];
        uint8_t f2 = launch_settings[2];
        uint32_t mode = *reinterpret_cast<const uint32_t*>(launch_settings + 0x0C);
        int16_t map_id = *reinterpret_cast<const int16_t*>(launch_settings + 0x14);
        uint32_t submode = *reinterpret_cast<const uint32_t*>(launch_settings + 0xE8);
        uint32_t f2f0 = *reinterpret_cast<const uint32_t*>(launch_settings + 0x2F0);
        g_launch_expected_players = static_cast<int>(submode);
        CE4P_LOG_INFO(
            "[H1] IGameEngineStart(f0=0x%02X, f2=0x%02X, mode=%u, map_id=%d, +0xE8=%u, +0x2F0=%u)",
            f0, f2, mode, static_cast<int>(map_id), submode, f2f0
        );
    } else {
        g_launch_expected_players = 0;
        CE4P_LOG_INFO("[H1] IGameEngineStart(launch_settings=null)");
    }
    g_last_client_hs_key = 0xFFFFFFFFFFFFFFFFull;
    g_orig_engine_start(self, mcc_iface, launch_settings, a4);
}

void WritePeerCapByte(uintptr_t cmp_addr, uint8_t value) {
    if (!cmp_addr) {
        return;
    }
    auto* target = reinterpret_cast<uint8_t*>(cmp_addr + 6);
    if (*target == value) {
        return;
    }
    DWORD old_protect = 0;
    if (VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &old_protect)) {
        *target = value;
        DWORD dummy = 0;
        VirtualProtect(target, 1, old_protect, &dummy);
        FlushInstructionCache(GetCurrentProcess(), target, 1);
    }
}

bool __fastcall Hook_HasChannelForSlot(void* transport, int32_t slot) {
    // 0x1803F3750 inserts channels under key (slot * 2), whereas 0x1803F3290
    // looks up `slot` directly; pass `slot * 2` so slot 2 doesn't collide with slot 1.
    return g_orig_has_channel_for_slot(transport, slot * 2);
}

uint64_t __fastcall Hook_MatchMakeCampaignNet(void* a1, void* a2, void* a3, void* a4) {
    uint32_t net_active = g_net_active_ptr ? *g_net_active_ptr : 0;
    uint32_t is_host = g_is_host_ptr ? *g_is_host_ptr : 0;
    uint8_t desired = 2;
    if (is_host != 0 && net_active != 0 && g_launch_expected_players >= 2 && g_launch_expected_players <= 4) {
        desired = static_cast<uint8_t>(g_launch_expected_players);
    }
    WritePeerCapByte(g_matchmake_peer_cmp_addr, desired);
    WritePeerCapByte(g_transport_advert_cmp_addr, desired);
    CE4P_LOG_INFO(
        "[H1] MatchMake_campaign_net(is_host=%u, net_active=%u, launch_players=%d) -> wait_cap=%u",
        is_host,
        net_active,
        g_launch_expected_players,
        static_cast<unsigned>(desired)
    );
    uint64_t ret = g_orig_matchmake_campaign_net(a1, a2, a3, a4);
    int32_t t_count = -1;
    int32_t t0_chans = -1;
    int32_t t0_peers = -1;
    const uint8_t* sess = nullptr;
    if (g_h1_base) {
        const uint8_t* t_arr = *reinterpret_cast<const uint8_t* const*>(g_h1_base + 0x02E3CE50);
        if (t_arr) {
            t_count = *reinterpret_cast<const int32_t*>(t_arr + 0x18);
            if (t_count > 0) {
                const uint8_t* const* vec = *reinterpret_cast<const uint8_t* const* const*>(t_arr + 0x10);
                if (vec && vec[0]) {
                    t0_chans = *reinterpret_cast<const int32_t*>(vec[0] + 0x128);
                    sess = *reinterpret_cast<const uint8_t* const*>(vec[0] + 0x30);
                    if (sess) {
                        t0_peers = *reinterpret_cast<const int32_t*>(sess + 0x50);
                    }
                }
            }
        }
    }
    CE4P_LOG_INFO(
        "[H1] MatchMake_campaign_net returned (transports=%d, t0_chans=%d, t0_peers=%d)",
        t_count, t0_chans, t0_peers
    );
    if (sess && t0_chans != static_cast<int32_t>(desired)) {
        int32_t local_idx = *reinterpret_cast<const int32_t*>(sess + 0x30);
        int32_t host_idx = *reinterpret_cast<const int32_t*>(sess + 0x34);
        uint8_t f176 = *(sess + 0x176);
        uint8_t f177 = *(sess + 0x177);
        const int32_t* slots = reinterpret_cast<const int32_t*>(sess + 0x58);
        CE4P_LOG_INFO(
            "[H1] Session0: local=%d, host=%d, f176=%u, f177=%u, slots=[%d,%d,%d,%d]",
            local_idx, host_idx, f176, f177, slots[0], slots[1], slots[2], slots[3]
        );
        const uint8_t* peers = *reinterpret_cast<const uint8_t* const*>(sess + 0x48);
        if (peers && t0_peers > 0) {
            int n = t0_peers < 8 ? t0_peers : 8;
            for (int i = 0; i < n; ++i) {
                const uint8_t* p = peers + static_cast<size_t>(i) * 0x118;
                uint32_t pflags = *reinterpret_cast<const uint32_t*>(p);
                int32_t pslot = *reinterpret_cast<const int32_t*>(p + 0x08);
                uint64_t pmask = *reinterpret_cast<const uint64_t*>(p + 0x50);
                CE4P_LOG_INFO(
                    "[H1] Session0 peer[%d]: flags=0x%X, slot=%d, mask50=0x%llX",
                    i, pflags, pslot, static_cast<unsigned long long>(pmask)
                );
            }
        }
    }
    return ret;
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

uint32_t __fastcall Hook_GetConnectedPeers() {
    uint32_t conn = g_orig_get_connected_peers();
    if (g_network_session_ptr) {
        const uint8_t* sess = *g_network_session_ptr;
        if (sess) {
            uint32_t state = *reinterpret_cast<const uint32_t*>(sess + 0x324B0);
            if (state != g_last_net_state_logged || conn != g_last_net_conn_logged) {
                g_last_net_state_logged = state;
                g_last_net_conn_logged = conn;
                uint32_t val_3c = *reinterpret_cast<const uint32_t*>(sess + 0x3C);
                uint32_t val_40 = *reinterpret_cast<const uint32_t*>(sess + 0x40);
                uint32_t val_50 = *reinterpret_cast<const uint32_t*>(sess + 0x50);
                uint32_t mask_54 = *reinterpret_cast<const uint32_t*>(sess + 0x54);
                uint32_t peers_12f0 = *reinterpret_cast<const uint32_t*>(sess + 0x12F0);
                uint32_t max_12f4 = *reinterpret_cast<const uint32_t*>(sess + 0x12F4);
                CE4P_LOG_INFO(
                    "[H1] NetworkSession: state=%u, +0x3C=%u, +0x40=%u, +0x50=%u, mask=0x%X, +0x12F0=%u, +0x12F4=%u, conn=%u",
                    state, val_3c, val_40, val_50, mask_54, peers_12f0, max_12f4, conn
                );
            }
        }
    }
    return conn;
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
        const uint8_t* flags = reinterpret_cast<const uint8_t*>(g_h1_base + kRvaGameModeFlags);
        const uint8_t* srv = *reinterpret_cast<const uint8_t* const*>(g_h1_base + kRvaH1ServerPtr);
        uint16_t srv_state = srv ? *reinterpret_cast<const uint16_t*>(srv + 0x08) : 0xFFFFu;
        int srv_slots = CountActiveServerSlots(srv);
        CE4P_LOG_INFO(
            "[H1] InitGameSession(a4=%u) -> ret=0x%llX, local_players=%d, flags=[%u,%u,%u,%u], srv_state=%u, srv_slots=%d",
            a4,
            static_cast<unsigned long long>(ret),
            static_cast<int>(*coop_count),
            flags[0], flags[1], flags[2], flags[3],
            srv_state,
            srv_slots
        );
    }
    if (g_network_session_ptr) {
        const uint8_t* sess = *g_network_session_ptr;
        if (sess) {
            uint32_t state = *reinterpret_cast<const uint32_t*>(sess + 0x324B0);
            uint32_t val_3c = *reinterpret_cast<const uint32_t*>(sess + 0x3C);
            uint32_t val_40 = *reinterpret_cast<const uint32_t*>(sess + 0x40);
            uint32_t val_50 = *reinterpret_cast<const uint32_t*>(sess + 0x50);
            uint32_t mask_54 = *reinterpret_cast<const uint32_t*>(sess + 0x54);
            uint32_t peers_12f0 = *reinterpret_cast<const uint32_t*>(sess + 0x12F0);
            uint32_t max_12f4 = *reinterpret_cast<const uint32_t*>(sess + 0x12F4);
            uint32_t conn = g_fn_get_connected_peers ? g_fn_get_connected_peers() : 0xFFFFFFFFu;
            CE4P_LOG_INFO(
                "[H1] NetworkSession: state=%u, +0x3C=%u, +0x40=%u, +0x50=%u, mask=0x%X, +0x12F0=%u, +0x12F4=%u, conn=%u",
                state, val_3c, val_40, val_50, mask_54, peers_12f0, max_12f4, conn
            );
        }
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
                if (!g_hooked_get_connected_peers) {
                    if (HookManager::Instance().InstallHook(
                            "H1::GetConnectedPeers",
                            fn_peers,
                            reinterpret_cast<void*>(&Hook_GetConnectedPeers),
                            reinterpret_cast<void**>(&g_orig_get_connected_peers)
                        )) {
                        g_hooked_get_connected_peers = fn_peers;
                    }
                }
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

    if (!g_network_session_ptr) {
        if (auto addr = ProbePattern(span, config, "NetworkSession", kSigNetworkSession)) {
            if (uintptr_t sess_ptr = ResolveRipRelative(*addr + 0x11, 3, 7)) {
                g_network_session_ptr = reinterpret_cast<const uint8_t* const*>(sess_ptr);
            }
        }
    }

    if (!g_hooked_client_handshake) {
        if (auto addr = ProbePattern(span, config, "ClientHandshakeTick", kSigClientHandshakeTick)) {
            if (uintptr_t cli_ptr = ResolveRipRelative(*addr + 0x04, 3, 7)) {
                g_h1_client_ptr = reinterpret_cast<const uint8_t* const*>(cli_ptr);
            }
            if (HookManager::Instance().InstallHook(
                    "H1::ClientHandshakeTick",
                    *addr,
                    reinterpret_cast<void*>(&Hook_ClientHandshakeTick),
                    reinterpret_cast<void**>(&g_orig_client_handshake)
                )) {
                g_hooked_client_handshake = *addr;
            }
        }
    }

    if (!g_hooked_server_accept) {
        if (auto addr = ProbePattern(span, config, "ServerAcceptClient", kSigServerAcceptClient)) {
            if (HookManager::Instance().InstallHook(
                    "H1::ServerAcceptClient",
                    *addr,
                    reinterpret_cast<void*>(&Hook_ServerAcceptClient),
                    reinterpret_cast<void**>(&g_orig_server_accept)
                )) {
                g_hooked_server_accept = *addr;
            }
        }
    }

    if (!g_hooked_server_validate) {
        if (auto addr = ProbePattern(span, config, "ServerValidateClient", kSigServerValidateClient)) {
            if (HookManager::Instance().InstallHook(
                    "H1::ServerValidateClient",
                    *addr,
                    reinterpret_cast<void*>(&Hook_ServerValidateClient),
                    reinterpret_cast<void**>(&g_orig_server_validate)
                )) {
                g_hooked_server_validate = *addr;
            }
        }
    }

    if (!g_matchmake_peer_cmp_addr) {
        if (auto addr = ProbePattern(span, config, "MatchMakePeerCap", kSigMatchMakePeerCap)) {
            g_matchmake_peer_cmp_addr = *addr;
        }
    }

    if (!g_transport_advert_cmp_addr) {
        if (auto addr = ProbePattern(span, config, "TransportAdvertCap", kSigTransportAdvertCap)) {
            g_transport_advert_cmp_addr = *addr;
        }
    }

    if (!g_hooked_has_channel_for_slot) {
        if (auto addr = ProbePattern(span, config, "HasChannelForSlot", kSigHasChannelForSlot)) {
            if (HookManager::Instance().InstallHook(
                    "H1::HasChannelForSlot",
                    *addr,
                    reinterpret_cast<void*>(&Hook_HasChannelForSlot),
                    reinterpret_cast<void**>(&g_orig_has_channel_for_slot)
                )) {
                g_hooked_has_channel_for_slot = *addr;
            }
        }
    }

    if (!g_hooked_matchmake_campaign_net) {
        if (auto addr = ProbePattern(span, config, "MatchMakeCampaignNet", kSigMatchMakeCampaignNet)) {
            if (uintptr_t net_ptr = ResolveRipRelative(*addr + 0x42, 2, 7)) {
                g_net_active_ptr = reinterpret_cast<const uint32_t*>(net_ptr);
            }
            if (uintptr_t host_ptr = ResolveRipRelative(*addr + 0x4F, 2, 7)) {
                g_is_host_ptr = reinterpret_cast<const uint32_t*>(host_ptr);
            }
            if (HookManager::Instance().InstallHook(
                    "H1::MatchMakeCampaignNet",
                    *addr,
                    reinterpret_cast<void*>(&Hook_MatchMakeCampaignNet),
                    reinterpret_cast<void**>(&g_orig_matchmake_campaign_net)
                )) {
                g_hooked_matchmake_campaign_net = *addr;
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
    if (g_matchmake_peer_cmp_addr) {
        WritePeerCapByte(g_matchmake_peer_cmp_addr, 2);
        g_matchmake_peer_cmp_addr = 0;
    }
    if (g_transport_advert_cmp_addr) {
        WritePeerCapByte(g_transport_advert_cmp_addr, 2);
        g_transport_advert_cmp_addr = 0;
    }
    if (g_hooked_has_channel_for_slot) {
        HookManager::Instance().RemoveHook(g_hooked_has_channel_for_slot);
        g_hooked_has_channel_for_slot = 0;
        g_orig_has_channel_for_slot = nullptr;
    }
    if (g_hooked_matchmake_campaign_net) {
        HookManager::Instance().RemoveHook(g_hooked_matchmake_campaign_net);
        g_hooked_matchmake_campaign_net = 0;
        g_orig_matchmake_campaign_net = nullptr;
    }
    g_net_active_ptr = nullptr;
    g_is_host_ptr = nullptr;
    g_launch_expected_players = 0;
    if (g_hooked_server_validate) {
        HookManager::Instance().RemoveHook(g_hooked_server_validate);
        g_hooked_server_validate = 0;
        g_orig_server_validate = nullptr;
    }
    if (g_hooked_server_accept) {
        HookManager::Instance().RemoveHook(g_hooked_server_accept);
        g_hooked_server_accept = 0;
        g_orig_server_accept = nullptr;
    }
    if (g_hooked_client_handshake) {
        HookManager::Instance().RemoveHook(g_hooked_client_handshake);
        g_hooked_client_handshake = 0;
        g_orig_client_handshake = nullptr;
    }
    g_h1_client_ptr = nullptr;
    g_last_client_hs_key = 0xFFFFFFFFFFFFFFFFull;
    if (g_hooked_get_connected_peers) {
        HookManager::Instance().RemoveHook(g_hooked_get_connected_peers);
        g_hooked_get_connected_peers = 0;
        g_orig_get_connected_peers = nullptr;
    }
    g_last_net_state_logged = 0xFFFFFFFFu;
    g_last_net_conn_logged = 0xFFFFFFFFu;
    if (g_hooked_wait_for_peers) {
        HookManager::Instance().RemoveHook(g_hooked_wait_for_peers);
        g_hooked_wait_for_peers = 0;
        g_orig_wait_for_peers = nullptr;
    }
    g_fn_get_connected_peers = nullptr;
    g_expected_peers_ptr = nullptr;
    g_last_connected_peers_logged = 0xFFFFFFFFu;
    g_network_session_ptr = nullptr;
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
