#include "hooks/h1_engine_hooks.hpp"

#include "core/hook_manager.hpp"
#include "core/logger.hpp"
#include "core/memory_patch.hpp"
#include "core/pattern_scanner.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>
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

constexpr const char* kSigLoadLevelSolo =
    "40 55 56 57 41 54 41 55 41 56 41 57 48 81 EC 90 03";

constexpr const char* kSigLoadLevelCoop =
    "48 89 54 24 10 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 50 FD";

constexpr const char* kSigScriptEventDispatch =
    "48 8B C4 57 48 83 EC 60 48 C7 40 D8 FE FF FF FF 48 89 58 18 48 89 70 20 48 8B F1";

constexpr const char* kSigPostEvent =
    "4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 E1";

constexpr const char* kSigRegSessionPlayersCount =
    "48 89 5C 24 10 57 48 83 EC 20 48 8B F9 48 8D 0D 5C 8B C7 FF";

constexpr const char* kSigMscriptCallSite =
    "41 8B D5 48 8D 4C 24 40 FF D3 E9 2B 01 00 00";

constexpr const char* kSigMscriptMethodCallSite =
    "4C 8B 45 6F 41 8B D5 48 8B CB 41 FF D7 90";

constexpr const char* kSigMscriptVtableCallSite =
    "48 89 54 24 28 89 44 24 20 4C 8D 45 08 48 8B D7 41 FF D2";

constexpr const char* kSigLoadLevelCoopLocalCount =
    "32 D2 B8 02 00 00 00 88 15";

// halo1.dll: ExternalGetLocalPlayersCount @ 0x18006A4E0 (mscript query only; reads 0x181B7B910)
constexpr const char* kSigExtGetLocalPlayersCount =
    "0F BF 05 29 14 B1 01 C3 CC CC CC CC CC CC CC CC 48 83 EC 38";

// halo1.dll: MatchMake_campaign_net 20s timeouts @ 0x18006638B and 0x1800665B7 (cmp eax, 0x4E20)
constexpr const char* kSigMatchMakeTimeout1 =
    "3D 20 4E 00 00 0F 87 31 02 00 00 66 66 0F 1F 84 00 00 00 00";
constexpr const char* kSigMatchMakeTimeout2 =
    "3D 20 4E 00 00 0F 86 DE FD FF FF 4C 8B 74 24 60 8B 05 E3 53";

// halo1.dll: Coop_ClientSendLocalInput target host slot calc @ 0x1800566CB
// +0x07: 8B F5 2B F7 (mov esi, ebp; sub esi, edi) -> breaks for slot >= 2
constexpr const char* kSigCoopClientTargetSlot =
    "48 8B 05 A6 4D DE 02 8B F5 2B F7 8B D6 48 8B 48 30 E8 CF AE";

// halo1.dll: Saber3D Co-op Lockstep & Blam 4-Player Action Hooks
constexpr const char* kSigCoopIsHostAndRemoteConn =
    "48 8B 15 01 56 DE 02 48 85 D2 74 4B 48 8B 52 30 48 85 D2 74";
constexpr const char* kSigTransportSendPacket =
    "48 8B C4 55 57 41 55 41 56 41 57 48 8B EC 48 83 EC 60 48 C7";
constexpr const char* kSigSerializeClientInputVTable =
    "48 89 5C 24 08 48 89 7C 24 18 55 48 8B EC 48 83 EC 20 41 80";
constexpr const char* kSigDeserializeClientInput =
    "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 80 7A 18 00 48 8B DA 48 8B F1 75 39 80";
constexpr const char* kSigSerializeLockstepVTable =
    "48 89 5C 24 08 57 48 83 EC 20 48 8B 1A 49 8B F8 48 8B CB 49 8B D0 E8 F5";
constexpr const char* kSigDeserializeLockstepVTable =
    "48 89 5C 24 08 57 48 83 EC 30 49 8B 18 48 8B FA 48 8B CB E8";
constexpr const char* kSigCoopLockstepOnPacket =
    "4C 8B DC 55 48 81 EC A0 00 00 00 4C 8B 0D B6 5F DE 02 48 8B";
constexpr const char* kSigCoopApplyActions =
    "48 89 5C 24 18 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D9 48 81 EC C0 00 00 00 48 8B 05 C9";
constexpr const char* kSigCoopHostCaptureActions =
    "40 53 48 81 EC 90 00 00 00 48 8B 05 20 3B 0C 01 48 33 C4 48";
constexpr const char* kSigBitstreamWriteInt =
    "48 83 EC 28 45 8B D0 4C 8B C9 45 85 C0 75 17 88 54 24 40 45";
constexpr const char* kSigBitstreamReadInt =
    "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 45 33 C9 48 8B";
constexpr const char* kSigSerializeAction =
    "48 89 5C 24 08 48 89 7C 24 10 4C 89 44 24 18 55 48 8B EC 48 83 EC 20 48";
constexpr const char* kSigDeserializeAction =
    "48 89 5C 24 08 48 89 74 24 10 4C 89 44 24 18 57 48 83 EC 30 48 8B DA C7";
constexpr const char* kSigCoopIsSessionActive =
    "48 83 EC 28 48 83 3D CC 56 DE 02 00 75 6D 48 89 5C 24 20 48";
constexpr const char* kSigTransportIsPeerConnected =
    "48 89 5C 24 18 48 89 6C 24 20 56 57 41 54 41 56 41 57 48 81 EC 20 05 00";
constexpr const char* kSigTransportFlushPeerPacket =
    "48 8B C4 56 57 41 54 41 56 41 57 48 81 EC 50 05 00 00";
constexpr const char* kSigTransportPrepareNextPacket =
    "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 56 41 57 48 83 EC 20 8B 91 20 01 00 00 4C 8D 81 3C 01 00 00";

constexpr const char* kSigEvalBytecode =
    "48 8B C4 4C 89 40 18 55 56 57 41 54 41 55 41 56 41 57 48 8D A8 58 FC FF FF 48 81 EC 70 04 00 00";

constexpr const char* kSigMscriptLogSink =
    "4C 8B DC 49 89 6B 20 57 48 81 EC C0 00 00 00 48 8B 01 33 ED 48 89 2A";
constexpr const char* kSigUnitExitVehicle =
    "48 83 EC 28 41 83 CB FF 41 3B CB 74 60 0F B7 D1 41 BA D8 00 00 00";

constexpr const char* kSigLockstepInputBuffer = "";
constexpr const char* kSigGameCreatePlayer = "";
constexpr const char* kSigCoopRespawnCheck = "";

constexpr uintptr_t kRvaMsgIdClientInput = 0x01B7AA54;
constexpr uintptr_t kRvaMsgIdLockstepFrame = 0x01B7AA68;
constexpr uintptr_t kRvaMsgIdCameraSync = 0x01B7AA6C;
constexpr uintptr_t kRvaNextLockstepTick = 0x01B7AA70;
constexpr uintptr_t kRvaCoopLocalPlayerIndex = 0x01B7B4AC;
constexpr uintptr_t kRvaCoopPlayerCount = 0x01B7B910;
constexpr uintptr_t kRvaLockstepFrameQueuePtr = 0x01BA39D8;
constexpr uintptr_t kRvaLockstepFrameQueueCount = 0x01BA39E0;
constexpr uintptr_t kRvaHostRemoteClientInputBuf = 0x01BA3A00;
constexpr uintptr_t kRvaRemoteClientSlotId = 0x01BE96FC;
constexpr uintptr_t kRvaActiveSession0Ptr = 0x02E3B478;
constexpr uintptr_t kRvaMsgIdTablePtr = 0x02ED9988;
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
std::atomic<bool> g_init_session_entered{false};
uintptr_t g_hooked_has_channel_for_slot = 0;
uint8_t g_hold_desired = 0;
uint64_t g_hold_until_ms = 0;
uintptr_t g_matchmake_peer_cmp_addr = 0;
uintptr_t g_transport_advert_cmp_addr = 0;
int g_launch_expected_players = 0;

uintptr_t g_hooked_ext_get_local_players_count = 0;
uintptr_t g_hooked_coop_is_host_and_remote = 0;
uintptr_t g_hooked_transport_send_packet = 0;
uintptr_t g_hooked_serialize_client_input_vtbl = 0;
uintptr_t g_hooked_deserialize_client_input = 0;
uintptr_t g_hooked_serialize_lockstep_vtbl = 0;
uintptr_t g_hooked_deserialize_lockstep_vtbl = 0;
uintptr_t g_hooked_coop_lockstep_on_packet = 0;
uintptr_t g_hooked_coop_apply_actions = 0;
uintptr_t g_hooked_coop_host_capture_actions = 0;

struct ExtraPlayersLockstep {
    uint32_t tick_num = 0;
    uint8_t p2_swizzled[0x30]{};
    uint8_t p3_swizzled[0x30]{};
    bool valid = false;
};

constexpr size_t kExtraLockstepRingSize = 512;
std::mutex g_lockstep_mutex;
ExtraPlayersLockstep g_extra_lockstep_ring[kExtraLockstepRingSize]{};
uint8_t g_host_client_pkt_state[4][0x58]{};
uint8_t g_host_client_raw_input[4][0x30]{};
int32_t g_client_ack_tick[4]{};
bool g_host_client_valid[4]{};

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

using FnInitGameSession = uint64_t(__fastcall*)(void* a1, void* a2, void* a3, uint32_t a4, uint8_t a5_is_new);
FnInitGameSession g_orig_init_game_session = nullptr;

using FnHasPlayer = bool(__fastcall*)(void* self, uint64_t a2, uint64_t a3, uint64_t a4, uint32_t slot);
FnHasPlayer g_orig_has_player = nullptr;

using FnObjectTeleportToFlag = void(__fastcall*)(uint32_t object_index, uint16_t flag_index, bool reset);
FnObjectTeleportToFlag g_orig_object_teleport_to_flag = nullptr;

using FnPostTeleportReset = void(__fastcall*)(uint32_t object_index);
FnPostTeleportReset g_fn_post_teleport = nullptr;

using FnDatumArrayNext = int32_t(__fastcall*)(const void* data_array, int32_t prev_datum);
FnDatumArrayNext g_fn_datum_next = nullptr;

using FnUnitExitVehicle = void(__fastcall*)(uint32_t unit_datum);
FnUnitExitVehicle g_fn_unit_exit_vehicle = nullptr;
using FnUnitExitSeatForce = void(__fastcall*)(uint32_t unit_datum, bool a2, bool a3, bool force);
FnUnitExitSeatForce g_fn_unit_exit_seat_force = nullptr;
using FnObjectSetPosition = void(__fastcall*)(uint32_t obj_datum, const float* xyz, const float* forward, uint8_t a4);
FnObjectSetPosition g_fn_object_set_position = nullptr;
const uint8_t* const* g_object_header_array_ptr = nullptr;
const uint8_t* const* g_object_pool_ptr = nullptr;
char g_current_map_name[32]{};
bool g_opening_seat_eject_done = false;
bool g_p0_ever_on_foot = false;
int32_t g_p1_on_foot_ticks = 0;

bool GetUnitSeatAndPos(uint32_t unit_datum, uint32_t& out_parent, int16_t& out_seat, float out_pos[3]) {
    out_parent = 0xFFFFFFFFu;
    out_seat = -1;
    if (unit_datum == 0xFFFFFFFFu || !g_object_header_array_ptr || !g_object_pool_ptr) {
        return false;
    }
    const uint8_t* hdr_arr = *g_object_header_array_ptr;
    const uint8_t* pool = *g_object_pool_ptr;
    if (!hdr_arr || !pool) {
        return false;
    }
    const int32_t data_off = *reinterpret_cast<const int32_t*>(hdr_arr + kDataArrayOffsetToData);
    const uint32_t idx = unit_datum & 0xFFFFu;
    const int32_t pool_off = *reinterpret_cast<const int32_t*>(hdr_arr + data_off + static_cast<size_t>(idx) * 12 + 0x08);
    if (pool_off < 0) {
        return false;
    }
    const uint8_t* obj = pool + static_cast<size_t>(pool_off);
    out_parent = *reinterpret_cast<const uint32_t*>(obj + 0x10C);
    out_seat = *reinterpret_cast<const int16_t*>(obj + 0x304);
    if (out_pos) {
        std::memcpy(out_pos, obj + 0x4C, sizeof(float) * 3);
    }
    return true;
}

using FnIGameEngineStart = void(__fastcall*)(void* self, void* mcc_iface, const uint8_t* launch_settings, void* a4);
FnIGameEngineStart g_orig_engine_start = nullptr;

using FnMatchMakeCampaignNet = uint64_t(__fastcall*)(void* a1, void* a2, void* a3, void* a4);
FnMatchMakeCampaignNet g_orig_matchmake_campaign_net = nullptr;

using FnHasChannelForSlot = bool(__fastcall*)(void* transport, int32_t slot);
FnHasChannelForSlot g_orig_has_channel_for_slot = nullptr;

using FnLoadLevelSolo = uint64_t(__fastcall*)(void* a1, void** a2, uint32_t a3, uint8_t a4_is_new);
FnLoadLevelSolo g_orig_load_level_solo = nullptr;
using FnLoadLevelCoop = uint64_t(__fastcall*)(void* a1, void** a2, uint32_t a3, uint8_t a4_is_new, uint8_t a5_is_online);
FnLoadLevelCoop g_orig_load_level_coop = nullptr;
uintptr_t g_hooked_load_level_solo = 0;

using FnExternalGetLocalPlayersCount = int32_t(__fastcall*)(void* this_ptr);
FnExternalGetLocalPlayersCount g_orig_ext_get_local_players_count = nullptr;

using FnCoopIsSessionActive = bool(__fastcall*)();
FnCoopIsSessionActive g_fn_coop_is_session_active = nullptr;

using FnCoopIsHostAndRemoteConnected = bool(__fastcall*)();
FnCoopIsHostAndRemoteConnected g_orig_coop_is_host_and_remote = nullptr;

using FnTransportIsPeerConnected = bool(__fastcall*)(const void* transport0, int32_t slot);
FnTransportIsPeerConnected g_fn_transport_is_peer_connected = nullptr;

using FnTransportFlushPeerPacket = void(__fastcall*)(void* transport0);
FnTransportFlushPeerPacket g_fn_transport_flush_peer_packet = nullptr;

using FnTransportPrepareNextPacket = int32_t(__fastcall*)(void* transport0);
FnTransportPrepareNextPacket g_orig_transport_prepare_next_packet = nullptr;
uintptr_t g_hooked_transport_prepare_next_packet = 0;

using FnTransportSendPacket = char(__fastcall*)(void* transport0, uint32_t target_slot_mask, int32_t msg_id, void* pkt_buf, uint32_t pkt_bits, uint32_t flags, int32_t a7);
FnTransportSendPacket g_orig_transport_send_packet = nullptr;

using FnBitstreamWriteInt = void(__fastcall*)(void* bitstream, uint32_t value, uint32_t max_val);
FnBitstreamWriteInt g_fn_bitstream_write_int = nullptr;

using FnBitstreamReadInt = void(__fastcall*)(void* bitstream, uint32_t* out_value, uint32_t max_val);
FnBitstreamReadInt g_fn_bitstream_read_int = nullptr;

using FnSerializeAction = void(__fastcall*)(const void* net_action_30, void* bitstream);
FnSerializeAction g_fn_serialize_action = nullptr;

using FnDeserializeAction = void(__fastcall*)(void* net_action_30, void* bitstream);
FnDeserializeAction g_fn_deserialize_action = nullptr;

using FnSerializeClientInputVTable = void(__fastcall*)(void* factory, uint8_t** pkt_58_ptr, void* bitstream);
FnSerializeClientInputVTable g_orig_serialize_client_input_vtbl = nullptr;

using FnDeserializeClientInput = void(__fastcall*)(uint8_t* pkt_58, void* bitstream);
FnDeserializeClientInput g_orig_deserialize_client_input = nullptr;

using FnSerializeLockstepVTable = void(__fastcall*)(void* factory, uint8_t** frame_6c_ptr, void* bitstream);
FnSerializeLockstepVTable g_orig_serialize_lockstep_vtbl = nullptr;

using FnDeserializeLockstepVTable = void(__fastcall*)(void* factory, void* bitstream, uint8_t** frame_6c_ptr);
FnDeserializeLockstepVTable g_orig_deserialize_lockstep_vtbl = nullptr;

using FnCoopLockstepOnPacket = void(__fastcall*)(uint8_t* mgr, uint64_t a2, int32_t msg_id, uint64_t a4, void* msg_envelope);
FnCoopLockstepOnPacket g_orig_coop_lockstep_on_packet = nullptr;

using FnCoopApplyActions = void(__fastcall*)(uint8_t* actions_4p, uint32_t* valid_mask_ptr);
FnCoopApplyActions g_orig_coop_apply_actions = nullptr;

using FnCoopHostCaptureActions = void(__fastcall*)(uint8_t* actions_4p);
FnCoopHostCaptureActions g_orig_coop_host_capture_actions = nullptr;

using FnEvalBytecode = void*(__fastcall*)(void* block, void* out_ptr, void* ctx, void* frame, void* a5, uint64_t a6, void* a7);
FnEvalBytecode g_orig_eval_bytecode = nullptr;
uintptr_t g_hooked_eval_bytecode = 0;

using FnMscriptLogSink = void(__fastcall*)(void** str_pp, void* out_ptr);
FnMscriptLogSink g_orig_mscript_log_sink = nullptr;
uintptr_t g_hooked_mscript_log_sink = 0;
uintptr_t g_hooked_load_level_coop = 0;

using FnScriptEventDispatch = void(__fastcall*)(uint32_t* ev);
FnScriptEventDispatch g_orig_script_event_dispatch = nullptr;
uintptr_t g_hooked_script_event_dispatch = 0;
std::atomic<bool> g_log_script_events{false};

using FnPostEvent = void(__fastcall*)(void* bus, uint32_t event_id, void* args);
FnPostEvent g_orig_post_event = nullptr;
uintptr_t g_hooked_post_event = 0;

using FnSessionPlayersCount = uint32_t(__fastcall*)(void* session);
FnSessionPlayersCount g_orig_session_players_count = nullptr;
uintptr_t g_hooked_session_players_count = 0;
std::atomic<bool> g_in_request_start_game{false};

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
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(target, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT) {
        return;
    }
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
    if (g_hold_desired > 2 && transport) {
        const auto* s0 = reinterpret_cast<const uint8_t*>(transport);
        const int32_t chans = *reinterpret_cast<const int32_t*>(s0 + 0x128);
        const uint8_t* t0 = *reinterpret_cast<const uint8_t* const*>(s0 + 0x30);
        const int32_t t0_peers = t0 ? *reinterpret_cast<const int32_t*>(t0 + 0x50) : 0;
        if (chans >= static_cast<int32_t>(g_hold_desired) && t0_peers >= static_cast<int32_t>(g_hold_desired)) {
            const uint64_t now = GetTickCount64();
            if (g_hold_until_ms == 0) {
                g_hold_until_ms = now + 2500;
            } else if (now >= g_hold_until_ms) {
                WritePeerCapByte(g_matchmake_peer_cmp_addr, g_hold_desired);
                g_hold_desired = 0;
            }
        }
    }
    const bool res = g_orig_has_channel_for_slot(transport, slot * 2);
    if (slot >= 2) {
        static std::atomic<int> slot2_log_budget{8};
        if (slot2_log_budget.fetch_sub(1) > 0) {
            const auto* s0 = reinterpret_cast<const uint8_t*>(transport);
            const int32_t chans = s0 ? *reinterpret_cast<const int32_t*>(s0 + 0x128) : -1;
            const uint8_t* t0 = s0 ? *reinterpret_cast<const uint8_t* const*>(s0 + 0x30) : nullptr;
            const int32_t t0_peers = t0 ? *reinterpret_cast<const int32_t*>(t0 + 0x50) : -1;
            CE4P_LOG_INFO("[H1] HasChannelForSlot(slot=%d, key=%d) -> %d (chans=%d, t0_peers=%d)",
                          slot, slot * 2, res ? 1 : 0, chans, t0_peers);
        }
    }
    return res;
}

uint64_t __fastcall Hook_MatchMakeCampaignNet(void* a1, void* a2, void* a3, void* a4) {
    uint32_t net_active = g_net_active_ptr ? *g_net_active_ptr : 0;
    uint32_t is_host = g_is_host_ptr ? *g_is_host_ptr : 0;
    uint8_t desired = 2;
    if (net_active != 0 && g_launch_expected_players >= 2 && g_launch_expected_players <= 4) {
        desired = static_cast<uint8_t>(g_launch_expected_players);
    }
    g_hold_until_ms = 0;
    g_hold_desired = (is_host != 0 && net_active != 0 && desired > 2) ? desired : 0;
    WritePeerCapByte(g_matchmake_peer_cmp_addr, g_hold_desired ? static_cast<uint8_t>(desired + 1) : desired);
    WritePeerCapByte(g_transport_advert_cmp_addr, desired);
    CE4P_LOG_INFO(
        "[H1] MatchMake_campaign_net(is_host=%u, net_active=%u, launch_players=%d) -> wait_cap=%u",
        is_host,
        net_active,
        g_launch_expected_players,
        static_cast<unsigned>(desired)
    );
    g_log_script_events.store(true);
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
    if (is_host != 0 && t0_chans >= 3) {
        g_init_session_entered.store(false);
        DWORD tid = GetCurrentThreadId();
        uintptr_t h1_base = g_h1_base;
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, tid);
        if (hThread) {
            struct WatchArgs { HANDLE th; uintptr_t base; };
            HANDLE w = CreateThread(
                nullptr, 0,
                [](LPVOID param) -> DWORD {
                    auto* a = reinterpret_cast<WatchArgs*>(param);
                    Sleep(3000);
                    if (!g_init_session_entered.load() && a->th) {
                        if (SuspendThread(a->th) != static_cast<DWORD>(-1)) {
                            CONTEXT ctx{};
                            ctx.ContextFlags = CONTEXT_CONTROL;
                            if (GetThreadContext(a->th, &ctx)) {
                                MEMORY_BASIC_INFORMATION mbi{};
                                uint32_t sr_flag = a->base ? *reinterpret_cast<const uint32_t*>(a->base + 0x01B7AA80) : 0xFFFFu;
                                uint8_t mm_fail = a->base ? *reinterpret_cast<const uint8_t*>(a->base + 0x02EA32E9) : 0xFFu;
                                uint32_t mm_exit = a->base ? *reinterpret_cast<const uint32_t*>(a->base + 0x02E3B9B0) : 0xFFFFu;
                                CE4P_LOG_WARN(
                                    "[H1] Watchdog(3s): MatchMake thread @ 0x%llX rsp=0x%llX (sr=%u, mm_fail=%u, mm_exit=%u)",
                                    static_cast<unsigned long long>(ctx.Rip),
                                    static_cast<unsigned long long>(ctx.Rsp),
                                    sr_flag, mm_fail, mm_exit
                                );
                                if (a->base && VirtualQuery(reinterpret_cast<void*>(ctx.Rsp), &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT) {
                                    const auto* stk = reinterpret_cast<const uintptr_t*>(ctx.Rsp);
                                    size_t max_q = (mbi.RegionSize - (ctx.Rsp - reinterpret_cast<uintptr_t>(mbi.BaseAddress))) / sizeof(uintptr_t);
                                    if (max_q > 256) max_q = 256;
                                    int hits = 0;
                                    for (size_t qi = 0; qi < max_q && hits < 6; ++qi) {
                                        uintptr_t v = stk[qi];
                                        if (v >= a->base && v < a->base + 0x3D82000) {
                                            CE4P_LOG_WARN("[H1] Watchdog stk[%zu] -> halo1+0x%llX", qi, static_cast<unsigned long long>(v - a->base));
                                            ++hits;
                                        }
                                    }
                                }
                            }
                            ResumeThread(a->th);
                        }
                    }
                    CloseHandle(a->th);
                    delete a;
                    return 0;
                },
                new WatchArgs{hThread, h1_base},
                0, nullptr
            );
            if (w) CloseHandle(w); else CloseHandle(hThread);
        }
    }
    if (sess) {
        uint64_t m178 = *reinterpret_cast<const uint64_t*>(sess + 0x178);
        uint64_t m180 = *reinterpret_cast<const uint64_t*>(sess + 0x180);
        const int32_t* slots = reinterpret_cast<const int32_t*>(sess + 0x58);
        CE4P_LOG_INFO(
            "[H1] Session0: slots=[%d,%d,%d,%d], m178=0x%llX, m180=0x%llX",
            slots[0], slots[1], slots[2], slots[3],
            static_cast<unsigned long long>(m178),
            static_cast<unsigned long long>(m180)
        );
    }
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

const char* LookupEventName(uint32_t id) {
    if (!g_h1_base) {
        return "?";
    }
    uintptr_t bus = *reinterpret_cast<const uintptr_t*>(g_h1_base + 0x02E3BBF8);
    if (!bus) {
        return "?";
    }
    uintptr_t page = *reinterpret_cast<const uintptr_t*>(bus + ((id >> 8) * 8) + 0x58);
    if (!page) {
        return "?";
    }
    uintptr_t str_ptr = *reinterpret_cast<const uintptr_t*>(page + ((id & 0xFFu) * 40u));
    return str_ptr ? reinterpret_cast<const char*>(str_ptr) : "?";
}

void LogStackTrace(const char* tag);

void __fastcall Hook_PostEvent(void* bus, uint32_t event_id, void* args) {
    if (g_log_script_events.load()) {
        const char* name = LookupEventName(event_id);
        if (strstr(name, "Game") != nullptr || strstr(name, "Start") != nullptr || strstr(name, "Matchmake") != nullptr) {
            CE4P_LOG_INFO("[H1] PostEvent(id=0x%X, name=%s)", event_id, name);
            LogStackTrace("PostEvent");
        }
    }
    g_orig_post_event(bus, event_id, args);
}

void __fastcall LogMscriptTarget(uintptr_t target) {
    if (!g_in_request_start_game.load()) {
        return;
    }
    if (g_h1_base && target >= g_h1_base && target < g_h1_base + 0x4000000) {
        CE4P_LOG_INFO("[H1] mscript_call -> halo1+0x%llX", static_cast<unsigned long long>(target - g_h1_base));
    } else {
        CE4P_LOG_INFO("[H1] mscript_call -> 0x%llX", static_cast<unsigned long long>(target));
    }
}

void __fastcall LogMscriptCallResult(uintptr_t target, const uint64_t* ret_var_ptr) {
    if (!g_in_request_start_game.load() || !ret_var_ptr) {
        return;
    }
    const uint64_t* v = reinterpret_cast<const uint64_t*>(*ret_var_ptr);
    if (!v || IsBadReadPtr(v, 16)) {
        return;
    }
    uint32_t type = static_cast<uint32_t>(v[0]);
    uint64_t val = v[1];
    CE4P_LOG_INFO("[H1] mscript_ret(halo1+0x%llX) -> type=%u val=0x%llX",
                  g_h1_base ? static_cast<unsigned long long>(target - g_h1_base) : static_cast<unsigned long long>(target),
                  type, static_cast<unsigned long long>(val));
}

bool InstallMscriptCallTracer(uintptr_t site_addr) {
    // site_addr:
    // +0: 41 8B D5             mov edx, r13d
    // +3: 48 8D 4C 24 40       lea rcx, [rsp+0x40]
    // +8: FF D3                call rbx
    // +A: E9 2B 01 00 00       jmp site_addr + 0x13A (0x18099A6D9)
    int32_t disp = *reinterpret_cast<const int32_t*>(site_addr + 0xB);
    uintptr_t resume_addr = site_addr + 0xF + disp;

    auto* stub = static_cast<uint8_t*>(VirtualAlloc(nullptr, 256, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!stub) {
        return false;
    }
    uint8_t* p = stub;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        for (uint8_t b : bytes) *p++ = b;
    };
    auto emit_u64 = [&](uint64_t v) {
        std::memcpy(p, &v, 8);
        p += 8;
    };
    // push rax, rcx, rdx, r8, r9, r10, r11 (7 * 8 = 56 bytes)
    emit({0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53});
    // sub rsp, 0x28 (56 + 40 = 96, 16-byte aligned)
    emit({0x48, 0x83, 0xEC, 0x28});
    // mov rcx, rbx
    emit({0x48, 0x89, 0xD9});
    // mov rax, LogMscriptTarget; call rax
    emit({0x48, 0xB8});
    emit_u64(reinterpret_cast<uint64_t>(&LogMscriptTarget));
    emit({0xFF, 0xD0});
    // add rsp, 0x28
    emit({0x48, 0x83, 0xC4, 0x28});
    // pop r11, r10, r9, r8, rdx, rcx, rax
    emit({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58});
    // mov edx, r13d; lea rcx, [rsp+0x40]; call rbx
    emit({0x41, 0x8B, 0xD5, 0x48, 0x8D, 0x4C, 0x24, 0x40, 0xFF, 0xD3});
    // Log result: push rax, rcx, rdx, r8, r9, r10, r11 (56 bytes)
    emit({0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53});
    // lea rdx, [rsp + 0x38 + 0x40] (rsp+0x78)
    emit({0x48, 0x8D, 0x54, 0x24, 0x78});
    // sub rsp, 0x28
    emit({0x48, 0x83, 0xEC, 0x28});
    // mov rcx, rbx
    emit({0x48, 0x89, 0xD9});
    // mov rax, LogMscriptCallResult; call rax
    emit({0x48, 0xB8});
    emit_u64(reinterpret_cast<uint64_t>(&LogMscriptCallResult));
    emit({0xFF, 0xD0});
    // add rsp, 0x28
    emit({0x48, 0x83, 0xC4, 0x28});
    // pop r11, r10, r9, r8, rdx, rcx, rax
    emit({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58});
    // jmp [rip+0] -> resume_addr (preserves rax)
    emit({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});
    emit_u64(resume_addr);

    DWORD old_prot = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(site_addr), 15, PAGE_EXECUTE_READWRITE, &old_prot)) {
        return false;
    }
    uint8_t* dst = reinterpret_cast<uint8_t*>(site_addr);
    dst[0] = 0x48;
    dst[1] = 0xB8;
    uint64_t stub_addr = reinterpret_cast<uint64_t>(stub);
    std::memcpy(dst + 2, &stub_addr, 8);
    dst[10] = 0xFF;
    dst[11] = 0xE0;
    dst[12] = 0x90;
    dst[13] = 0x90;
    dst[14] = 0x90;
    VirtualProtect(reinterpret_cast<void*>(site_addr), 15, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(site_addr), 15);
    return true;
}

bool InstallMscriptMethodCallTracer(uintptr_t site_addr) {
    // site_addr (14 bytes):
    // +0: 4C 8B 45 6F    mov r8, [rbp+0x6F]
    // +4: 41 8B D5       mov edx, r13d
    // +7: 48 8B CB       mov rcx, rbx
    // +A: 41 FF D7       call r15
    // +D: 90             nop
    uintptr_t resume_addr = site_addr + 14;

    auto* stub = static_cast<uint8_t*>(VirtualAlloc(nullptr, 128, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!stub) {
        return false;
    }
    uint8_t* p = stub;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        for (uint8_t b : bytes) *p++ = b;
    };
    auto emit_u64 = [&](uint64_t v) {
        std::memcpy(p, &v, 8);
        p += 8;
    };
    // push rax, rcx, rdx, r8, r9, r10, r11
    emit({0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53});
    // sub rsp, 0x28
    emit({0x48, 0x83, 0xEC, 0x28});
    // mov rcx, r15
    emit({0x4C, 0x89, 0xF9});
    // mov rax, LogMscriptTarget; call rax
    emit({0x48, 0xB8});
    emit_u64(reinterpret_cast<uint64_t>(&LogMscriptTarget));
    emit({0xFF, 0xD0});
    // add rsp, 0x28
    emit({0x48, 0x83, 0xC4, 0x28});
    // pop r11, r10, r9, r8, rdx, rcx, rax
    emit({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58});
    // Original instructions: mov r8, [rbp+0x6F]; mov edx, r13d; mov rcx, rbx; call r15
    emit({0x4C, 0x8B, 0x45, 0x6F, 0x41, 0x8B, 0xD5, 0x48, 0x8B, 0xCB, 0x41, 0xFF, 0xD7});
    // jmp [rip+0] -> resume_addr (preserves rax)
    emit({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});
    emit_u64(resume_addr);

    DWORD old_prot = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(site_addr), 14, PAGE_EXECUTE_READWRITE, &old_prot)) {
        return false;
    }
    uint8_t* dst = reinterpret_cast<uint8_t*>(site_addr);
    dst[0] = 0xFF;
    dst[1] = 0x25;
    dst[2] = 0x00;
    dst[3] = 0x00;
    dst[4] = 0x00;
    dst[5] = 0x00;
    uint64_t stub_addr = reinterpret_cast<uint64_t>(stub);
    std::memcpy(dst + 6, &stub_addr, 8);
    VirtualProtect(reinterpret_cast<void*>(site_addr), 14, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(site_addr), 14);
    return true;
}

void __fastcall LogMscriptVtableCall(uintptr_t target, uintptr_t name_ptr) {
    if (!g_in_request_start_game.load()) {
        return;
    }
    char name_buf[48] = {};
    if (name_ptr > 0x10000 && !IsBadReadPtr(reinterpret_cast<const void*>(name_ptr), 32)) {
        const char* s = reinterpret_cast<const char*>(name_ptr);
        size_t i = 0;
        for (; i < 40; ++i) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (c == 0) break;
            if (c < 0x20 || c > 0x7E) {
                i = 0;
                break;
            }
            name_buf[i] = static_cast<char>(c);
        }
        name_buf[i] = '\0';
    }
    if (g_h1_base && target >= g_h1_base && target < g_h1_base + 0x4000000) {
        if (name_buf[0]) {
            CE4P_LOG_INFO("[H1] mscript_vcall -> halo1+0x%llX ('%s')",
                          static_cast<unsigned long long>(target - g_h1_base), name_buf);
        } else {
            CE4P_LOG_INFO("[H1] mscript_vcall -> halo1+0x%llX (rdx=0x%llX)",
                          static_cast<unsigned long long>(target - g_h1_base),
                          static_cast<unsigned long long>(name_ptr));
        }
    } else {
        CE4P_LOG_INFO("[H1] mscript_vcall -> 0x%llX (rdx=0x%llX)",
                      static_cast<unsigned long long>(target),
                      static_cast<unsigned long long>(name_ptr));
    }
}

void __fastcall LogMscriptVtableResult(uint32_t ret_eax, const uint64_t* out_variant) {
    if (!g_in_request_start_game.load() || !out_variant || IsBadReadPtr(out_variant, 16)) {
        return;
    }
    uint32_t type = static_cast<uint32_t>(out_variant[0]);
    uint64_t val = out_variant[1];
    CE4P_LOG_INFO("[H1] mscript_vret -> eax=%u type=%u val=0x%llX",
                  ret_eax, type, static_cast<unsigned long long>(val));
}

bool InstallMscriptVtableCallTracer(uintptr_t site_addr) {
    // site_addr (19 bytes):
    // +0:  48 89 54 24 28   mov [rsp+0x28], rdx
    // +5:  89 44 24 20      mov [rsp+0x20], eax
    // +9:  4C 8D 45 08      lea r8, [rbp+0x8]
    // +D:  48 8B D7         mov rdx, rdi
    // +10: 41 FF D2         call r10
    uintptr_t resume_addr = site_addr + 19;

    auto* stub = static_cast<uint8_t*>(VirtualAlloc(nullptr, 256, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!stub) {
        return false;
    }
    uint8_t* p = stub;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        for (uint8_t b : bytes) *p++ = b;
    };
    auto emit_u64 = [&](uint64_t v) {
        std::memcpy(p, &v, 8);
        p += 8;
    };
    // Original setup instructions BEFORE call r10:
    // mov [rsp+0x28], rdx; mov [rsp+0x20], eax; lea r8, [rbp+0x8]; mov rdx, rdi
    // Wait: [rsp+0x28] and [rsp+0x20] are caller's stack slots, so do them BEFORE pushing!
    emit({0x48, 0x89, 0x54, 0x24, 0x28,
          0x89, 0x44, 0x24, 0x20,
          0x4C, 0x8D, 0x45, 0x08,
          0x48, 0x8B, 0xD7});
    // push rax, rcx, rdx, r8, r9, r10, r11 (56 bytes)
    emit({0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53});
    // sub rsp, 0x28
    emit({0x48, 0x83, 0xEC, 0x28});
    // mov rcx, r10 (4C 89 D1)
    emit({0x4C, 0x89, 0xD1});
    // mov rdx, rdi (48 89 FA) -> already in rdx, but rdi is unchanged
    emit({0x48, 0x89, 0xFA});
    // mov rax, LogMscriptVtableCall; call rax
    emit({0x48, 0xB8});
    emit_u64(reinterpret_cast<uint64_t>(&LogMscriptVtableCall));
    emit({0xFF, 0xD0});
    // add rsp, 0x28
    emit({0x48, 0x83, 0xC4, 0x28});
    // pop r11, r10, r9, r8, rdx, rcx, rax
    emit({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58});
    // call r10
    emit({0x41, 0xFF, 0xD2});
    // Log result: push rax, rcx, rdx, r8, r9, r10, r11 (56 bytes)
    emit({0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53});
    // sub rsp, 0x28
    emit({0x48, 0x83, 0xEC, 0x28});
    // mov ecx, eax
    emit({0x89, 0xC1});
    // lea rdx, [rbp + 0xf8]
    emit({0x48, 0x8D, 0x95, 0xF8, 0x00, 0x00, 0x00});
    // mov rax, LogMscriptVtableResult; call rax
    emit({0x48, 0xB8});
    emit_u64(reinterpret_cast<uint64_t>(&LogMscriptVtableResult));
    emit({0xFF, 0xD0});
    // add rsp, 0x28
    emit({0x48, 0x83, 0xC4, 0x28});
    // pop r11, r10, r9, r8, rdx, rcx, rax
    emit({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58});
    // jmp [rip+0] -> resume_addr
    emit({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});
    emit_u64(resume_addr);

    DWORD old_prot = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(site_addr), 19, PAGE_EXECUTE_READWRITE, &old_prot)) {
        return false;
    }
    uint8_t* dst = reinterpret_cast<uint8_t*>(site_addr);
    dst[0] = 0xFF;
    dst[1] = 0x25;
    dst[2] = 0x00;
    dst[3] = 0x00;
    dst[4] = 0x00;
    dst[5] = 0x00;
    uint64_t stub_addr = reinterpret_cast<uint64_t>(stub);
    std::memcpy(dst + 6, &stub_addr, 8);
    for (int i = 14; i < 19; ++i) dst[i] = 0x90;
    VirtualProtect(reinterpret_cast<void*>(site_addr), 19, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(site_addr), 19);
    return true;
}

void LogStackTrace(const char* tag);

uint32_t __fastcall Hook_SessionPlayersCount(void* session) {
    uint32_t count = g_orig_session_players_count(session);
    if (count > 2) {
        static std::atomic<int> log_budget{8};
        if (log_budget.fetch_sub(1) > 0) {
            CE4P_LOG_INFO("[H1] Session.PlayersCount() clamped: %u -> 2", count);
        }
        return 2;
    }
    return count;
}

void* __fastcall Hook_EvalBytecode(void* block, void* out_ptr, void* ctx, void* frame, void* a5, uint64_t a6, void* a7) {
    if (g_in_request_start_game.load() && block && !IsBadReadPtr(block, 0x48)) {
        static std::atomic<uintptr_t> dumped_blocks[16]{};
        uintptr_t baddr = reinterpret_cast<uintptr_t>(block);
        bool seen = false;
        for (auto& slot : dumped_blocks) {
            uintptr_t v = slot.load();
            if (v == baddr) {
                seen = true;
                break;
            }
            if (v == 0) {
                uintptr_t expected = 0;
                if (slot.compare_exchange_strong(expected, baddr)) {
                    break;
                }
            }
        }
        if (!seen) {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(block);
            const uint32_t* insns = *reinterpret_cast<const uint32_t* const*>(p + 0x38);
            int32_t count = *reinterpret_cast<const int32_t*>(p + 0x40);
            CE4P_LOG_INFO("[H1] EvalBytecode block=0x%llX count=%d", static_cast<unsigned long long>(baddr), count);
            if (insns && count > 0 && count <= 512 && !IsBadReadPtr(insns, static_cast<size_t>(count) * 16)) {
                for (int32_t i = 0; i < count; ++i) {
                    const uint32_t* ins = insns + i * 4;
                    CE4P_LOG_INFO("[H1]   bc[%03d]: op=0x%02X a1=0x%08X a2=0x%08X a3=0x%08X",
                                  i, ins[0], ins[1], ins[2], ins[3]);
                }
            }
        }
    }
    return g_orig_eval_bytecode(block, out_ptr, ctx, frame, a5, a6, a7);
}

void __fastcall Hook_MscriptLogSink(void** str_pp, void* out_ptr) {
    if (g_in_request_start_game.load() && str_pp && !IsBadReadPtr(str_pp, sizeof(void*)) && *str_pp &&
        !IsBadReadPtr(*str_pp, 16)) {
        const char* msg = reinterpret_cast<const char*>(*str_pp) + 0xC;
        CE4P_LOG_INFO("[H1] mscript_log: %s", msg);
    }
    g_orig_mscript_log_sink(str_pp, out_ptr);
}

void __fastcall Hook_ScriptEventDispatch(uint32_t* ev) {
    bool is_start_game = false;
    if (ev && g_h1_base) {
        uint32_t id = *ev;
        const char* name = LookupEventName(id);
        is_start_game = (strcmp(name, "Request_StartGame") == 0);
        if (g_log_script_events.load()) {
            static std::atomic<uint64_t> seen_mask{0};
            uint32_t bucket = id & 63u;
            uint64_t bit = 1ull << bucket;
            if ((seen_mask.fetch_or(bit) & bit) == 0 || strstr(name, "Matchmake") != nullptr || strstr(name, "Level") != nullptr || strstr(name, "Game") != nullptr) {
                CE4P_LOG_INFO("[H1] ScriptEvent(id=0x%X, name=%s)", id, name);
            }
        }
    }
    if (is_start_game) {
        g_in_request_start_game.store(true);
    }
    g_orig_script_event_dispatch(ev);
    if (is_start_game) {
        g_in_request_start_game.store(false);
    }
}

void LogStackTrace(const char* tag) {
    void* frames[28]{};
    USHORT count = CaptureStackBackTrace(1, 28, frames, nullptr);
    for (USHORT i = 0; i < count; ++i) {
        uintptr_t addr = reinterpret_cast<uintptr_t>(frames[i]);
        if (g_h1_base && addr >= g_h1_base && addr < g_h1_base + 0x4000000) {
            CE4P_LOG_INFO("[H1] %s stk[%u] -> halo1+0x%llX", tag, static_cast<unsigned>(i),
                          static_cast<unsigned long long>(addr - g_h1_base));
        } else {
            CE4P_LOG_INFO("[H1] %s stk[%u] -> 0x%llX", tag, static_cast<unsigned>(i),
                          static_cast<unsigned long long>(addr));
        }
    }
}

void ResetLockstepMultiplexState() {
    std::lock_guard<std::mutex> lock(g_lockstep_mutex);
    std::memset(g_extra_lockstep_ring, 0, sizeof(g_extra_lockstep_ring));
    std::memset(g_host_client_raw_input, 0, sizeof(g_host_client_raw_input));
    std::memset(g_client_ack_tick, 0, sizeof(g_client_ack_tick));
    std::memset(g_host_client_valid, 0, sizeof(g_host_client_valid));
    for (int i = 0; i < 4; ++i) {
        uint8_t* st = g_host_client_pkt_state[i];
        std::memset(st, 0, 0x58);
        *reinterpret_cast<int64_t*>(st + 0x30) = -1;
        *reinterpret_cast<int32_t*>(st + 0x48) = -1;
        *reinterpret_cast<int64_t*>(st + 0x4C) = -1;
        *reinterpret_cast<int32_t*>(st + 0x54) = -1;
    }
}

void SwizzleBlamActionToNet(const uint8_t* blam, uint8_t* net) {
    std::memcpy(net, blam, 0x30);
    // Network 0x30 layout sign-extends Blam +0x19 (int8) into +0x18..+0x19 (int16) and zeros +0x1E..+0x1F.
    const int16_t ext = static_cast<int16_t>(static_cast<int8_t>(blam[0x19]));
    std::memcpy(net + 0x18, &ext, sizeof(ext));
    const uint16_t zero16 = 0;
    std::memcpy(net + 0x1E, &zero16, sizeof(zero16));
}

void UnswizzleNetActionToBlam(const uint8_t* net, uint8_t* blam) {
    std::memcpy(blam, net, 0x30);
    // Blam 0x30 layout stores the int8 from network +0x18 at +0x19 and clears padding byte +0x18.
    blam[0x18] = 0;
    blam[0x19] = net[0x18];
}

const uint8_t* GetTransportFromSession0(int32_t* out_local_slot = nullptr, int32_t* out_s0_peers = nullptr) {
    if (!g_h1_base) {
        return nullptr;
    }
    const uint8_t* session0 = *reinterpret_cast<const uint8_t* const*>(g_h1_base + kRvaActiveSession0Ptr);
    if (!session0) {
        return nullptr;
    }
    if (out_s0_peers) {
        *out_s0_peers = *reinterpret_cast<const int32_t*>(session0 + 0x128);
    }
    const uint8_t* transport0 = *reinterpret_cast<const uint8_t* const*>(session0 + 0x30);
    if (transport0 && out_local_slot) {
        int32_t local_slot = 0;
        const int32_t local_idx = *reinterpret_cast<const int32_t*>(transport0 + 0x30);
        const int32_t peer_count = *reinterpret_cast<const int32_t*>(transport0 + 0x50);
        const uint8_t* peers = *reinterpret_cast<const uint8_t* const*>(transport0 + 0x48);
        if (peers && local_idx >= 0 && local_idx < peer_count) {
            local_slot = *reinterpret_cast<const int32_t*>(peers + static_cast<size_t>(local_idx) * 0x118 + 0x08);
        }
        *out_local_slot = local_slot;
    }
    return transport0;
}

uint32_t GetConnectedRemoteClientsMask(const void* transport0, int32_t* out_first_slot = nullptr) {
    if (out_first_slot) {
        *out_first_slot = -1;
    }
    if (!transport0) {
        return 0;
    }
    const auto* t = reinterpret_cast<const uint8_t*>(transport0);
    const int32_t local_idx = *reinterpret_cast<const int32_t*>(t + 0x30);
    const int32_t peer_count = *reinterpret_cast<const int32_t*>(t + 0x50);
    const uint8_t* peers = *reinterpret_cast<const uint8_t* const*>(t + 0x48);
    if (!peers || peer_count <= 0) {
        return 0;
    }
    uint32_t mask = 0;
    int32_t first_slot = -1;
    const int n = (peer_count < 8) ? peer_count : 8;
    for (int i = 0; i < n; ++i) {
        if (i == local_idx) {
            continue;
        }
        const int32_t slot_id = *reinterpret_cast<const int32_t*>(peers + static_cast<size_t>(i) * 0x118 + 0x08);
        if (slot_id <= 0 || slot_id >= 32) {
            continue;
        }
        // Note: 0x1801D15B0 (g_fn_transport_is_peer_connected) is Transport0::PrepareSlotPacket,
        // which mutates t0+0x138/t0+0x168 and checks send-window state. Use the read-only peer
        // flags at t0->peers[mapped]+0x00 (bit 1 = slot assigned/connected) instead.
        const int32_t mapped = *reinterpret_cast<const int32_t*>(t + 0x58 + static_cast<size_t>(slot_id) * 4);
        const bool connected = (mapped >= 0 && mapped < peer_count) &&
                               (((*reinterpret_cast<const uint32_t*>(peers + static_cast<size_t>(mapped) * 0x118)) >> 1) & 1u) != 0;
        if (connected) {
            mask |= (1u << static_cast<uint32_t>(slot_id));
            if (first_slot < 0) {
                first_slot = slot_id;
            }
        }
    }
    if (out_first_slot) {
        *out_first_slot = first_slot;
    }
    return mask;
}

int32_t __fastcall Hook_ExternalGetLocalPlayersCount(void* this_ptr) {
    if (g_h1_base) {
        const uint8_t is_splitscreen = *reinterpret_cast<const uint8_t*>(g_h1_base + kRvaGameModeFlags);
        if (is_splitscreen == 0) {
            // Online co-op and solo render 1 local viewport; mscript queries this in OnLevelLoaded().
            return 1;
        }
    }
    return g_orig_ext_get_local_players_count ? g_orig_ext_get_local_players_count(this_ptr) : 1;
}

bool __fastcall Hook_CoopIsHostAndRemoteConnected() {
    if (!g_h1_base) {
        return g_orig_coop_is_host_and_remote ? g_orig_coop_is_host_and_remote() : false;
    }
    int32_t local_slot = -1;
    const uint8_t* transport0 = GetTransportFromSession0(&local_slot, nullptr);
    if (transport0 && local_slot == 0) {
        int32_t first_slot = -1;
        const uint32_t mask = GetConnectedRemoteClientsMask(transport0, &first_slot);
        if (first_slot > 0) {
            *reinterpret_cast<int32_t*>(g_h1_base + kRvaRemoteClientSlotId) = first_slot;
        }
        return mask != 0;
    }
    return g_orig_coop_is_host_and_remote ? g_orig_coop_is_host_and_remote() : false;
}

// LTCG callers (e.g. 0x180AB150E) assume 0x180055E70 preserves volatile regs such as r9.
void* BuildVolatilePreservingNoArgStub(void* target_fn) {
    auto* stub = static_cast<uint8_t*>(VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!stub) {
        return target_fn;
    }
    uint8_t* p = stub;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        for (uint8_t b : bytes) *p++ = b;
    };
    emit({0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53});  // push rcx, rdx, r8..r11
    emit({0x48, 0x83, 0xEC, 0x28});                                      // sub rsp, 0x28
    emit({0x48, 0xB8});                                                  // mov rax, target_fn
    uint64_t addr = reinterpret_cast<uint64_t>(target_fn);
    std::memcpy(p, &addr, 8);
    p += 8;
    emit({0xFF, 0xD0});                                                  // call rax
    emit({0x48, 0x83, 0xC4, 0x28});                                      // add rsp, 0x28
    emit({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59});  // pop r11..r8, rdx, rcx
    emit({0xC3});                                                        // ret
    FlushInstructionCache(GetCurrentProcess(), stub, 64);
    return stub;
}

int32_t LookupMsgIdFromIndex(uintptr_t h1_base, uintptr_t idx_rva) {
    const int32_t idx = *reinterpret_cast<const int32_t*>(h1_base + idx_rva);
    if (idx < 0) {
        return -1;
    }
    const auto* table = *reinterpret_cast<const uint8_t* const*>(h1_base + kRvaMsgIdTablePtr);
    if (!table) {
        return -1;
    }
    return *reinterpret_cast<const int32_t*>(table + static_cast<size_t>(idx) * 16 + 8);
}

char __fastcall Hook_TransportSendPacket(
    void* transport0,
    uint32_t target_slot_mask,
    int32_t msg_id,
    void* pkt_buf,
    uint32_t pkt_bits,
    uint32_t flags,
    int32_t a7
) {
    if (g_h1_base) {
        const int32_t local_player_idx = *reinterpret_cast<const int32_t*>(g_h1_base + kRvaCoopLocalPlayerIndex);
        const int32_t msg_lockstep = LookupMsgIdFromIndex(g_h1_base, kRvaMsgIdLockstepFrame);
        const int32_t msg_camera = LookupMsgIdFromIndex(g_h1_base, kRvaMsgIdCameraSync);
        const int32_t msg_input = LookupMsgIdFromIndex(g_h1_base, kRvaMsgIdClientInput);
        if (local_player_idx == 0 && (msg_id == msg_lockstep || msg_id == msg_camera)) {
            if (const uint8_t* s0_t0 = GetTransportFromSession0()) {
                const uint32_t remote_mask = GetConnectedRemoteClientsMask(s0_t0);
                static std::atomic<int> send_diag_budget{10};
                if (send_diag_budget.fetch_sub(1) > 0) {
                    const int32_t pcnt = *reinterpret_cast<const int32_t*>(s0_t0 + 0x50);
                    const uint8_t* peers = *reinterpret_cast<const uint8_t* const*>(s0_t0 + 0x48);
                    const uint8_t* ll = *reinterpret_cast<const uint8_t* const*>(s0_t0 + 0x118);
                    const uint8_t* ll_chans = ll ? *reinterpret_cast<const uint8_t* const*>(ll + 0x20) : nullptr;
                    for (int pi = 0; pi < pcnt && pi < 4 && peers; ++pi) {
                        const uint8_t* p = peers + static_cast<size_t>(pi) * 0x118;
                        const uint32_t pf = *reinterpret_cast<const uint32_t*>(p);
                        const int32_t ps = *reinterpret_cast<const int32_t*>(p + 0x08);
                        const int32_t ch = *reinterpret_cast<const int32_t*>(p + 0x4C);
                        uint32_t lf = 0;
                        int32_t ls = -1;
                        if (ll_chans && ch >= 0) {
                            lf = *reinterpret_cast<const uint32_t*>(ll_chans + static_cast<size_t>(ch) * 0x38);
                            ls = *reinterpret_cast<const int32_t*>(ll_chans + static_cast<size_t>(ch) * 0x38 + 0x04);
                        }
                        CE4P_LOG_INFO("[H1] SendPkt(msg=%d, orig_mask=0x%X, new_mask=0x%X) peer[%d]: slot=%d flags=0x%X ch=%d ll_flags=0x%X ll_state=%d",
                                      msg_id, target_slot_mask, remote_mask, pi, ps, pf, ch, lf, ls);
                    }
                }
                if (remote_mask != 0) {
                    target_slot_mask = remote_mask;
                }
            }
        } else if (local_player_idx > 0 && (msg_id == msg_input || msg_id == msg_camera)) {
            target_slot_mask = 1u;
        } else if (transport0 == GetTransportFromSession0() && msg_id != msg_lockstep && msg_id != msg_camera && msg_id != msg_input) {
            static std::atomic<int> nonlock_diag_budget{30};
            if (nonlock_diag_budget.fetch_sub(1) > 0) {
                CE4P_LOG_INFO("[H1] SendPktOther(msg=%d, mask=0x%X, bits=%u, local_pidx=%d)",
                              msg_id, target_slot_mask, pkt_bits, local_player_idx);
            }
        }
    }

    bool multi_peer_queue_flush = false;
    if (g_h1_base && transport0 && g_fn_transport_is_peer_connected && g_fn_transport_flush_peer_packet) {
        const int32_t local_player_idx = *reinterpret_cast<const int32_t*>(g_h1_base + kRvaCoopLocalPlayerIndex);
        const int32_t msg_lockstep = LookupMsgIdFromIndex(g_h1_base, kRvaMsgIdLockstepFrame);
        const int32_t msg_camera = LookupMsgIdFromIndex(g_h1_base, kRvaMsgIdCameraSync);
        if (local_player_idx == 0 && (msg_id == msg_lockstep || msg_id == msg_camera) &&
            transport0 == GetTransportFromSession0() &&
            target_slot_mask != 0 && (target_slot_mask & (target_slot_mask - 1u)) != 0) {
            multi_peer_queue_flush = true;
            auto* t0_bytes = reinterpret_cast<uint8_t*>(transport0);
            // Flush any active single-peer buffer first so t0+0x138 becomes -1.
            // This forces TransportSendPacket onto the QueueMessage (0x1801D03A0) path
            // instead of writing directly into one peer's t0+0x140 buffer.
            if (*reinterpret_cast<const int32_t*>(t0_bytes + 0x138) >= 0) {
                g_fn_transport_flush_peer_packet(transport0);
            }
        }
    }

    const char ret = g_orig_transport_send_packet(transport0, target_slot_mask, msg_id, pkt_buf, pkt_bits, flags, a7);
    if (multi_peer_queue_flush) {
        auto* t0_bytes = reinterpret_cast<uint8_t*>(transport0);
        const int32_t first_slot = *reinterpret_cast<const int32_t*>(g_h1_base + kRvaRemoteClientSlotId);
        static std::atomic<int> extra_diag_budget{10};
        const bool do_diag = (extra_diag_budget.fetch_sub(1) > 0);
        for (int32_t s = 1; s < 32; ++s) {
            if ((target_slot_mask & (1u << static_cast<uint32_t>(s))) != 0) {
                const bool prep_ok = g_fn_transport_is_peer_connected(transport0, s);
                const int32_t s_peer = *reinterpret_cast<const int32_t*>(t0_bytes + 0x138);
                const int32_t s_bits = *reinterpret_cast<const int32_t*>(t0_bytes + 0x154);
                const int32_t s_msgs = *reinterpret_cast<const int32_t*>(t0_bytes + 0x168);
                if (do_diag) {
                    CE4P_LOG_INFO("[H1] MultiFlush(msg=%d, mask=0x%X) -> slot=%d prep_ok=%d peer=%d bits=%d msgs=%d",
                                  msg_id, target_slot_mask, s, prep_ok ? 1 : 0, s_peer, s_bits, s_msgs);
                }
                if (prep_ok) {
                    g_fn_transport_flush_peer_packet(transport0);
                }
            }
        }
        // Restore t0+0x138 >= 0 so caller's subsequent FlushPeerPacket(t0) never sees -1.
        if (first_slot >= 1 && first_slot < 32) {
            g_fn_transport_is_peer_connected(transport0, first_slot);
            if (*reinterpret_cast<const int32_t*>(t0_bytes + 0x138) < 0) {
                *reinterpret_cast<int32_t*>(t0_bytes + 0x138) =
                    *reinterpret_cast<const int32_t*>(t0_bytes + 0x58 + static_cast<size_t>(first_slot) * 4);
            }
        }
    } else if (g_h1_base && transport0 && g_fn_transport_is_peer_connected && g_fn_transport_flush_peer_packet) {
        const int32_t local_player_idx = *reinterpret_cast<const int32_t*>(g_h1_base + kRvaCoopLocalPlayerIndex);
        if (local_player_idx == 0 && transport0 == GetTransportFromSession0() && target_slot_mask == 0xFFFFFFFFu) {
            const uint32_t remote_mask = GetConnectedRemoteClientsMask(transport0);
            if ((remote_mask & ~2u) != 0) {
                auto* t0_bytes = reinterpret_cast<uint8_t*>(transport0);
                if (*reinterpret_cast<const int32_t*>(t0_bytes + 0x138) >= 0) {
                    g_fn_transport_flush_peer_packet(transport0);
                }
                for (int32_t s = 1; s < 32; ++s) {
                    if ((remote_mask & (1u << static_cast<uint32_t>(s))) != 0) {
                        if (g_fn_transport_is_peer_connected(transport0, s)) {
                            g_fn_transport_flush_peer_packet(transport0);
                        }
                    }
                }
            }
        }
    }
    return ret;
}

int32_t __fastcall Hook_TransportPrepareNextPacket(void* transport0) {
    const int32_t peer_idx = g_orig_transport_prepare_next_packet(transport0);
    if (peer_idx < 0 || !g_h1_base || !transport0 || transport0 != GetTransportFromSession0() ||
        !g_fn_transport_is_peer_connected || !g_fn_transport_flush_peer_packet) {
        return peer_idx;
    }

    const auto* t0_bytes = reinterpret_cast<const uint8_t*>(transport0);
    const int32_t local_peer_idx = *reinterpret_cast<const int32_t*>(t0_bytes + 0x30);
    const int32_t peer_count = *reinterpret_cast<const int32_t*>(t0_bytes + 0x50);
    const auto* peers = *reinterpret_cast<const uint8_t* const*>(t0_bytes + 0x48);
    if (!peers || local_peer_idx < 0 || local_peer_idx >= peer_count || peer_idx >= peer_count) {
        return peer_idx;
    }

    const int32_t local_slot = *reinterpret_cast<const int32_t*>(peers + static_cast<size_t>(local_peer_idx) * 0x118 + 0x08);
    if (local_slot != 0) {
        return peer_idx;
    }

    const int32_t prepared_slot = *reinterpret_cast<const int32_t*>(peers + static_cast<size_t>(peer_idx) * 0x118 + 0x08);
    const uint32_t remote_mask = GetConnectedRemoteClientsMask(transport0);
    const uint32_t prepared_bit = (prepared_slot >= 1 && prepared_slot < 32) ? (1u << static_cast<uint32_t>(prepared_slot)) : 0u;
    if ((remote_mask & ~prepared_bit) == 0) {
        return peer_idx;
    }

    // Flush the peer PrepareNextPacket just packed first, then prepare+flush all other connected remote peers
    // so Session0::Tick does not starve slot >= 2 on a 100ms per-peer cadence.
    g_fn_transport_flush_peer_packet(transport0);
    for (int32_t s = 1; s < 32; ++s) {
        if (s != prepared_slot && (remote_mask & (1u << static_cast<uint32_t>(s))) != 0) {
            if (g_fn_transport_is_peer_connected(transport0, s)) {
                g_fn_transport_flush_peer_packet(transport0);
            }
        }
    }

    static std::atomic<int> prep_diag_budget{15};
    if (prep_diag_budget.fetch_sub(1) > 0) {
        CE4P_LOG_INFO("[H1] PrepareNextPacket flushed peer_idx=%d (slot=%d) + remote_mask=0x%X",
                      peer_idx, prepared_slot, remote_mask);
    }
    return -1;
}

void __fastcall Hook_SerializeClientInputVTable(void* factory, uint8_t** pkt_58_ptr, void* bitstream) {
    g_orig_serialize_client_input_vtbl(factory, pkt_58_ptr, bitstream);
    if (g_h1_base && g_fn_bitstream_write_int && bitstream) {
        const int32_t local_idx = *reinterpret_cast<const int32_t*>(g_h1_base + kRvaCoopLocalPlayerIndex);
        const uint32_t tag = (local_idx >= 1 && local_idx <= 3) ? static_cast<uint32_t>(local_idx) : 1u;
        g_fn_bitstream_write_int(bitstream, tag, 7);
    }
}

void __fastcall Hook_DeserializeClientInput(uint8_t* pkt_58, void* bitstream) {
    g_orig_deserialize_client_input(pkt_58, bitstream);
    if (pkt_58) {
        uint32_t sender_idx = 1;
        if (g_fn_bitstream_read_int && bitstream) {
            g_fn_bitstream_read_int(bitstream, &sender_idx, 7);
        }
        if (sender_idx < 1 || sender_idx > 3) {
            sender_idx = 1;
        }
        pkt_58[0x3B] = static_cast<uint8_t>(sender_idx);
    }
}

void __fastcall Hook_SerializeLockstepVTable(void* factory, uint8_t** frame_6c_ptr, void* bitstream) {
    g_orig_serialize_lockstep_vtbl(factory, frame_6c_ptr, bitstream);
    if (!frame_6c_ptr || !*frame_6c_ptr || !g_fn_serialize_action || !bitstream) {
        return;
    }
    const uint32_t tick = *reinterpret_cast<const uint32_t*>(*frame_6c_ptr + 0x64);
    ExtraPlayersLockstep copy{};
    {
        std::lock_guard<std::mutex> lock(g_lockstep_mutex);
        const auto& slot = g_extra_lockstep_ring[tick & (kExtraLockstepRingSize - 1)];
        if (slot.valid && slot.tick_num == tick) {
            copy = slot;
        }
    }
    g_fn_serialize_action(copy.p2_swizzled, bitstream);
    g_fn_serialize_action(copy.p3_swizzled, bitstream);
}

void __fastcall Hook_DeserializeLockstepVTable(void* factory, void* bitstream, uint8_t** frame_6c_ptr) {
    g_orig_deserialize_lockstep_vtbl(factory, bitstream, frame_6c_ptr);
    if (!frame_6c_ptr || !*frame_6c_ptr || !g_fn_deserialize_action || !bitstream) {
        return;
    }
    ExtraPlayersLockstep entry{};
    entry.tick_num = *reinterpret_cast<const uint32_t*>(*frame_6c_ptr + 0x64);
    entry.valid = true;
    g_fn_deserialize_action(entry.p2_swizzled, bitstream);
    g_fn_deserialize_action(entry.p3_swizzled, bitstream);
    std::lock_guard<std::mutex> lock(g_lockstep_mutex);
    g_extra_lockstep_ring[entry.tick_num & (kExtraLockstepRingSize - 1)] = entry;
}

void __fastcall Hook_CoopLockstepOnPacket(uint8_t* mgr, uint64_t a2, int32_t msg_id, uint64_t a4, void* msg_envelope) {
    if (!g_h1_base || !msg_envelope) {
        g_orig_coop_lockstep_on_packet(mgr, a2, msg_id, a4, msg_envelope);
        return;
    }
    const int32_t msg_client_input = *reinterpret_cast<const int32_t*>(g_h1_base + kRvaMsgIdClientInput);
    const int32_t local_idx = *reinterpret_cast<const int32_t*>(g_h1_base + kRvaCoopLocalPlayerIndex);
    if (msg_id != msg_client_input || local_idx != 0) {
        g_orig_coop_lockstep_on_packet(mgr, a2, msg_id, a4, msg_envelope);
        return;
    }

    uint8_t* pkt_58 = nullptr;
    void* msg_obj = *reinterpret_cast<void* const*>(reinterpret_cast<const uint8_t*>(msg_envelope) + 0x08);
    if (msg_obj) {
        auto* vtbl = *reinterpret_cast<uintptr_t* const*>(msg_obj);
        auto fn_get = reinterpret_cast<uint8_t*(__fastcall*)(void*, void*)>(vtbl[0x38 / 8]);
        pkt_58 = fn_get(msg_obj, msg_envelope);
    }
    if (!pkt_58) {
        g_orig_coop_lockstep_on_packet(mgr, a2, msg_id, a4, msg_envelope);
        return;
    }

    uint32_t sender_idx = pkt_58[0x3B];
    if (sender_idx < 1 || sender_idx > 3) {
        sender_idx = 1;
    }
    const int16_t total_players = *reinterpret_cast<const int16_t*>(g_h1_base + kRvaCoopPlayerCount);
    uint8_t* vanilla_buf = g_h1_base ? reinterpret_cast<uint8_t*>(g_h1_base + kRvaHostRemoteClientInputBuf) : (mgr + 0x30);

    std::unique_lock<std::mutex> lock(g_lockstep_mutex);
    const int32_t orig_ack_tick = *reinterpret_cast<const int32_t*>(pkt_58 + 0x3C);
    const uint64_t orig_ack_mask = *reinterpret_cast<const uint64_t*>(pkt_58 + 0x40);
    g_client_ack_tick[sender_idx] = orig_ack_tick;

    bool clamped_ack = false;
    if (total_players > 2) {
        int32_t min_ack = orig_ack_tick;
        for (int s = 1; s < total_players && s < 4; ++s) {
            if (s != static_cast<int>(sender_idx) && g_host_client_valid[s] && g_client_ack_tick[s] < min_ack) {
                min_ack = g_client_ack_tick[s];
                clamped_ack = true;
            }
        }
        if (clamped_ack) {
            *reinterpret_cast<int32_t*>(pkt_58 + 0x3C) = min_ack;
            *reinterpret_cast<uint64_t*>(pkt_58 + 0x40) = 0;
        }
    }

    std::memcpy(vanilla_buf, g_host_client_pkt_state[sender_idx], 0x58);
    lock.unlock();

    g_orig_coop_lockstep_on_packet(mgr, a2, msg_id, a4, msg_envelope);

    lock.lock();
    if (clamped_ack) {
        *reinterpret_cast<int32_t*>(pkt_58 + 0x3C) = orig_ack_tick;
        *reinterpret_cast<uint64_t*>(pkt_58 + 0x40) = orig_ack_mask;
    }
    std::memcpy(g_host_client_pkt_state[sender_idx], vanilla_buf, 0x58);
    if (*reinterpret_cast<const int32_t*>(g_host_client_pkt_state[sender_idx] + 0x30) >= 0) {
        UnswizzleNetActionToBlam(g_host_client_pkt_state[sender_idx], g_host_client_raw_input[sender_idx]);
        g_host_client_valid[sender_idx] = true;
    }
    std::memcpy(vanilla_buf, g_host_client_pkt_state[1], 0x58);
    if (g_host_client_valid[1]) {
        int32_t min_a34 = *reinterpret_cast<const int32_t*>(g_host_client_pkt_state[1] + 0x34);
        for (int s = 2; s < 4; ++s) {
            if (g_host_client_valid[s]) {
                const int32_t a34 = *reinterpret_cast<const int32_t*>(g_host_client_pkt_state[s] + 0x34);
                if (a34 < min_a34) {
                    min_a34 = a34;
                }
            }
        }
        *reinterpret_cast<int32_t*>(vanilla_buf + 0x34) = min_a34;
    }
}

void __fastcall Hook_CoopHostCaptureActions(uint8_t* actions_4p) {
    if (g_h1_base && actions_4p) {
        const uint32_t tick = *reinterpret_cast<const uint32_t*>(g_h1_base + kRvaNextLockstepTick);
        ExtraPlayersLockstep entry{};
        entry.tick_num = tick;
        entry.valid = true;
        SwizzleBlamActionToNet(actions_4p + 2 * 0x30, entry.p2_swizzled);
        SwizzleBlamActionToNet(actions_4p + 3 * 0x30, entry.p3_swizzled);
        std::lock_guard<std::mutex> lock(g_lockstep_mutex);
        g_extra_lockstep_ring[tick & (kExtraLockstepRingSize - 1)] = entry;
    }
    g_orig_coop_host_capture_actions(actions_4p);
}

void __fastcall Hook_CoopApplyActions(uint8_t* actions_4p, uint32_t* valid_mask_ptr) {
    uint32_t peeked_tick = 0;
    bool had_queued_frame = false;
    if (g_h1_base) {
        const int32_t q_cnt = *reinterpret_cast<const int32_t*>(g_h1_base + kRvaLockstepFrameQueueCount);
        const uint8_t* q_ptr = *reinterpret_cast<const uint8_t* const*>(g_h1_base + kRvaLockstepFrameQueuePtr);
        if (q_cnt > 0 && q_ptr) {
            peeked_tick = *reinterpret_cast<const uint32_t*>(q_ptr + 0x64);
            had_queued_frame = true;
        }
    }

    g_orig_coop_apply_actions(actions_4p, valid_mask_ptr);

    if (!g_h1_base || !actions_4p || !valid_mask_ptr) {
        return;
    }
    const int16_t total_players = *reinterpret_cast<const int16_t*>(g_h1_base + kRvaCoopPlayerCount);
    if (total_players <= 2) {
        return;
    }
    const int32_t local_idx = *reinterpret_cast<const int32_t*>(g_h1_base + kRvaCoopLocalPlayerIndex);
    if (local_idx == 0 && (*valid_mask_ptr & 0x2u) != 0) {
        std::lock_guard<std::mutex> lock(g_lockstep_mutex);
        for (int s = 2; s < total_players && s < 4; ++s) {
            std::memcpy(actions_4p + static_cast<size_t>(s) * 0x30, g_host_client_raw_input[s], 0x30);
            *valid_mask_ptr |= (1u << static_cast<uint32_t>(s));
        }
    } else if (local_idx > 0 && had_queued_frame && (*valid_mask_ptr & 0x2u) != 0) {
        ExtraPlayersLockstep copy{};
        {
            std::lock_guard<std::mutex> lock(g_lockstep_mutex);
            const auto& slot = g_extra_lockstep_ring[peeked_tick & (kExtraLockstepRingSize - 1)];
            if (slot.valid && slot.tick_num == peeked_tick) {
                copy = slot;
            }
        }
        if (copy.valid) {
            if (total_players >= 3) {
                UnswizzleNetActionToBlam(copy.p2_swizzled, actions_4p + 2 * 0x30);
                *valid_mask_ptr |= (1u << 2);
            }
            if (total_players >= 4) {
                UnswizzleNetActionToBlam(copy.p3_swizzled, actions_4p + 3 * 0x30);
                *valid_mask_ptr |= (1u << 3);
            }
        }
    }

    // Deterministic opening-seat fix (a10 cryotube, a50 Pelican, etc.): if Player 0
    // has never been on foot yet and remains seated while Player 1 is on foot for 1.5s (45 ticks),
    // force-eject Player 0 and move them next to Player 1 identically on all peers.
    if (!g_p0_ever_on_foot && !g_opening_seat_eject_done && (*valid_mask_ptr & 0x1u) != 0 &&
        g_fn_unit_exit_seat_force && g_players_array_ptr && g_fn_datum_next) {
        const uint8_t* players_arr = *g_players_array_ptr;
        if (players_arr) {
            const int32_t data_off = *reinterpret_cast<const int32_t*>(players_arr + kDataArrayOffsetToData);
            const uint8_t* data_base = players_arr + data_off;
            const int32_t d0 = g_fn_datum_next(players_arr, -1);
            const int32_t d1 = (d0 != -1) ? g_fn_datum_next(players_arr, d0) : -1;
            if (d0 != -1 && d1 != -1) {
                const uint32_t p0_unit = *reinterpret_cast<const uint32_t*>(data_base + static_cast<size_t>(d0 & 0xFFFF) * kPlayerDatumStride + kPlayerDatumUnitOffset);
                const uint32_t p1_unit = *reinterpret_cast<const uint32_t*>(data_base + static_cast<size_t>(d1 & 0xFFFF) * kPlayerDatumStride + kPlayerDatumUnitOffset);
                uint32_t p0_parent = 0xFFFFFFFFu;
                int16_t p0_seat = -1;
                uint32_t p1_parent = 0xFFFFFFFFu;
                int16_t p1_seat = -1;
                float p1_pos[3]{};
                if (GetUnitSeatAndPos(p0_unit, p0_parent, p0_seat, nullptr) &&
                    GetUnitSeatAndPos(p1_unit, p1_parent, p1_seat, p1_pos)) {
                    if (p0_parent == 0xFFFFFFFFu && p0_seat == -1) {
                        g_p0_ever_on_foot = true;
                    } else if (p0_parent != 0xFFFFFFFFu && p0_seat != -1 && p1_parent == 0xFFFFFFFFu) {
                        ++g_p1_on_foot_ticks;
                        if (g_p1_on_foot_ticks >= 45) {
                            g_fn_unit_exit_seat_force(p0_unit, false, false, true);
                            float target_pos[3]{p1_pos[0], p1_pos[1] + 0.8f, p1_pos[2] + 0.05f};
                            if (g_fn_object_set_position) {
                                g_fn_object_set_position(p0_unit, target_pos, nullptr, 0);
                            }
                            if (g_fn_post_teleport) {
                                g_fn_post_teleport(p0_unit);
                            }
                            g_opening_seat_eject_done = true;
                            CE4P_LOG_INFO("[H1] OpeningSeatEject(%s): ForceExit + Move(p0=0x%X -> %.2f, %.2f, %.2f)",
                                          g_current_map_name[0] ? g_current_map_name : "?",
                                          p0_unit, target_pos[0], target_pos[1], target_pos[2]);
                        }
                    } else {
                        g_p1_on_foot_ticks = 0;
                    }
                }
            }
        }
    }
}

uint64_t __fastcall Hook_LoadLevelSolo(void* a1, void** a2, uint32_t a3, uint8_t a4_is_new) {
    const char* map_str = (a2 && *a2) ? (reinterpret_cast<const char*>(*a2) + 0xC) : "?";
    uint32_t sr = g_h1_base ? *reinterpret_cast<const uint32_t*>(g_h1_base + 0x01B7AA80) : 0xFFFFFFFFu;
    CE4P_LOG_INFO("[H1] LoadLevelSolo(map=%s, diff=%u, isNew=%u, sr=%u) enter", map_str, a3, a4_is_new, sr);
    LogStackTrace("LoadLevelSolo");
    return g_orig_load_level_solo(a1, a2, a3, a4_is_new);
}

uint64_t __fastcall Hook_LoadLevelCoop(void* a1, void** a2, uint32_t a3, uint8_t a4_is_new, uint8_t a5_is_online) {
    const char* map_str = (a2 && *a2) ? (reinterpret_cast<const char*>(*a2) + 0xC) : "?";
    uint32_t sr = g_h1_base ? *reinterpret_cast<const uint32_t*>(g_h1_base + 0x01B7AA80) : 0xFFFFFFFFu;
    CE4P_LOG_INFO(
        "[H1] LoadLevelCoop(map=%s, diff=%u, isNew=%u, isOnline=%u, sr=%u) enter",
        map_str, a3, a4_is_new, a5_is_online, sr
    );
    LogStackTrace("LoadLevelCoop");
    ResetLockstepMultiplexState();
    std::snprintf(g_current_map_name, sizeof(g_current_map_name), "%s", map_str ? map_str : "?");
    g_opening_seat_eject_done = false;
    g_p0_ever_on_foot = false;
    g_p1_on_foot_ticks = 0;

    uint64_t ret = g_orig_load_level_coop(a1, a2, a3, a4_is_new, a5_is_online);

    if (g_h1_base && a5_is_online != 0) {
        int32_t local_slot = 0;
        int32_t s0_peers = 0;
        const uint8_t* transport0 = GetTransportFromSession0(&local_slot, &s0_peers);
        int32_t total_players = 2;
        if (s0_peers >= 2 && s0_peers <= 4) {
            total_players = s0_peers;
        }
        if (g_launch_expected_players > total_players && g_launch_expected_players <= 4 && s0_peers >= 2) {
            total_players = g_launch_expected_players;
        }

        auto* coop_count = reinterpret_cast<int16_t*>(g_h1_base + kRvaCoopPlayerCount);
        auto* local_player_idx = reinterpret_cast<int32_t*>(g_h1_base + kRvaCoopLocalPlayerIndex);
        *coop_count = static_cast<int16_t>(total_players);
        if (local_slot >= 0 && local_slot < total_players) {
            *local_player_idx = local_slot;
        }

        const uint8_t is_split = *reinterpret_cast<const uint8_t*>(g_h1_base + kRvaGameModeFlags);
        CE4P_LOG_INFO(
            "[H1] LoadLevelCoop online state: s0_peers=%d, total_coop=%d, local_slot=%d, coop_local_idx=%d, is_split=%u, transport0=0x%llX",
            s0_peers,
            static_cast<int>(*coop_count),
            local_slot,
            *local_player_idx,
            static_cast<unsigned>(is_split),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(transport0))
        );
    }

    CE4P_LOG_INFO("[H1] LoadLevelCoop exit -> 0x%llX", static_cast<unsigned long long>(ret));
    return ret;
}

uint64_t __fastcall Hook_InitGameSession(void* a1, void* a2, void* a3, uint32_t a4, uint8_t a5_is_new) {
    g_init_session_entered.store(true);
    CE4P_LOG_INFO("[H1] InitGameSession(diff=%u, isNew=%u) enter", a4, a5_is_new);
    LogStackTrace("InitGameSession");
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

    uint64_t ret = g_orig_init_game_session(a1, a2, a3, a4, a5_is_new);
    if (g_h1_base) {
        auto* coop_count = reinterpret_cast<const int16_t*>(g_h1_base + kRvaCoopPlayerCount);
        const uint8_t* flags = reinterpret_cast<const uint8_t*>(g_h1_base + kRvaGameModeFlags);
        const uint8_t* srv = *reinterpret_cast<const uint8_t* const*>(g_h1_base + kRvaH1ServerPtr);
        uint16_t srv_state = srv ? *reinterpret_cast<const uint16_t*>(srv + 0x08) : 0xFFFFu;
        int srv_slots = CountActiveServerSlots(srv);
        CE4P_LOG_INFO(
            "[H1] InitGameSession(diff=%u, isNew=%u) -> ret=0x%llX, local_players=%d, flags=[%u,%u,%u,%u], srv_state=%u, srv_slots=%d",
            a4,
            a5_is_new,
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

    if (auto addr = ProbePattern(span, config, "MatchMakeTimeout1", kSigMatchMakeTimeout1)) {
        g_h1_patches.WriteBytes("MatchMakeTimeout1", *addr + 1, {0x60, 0xEA, 0x00, 0x00});
    }
    if (auto addr = ProbePattern(span, config, "MatchMakeTimeout2", kSigMatchMakeTimeout2)) {
        g_h1_patches.WriteBytes("MatchMakeTimeout2", *addr + 1, {0x60, 0xEA, 0x00, 0x00});
    }
    if (auto addr = ProbePattern(span, config, "CoopClientTargetSlot", kSigCoopClientTargetSlot)) {
        g_h1_patches.WriteBytes("CoopClientTargetSlot", *addr + 7, {0x31, 0xF6, 0x90, 0x90});
    }

    if (!g_fn_bitstream_write_int) {
        if (auto addr = ProbePattern(span, config, "BitstreamWriteInt", kSigBitstreamWriteInt)) {
            g_fn_bitstream_write_int = reinterpret_cast<FnBitstreamWriteInt>(*addr);
        }
    }
    if (!g_fn_bitstream_read_int) {
        if (auto addr = ProbePattern(span, config, "BitstreamReadInt", kSigBitstreamReadInt)) {
            g_fn_bitstream_read_int = reinterpret_cast<FnBitstreamReadInt>(*addr);
        }
    }
    if (!g_fn_serialize_action) {
        if (auto addr = ProbePattern(span, config, "SerializeAction", kSigSerializeAction)) {
            g_fn_serialize_action = reinterpret_cast<FnSerializeAction>(*addr);
        }
    }
    if (!g_fn_deserialize_action) {
        if (auto addr = ProbePattern(span, config, "DeserializeAction", kSigDeserializeAction)) {
            g_fn_deserialize_action = reinterpret_cast<FnDeserializeAction>(*addr);
        }
    }
    if (!g_fn_coop_is_session_active) {
        if (auto addr = ProbePattern(span, config, "CoopIsSessionActive", kSigCoopIsSessionActive)) {
            g_fn_coop_is_session_active = reinterpret_cast<FnCoopIsSessionActive>(*addr);
        }
    }
    if (!g_fn_transport_is_peer_connected) {
        if (auto addr = ProbePattern(span, config, "TransportIsPeerConnected", kSigTransportIsPeerConnected)) {
            g_fn_transport_is_peer_connected = reinterpret_cast<FnTransportIsPeerConnected>(*addr);
        }
    }
    if (!g_fn_transport_flush_peer_packet) {
        if (auto addr = ProbePattern(span, config, "TransportFlushPeerPacket", kSigTransportFlushPeerPacket)) {
            g_fn_transport_flush_peer_packet = reinterpret_cast<FnTransportFlushPeerPacket>(*addr);
        }
    }
    if (!g_hooked_transport_prepare_next_packet) {
        if (auto addr = ProbePattern(span, config, "TransportPrepareNextPacket", kSigTransportPrepareNextPacket)) {
            if (HookManager::Instance().InstallHook(
                    "H1::TransportPrepareNextPacket",
                    *addr,
                    reinterpret_cast<void*>(&Hook_TransportPrepareNextPacket),
                    reinterpret_cast<void**>(&g_orig_transport_prepare_next_packet)
                )) {
                g_hooked_transport_prepare_next_packet = *addr;
            }
        }
    }

    if (!g_hooked_ext_get_local_players_count) {
        if (auto addr = ProbePattern(span, config, "ExtGetLocalPlayersCount", kSigExtGetLocalPlayersCount)) {
            if (HookManager::Instance().InstallHook(
                    "H1::ExternalGetLocalPlayersCount",
                    *addr,
                    reinterpret_cast<void*>(&Hook_ExternalGetLocalPlayersCount),
                    reinterpret_cast<void**>(&g_orig_ext_get_local_players_count)
                )) {
                g_hooked_ext_get_local_players_count = *addr;
            }
        }
    }

    if (!g_hooked_coop_is_host_and_remote) {
        if (auto addr = ProbePattern(span, config, "CoopIsHostAndRemoteConn", kSigCoopIsHostAndRemoteConn)) {
            void* stub = BuildVolatilePreservingNoArgStub(reinterpret_cast<void*>(&Hook_CoopIsHostAndRemoteConnected));
            if (HookManager::Instance().InstallHook(
                    "H1::CoopIsHostAndRemoteConnected",
                    *addr,
                    stub,
                    reinterpret_cast<void**>(&g_orig_coop_is_host_and_remote)
                )) {
                g_hooked_coop_is_host_and_remote = *addr;
            }
        }
    }

    if (!g_hooked_transport_send_packet) {
        if (auto addr = ProbePattern(span, config, "TransportSendPacket", kSigTransportSendPacket)) {
            if (HookManager::Instance().InstallHook(
                    "H1::TransportSendPacket",
                    *addr,
                    reinterpret_cast<void*>(&Hook_TransportSendPacket),
                    reinterpret_cast<void**>(&g_orig_transport_send_packet)
                )) {
                g_hooked_transport_send_packet = *addr;
            }
        }
    }

    if (!g_hooked_serialize_client_input_vtbl) {
        if (auto addr = ProbePattern(span, config, "SerializeClientInputVTable", kSigSerializeClientInputVTable)) {
            if (HookManager::Instance().InstallHook(
                    "H1::SerializeClientInputVTable",
                    *addr,
                    reinterpret_cast<void*>(&Hook_SerializeClientInputVTable),
                    reinterpret_cast<void**>(&g_orig_serialize_client_input_vtbl)
                )) {
                g_hooked_serialize_client_input_vtbl = *addr;
            }
        }
    }

    if (!g_hooked_deserialize_client_input) {
        if (auto addr = ProbePattern(span, config, "DeserializeClientInput", kSigDeserializeClientInput)) {
            if (HookManager::Instance().InstallHook(
                    "H1::DeserializeClientInput",
                    *addr,
                    reinterpret_cast<void*>(&Hook_DeserializeClientInput),
                    reinterpret_cast<void**>(&g_orig_deserialize_client_input)
                )) {
                g_hooked_deserialize_client_input = *addr;
            }
        }
    }

    if (!g_hooked_serialize_lockstep_vtbl) {
        if (auto addr = ProbePattern(span, config, "SerializeLockstepVTable", kSigSerializeLockstepVTable)) {
            if (HookManager::Instance().InstallHook(
                    "H1::SerializeLockstepVTable",
                    *addr,
                    reinterpret_cast<void*>(&Hook_SerializeLockstepVTable),
                    reinterpret_cast<void**>(&g_orig_serialize_lockstep_vtbl)
                )) {
                g_hooked_serialize_lockstep_vtbl = *addr;
            }
        }
    }

    if (!g_hooked_deserialize_lockstep_vtbl) {
        if (auto addr = ProbePattern(span, config, "DeserializeLockstepVTable", kSigDeserializeLockstepVTable)) {
            if (HookManager::Instance().InstallHook(
                    "H1::DeserializeLockstepVTable",
                    *addr,
                    reinterpret_cast<void*>(&Hook_DeserializeLockstepVTable),
                    reinterpret_cast<void**>(&g_orig_deserialize_lockstep_vtbl)
                )) {
                g_hooked_deserialize_lockstep_vtbl = *addr;
            }
        }
    }

    if (!g_hooked_coop_lockstep_on_packet) {
        if (auto addr = ProbePattern(span, config, "CoopLockstepOnPacket", kSigCoopLockstepOnPacket)) {
            if (HookManager::Instance().InstallHook(
                    "H1::CoopLockstepOnPacket",
                    *addr,
                    reinterpret_cast<void*>(&Hook_CoopLockstepOnPacket),
                    reinterpret_cast<void**>(&g_orig_coop_lockstep_on_packet)
                )) {
                g_hooked_coop_lockstep_on_packet = *addr;
            }
        }
    }

    if (!g_hooked_coop_host_capture_actions) {
        if (auto addr = ProbePattern(span, config, "CoopHostCaptureActions", kSigCoopHostCaptureActions)) {
            if (HookManager::Instance().InstallHook(
                    "H1::CoopHostCaptureActions",
                    *addr,
                    reinterpret_cast<void*>(&Hook_CoopHostCaptureActions),
                    reinterpret_cast<void**>(&g_orig_coop_host_capture_actions)
                )) {
                g_hooked_coop_host_capture_actions = *addr;
            }
        }
    }

    if (!g_hooked_coop_apply_actions) {
        if (auto addr = ProbePattern(span, config, "CoopApplyActions", kSigCoopApplyActions)) {
            if (HookManager::Instance().InstallHook(
                    "H1::CoopApplyActions",
                    *addr,
                    reinterpret_cast<void*>(&Hook_CoopApplyActions),
                    reinterpret_cast<void**>(&g_orig_coop_apply_actions)
                )) {
                g_hooked_coop_apply_actions = *addr;
            }
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

    if (!g_fn_unit_exit_vehicle) {
        if (auto addr = ProbePattern(span, config, "UnitExitVehicle", kSigUnitExitVehicle)) {
            g_fn_unit_exit_vehicle = reinterpret_cast<FnUnitExitVehicle>(*addr);
            if (uintptr_t hdr_ptr = ResolveRipRelative(*addr + 0x1A, 3, 7)) {
                g_object_header_array_ptr = reinterpret_cast<const uint8_t* const*>(hdr_ptr);
            }
            if (uintptr_t pool_ptr = ResolveRipRelative(*addr + 0x2D, 3, 7)) {
                g_object_pool_ptr = reinterpret_cast<const uint8_t* const*>(pool_ptr);
            }
        }
    }
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
                if (uintptr_t force_exit = ResolveRipRelative(obj_tp + 0xD9, 1, 5)) {
                    g_fn_unit_exit_seat_force = reinterpret_cast<FnUnitExitSeatForce>(force_exit);
                }
                if (uintptr_t set_pos = ResolveRipRelative(obj_tp + 0x263, 1, 5)) {
                    g_fn_object_set_position = reinterpret_cast<FnObjectSetPosition>(set_pos);
                }
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

    if (!g_hooked_load_level_solo) {
        if (auto addr = ProbePattern(span, config, "LoadLevelSolo", kSigLoadLevelSolo)) {
            if (HookManager::Instance().InstallHook(
                    "H1::LoadLevelSolo",
                    *addr,
                    reinterpret_cast<void*>(&Hook_LoadLevelSolo),
                    reinterpret_cast<void**>(&g_orig_load_level_solo)
                )) {
                g_hooked_load_level_solo = *addr;
            }
        }
    }

    if (!g_hooked_load_level_coop) {
        if (auto addr = ProbePattern(span, config, "LoadLevelCoop", kSigLoadLevelCoop)) {
            if (HookManager::Instance().InstallHook(
                    "H1::LoadLevelCoop",
                    *addr,
                    reinterpret_cast<void*>(&Hook_LoadLevelCoop),
                    reinterpret_cast<void**>(&g_orig_load_level_coop)
                )) {
                g_hooked_load_level_coop = *addr;
            }
        }
    }

    if (!g_hooked_script_event_dispatch) {
        if (auto addr = ProbePattern(span, config, "ScriptEventDispatch", kSigScriptEventDispatch)) {
            if (HookManager::Instance().InstallHook(
                    "H1::ScriptEventDispatch",
                    *addr,
                    reinterpret_cast<void*>(&Hook_ScriptEventDispatch),
                    reinterpret_cast<void**>(&g_orig_script_event_dispatch)
                )) {
                g_hooked_script_event_dispatch = *addr;
            }
        }
    }

    if (!g_hooked_post_event) {
        if (auto addr = ProbePattern(span, config, "PostEvent", kSigPostEvent)) {
            if (HookManager::Instance().InstallHook(
                    "H1::PostEvent",
                    *addr,
                    reinterpret_cast<void*>(&Hook_PostEvent),
                    reinterpret_cast<void**>(&g_orig_post_event)
                )) {
                g_hooked_post_event = *addr;
            }
        }
    }

    if (!g_hooked_session_players_count) {
        if (auto reg_addr = ProbePattern(span, config, "RegSessionPlayersCount", kSigRegSessionPlayersCount)) {
            if (uintptr_t fn_addr = ResolveRipRelative(*reg_addr + 0xD, 3, 7)) {
                if (HookManager::Instance().InstallHook(
                        "H1::SessionPlayersCount",
                        fn_addr,
                        reinterpret_cast<void*>(&Hook_SessionPlayersCount),
                        reinterpret_cast<void**>(&g_orig_session_players_count)
                    )) {
                    g_hooked_session_players_count = fn_addr;
                }
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
    g_hold_desired = 0;
    g_hold_until_ms = 0;
    g_matchmake_peer_cmp_addr = 0;
    g_transport_advert_cmp_addr = 0;
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
    g_fn_unit_exit_vehicle = nullptr;
    g_fn_unit_exit_seat_force = nullptr;
    g_fn_object_set_position = nullptr;
    g_object_header_array_ptr = nullptr;
    g_object_pool_ptr = nullptr;
    g_current_map_name[0] = '\0';
    g_opening_seat_eject_done = false;
    g_p0_ever_on_foot = false;
    g_p1_on_foot_ticks = 0;
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
    auto unhook = [](uintptr_t& addr, auto& orig_fn) {
        if (addr) {
            HookManager::Instance().RemoveHook(addr);
            addr = 0;
            orig_fn = nullptr;
        }
    };
    unhook(g_hooked_coop_apply_actions, g_orig_coop_apply_actions);
    unhook(g_hooked_coop_host_capture_actions, g_orig_coop_host_capture_actions);
    unhook(g_hooked_coop_lockstep_on_packet, g_orig_coop_lockstep_on_packet);
    unhook(g_hooked_deserialize_lockstep_vtbl, g_orig_deserialize_lockstep_vtbl);
    unhook(g_hooked_serialize_lockstep_vtbl, g_orig_serialize_lockstep_vtbl);
    unhook(g_hooked_deserialize_client_input, g_orig_deserialize_client_input);
    unhook(g_hooked_serialize_client_input_vtbl, g_orig_serialize_client_input_vtbl);
    unhook(g_hooked_transport_send_packet, g_orig_transport_send_packet);
    unhook(g_hooked_transport_prepare_next_packet, g_orig_transport_prepare_next_packet);
    unhook(g_hooked_coop_is_host_and_remote, g_orig_coop_is_host_and_remote);
    unhook(g_hooked_ext_get_local_players_count, g_orig_ext_get_local_players_count);
    unhook(g_hooked_session_players_count, g_orig_session_players_count);
    unhook(g_hooked_post_event, g_orig_post_event);
    unhook(g_hooked_script_event_dispatch, g_orig_script_event_dispatch);
    unhook(g_hooked_load_level_coop, g_orig_load_level_coop);
    unhook(g_hooked_load_level_solo, g_orig_load_level_solo);
    g_fn_bitstream_write_int = nullptr;
    g_fn_bitstream_read_int = nullptr;
    g_fn_serialize_action = nullptr;
    g_fn_deserialize_action = nullptr;
    g_fn_coop_is_session_active = nullptr;
    g_fn_transport_is_peer_connected = nullptr;
    g_fn_transport_flush_peer_packet = nullptr;
    ResetLockstepMultiplexState();

    g_h1_patches.RevertAll();
    g_h1_base = 0;
    g_active_snapshot.reset();
    CE4P_LOG_INFO("[H1] Cleaned up halo1.dll hooks and patches.");
}

}  // namespace ce4p::h1
