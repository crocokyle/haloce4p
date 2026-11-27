#include "core/config.hpp"
#include "core/spawn_helper.hpp"

#include <cassert>
#include <cmath>
#include <iostream>

namespace {

void TestConfigParsing() {
    const std::string ini = R"(
# Comment line
[General]
AllocConsole = false
TargetMaxPlayers = 4
ForceTestPlayerCount = 4
ForceTestPartySize = 3
EnableSpawnCloning = true
SpawnCloneRadius = 2.5 ; inline comment
EnableCatchupTeleport = 0

[Signatures]
CampaignPlayerCap = 48 83 F8 02 7F ?
GameCreatePlayer = 48 89 5C 24 ? 57

[MissionSpawns]
a10 = eject, x=0.25, y=-1.2, z=0.10, delay=2.0, cutscene=false
a10.p1 = y=-1.6, z=0.0
b30 = both, x=1.0, y=0.5, z=0.0, delay_ticks=60, cutscene=true
c40.p3 = none
)";

    ce4p::ModConfig cfg = ce4p::ParseConfigText(ini);
    assert(!cfg.alloc_console);
    assert(cfg.target_max_players == 4);
    assert(cfg.force_test_player_count == 4);
    assert(cfg.force_test_party_size == 3);
    assert(cfg.enable_spawn_cloning);
    assert(std::fabs(cfg.spawn_clone_radius - 2.5f) < 1e-5f);
    assert(!cfg.enable_catchup_teleport);
    assert(cfg.GetSignature("CampaignPlayerCap", "") == "48 83 F8 02 7F ?");
    assert(cfg.GetSignature("GameCreatePlayer", "") == "48 89 5C 24 ? 57");
    assert(cfg.GetSignature("MissingKey", "DEFAULT") == "DEFAULT");

    // Built-in default preserved for a30: p1/p2 untouched, p3 has separate+cutscene
    const auto a30_p1 = cfg.GetMissionSpawn("a30", 0);
    assert(!a30_p1.eject && !a30_p1.separate);
    const auto a30_p3 = cfg.GetMissionSpawn("a30", 2);
    assert(!a30_p3.eject && a30_p3.separate && a30_p3.during_cutscene && a30_p3.custom_offset);
    assert(std::fabs(a30_p3.offset_x - 0.8f) < 1e-5f);

    // Overridden a10, per-player a10.p1 inheritance, newly added b30, and disabled c40.p3
    const auto a10_p2 = cfg.GetMissionSpawn("a10", 1);
    assert(a10_p2.eject && !a10_p2.separate && a10_p2.delay_ticks == 60 && !a10_p2.custom_offset);
    assert(std::fabs(a10_p2.offset_x - 0.25f) < 1e-5f);
    assert(std::fabs(a10_p2.offset_y - (-1.2f)) < 1e-5f);
    assert(std::fabs(a10_p2.offset_z - 0.10f) < 1e-5f);

    const auto a10_p1 = cfg.GetMissionSpawn("a10", 0);
    assert(a10_p1.eject && a10_p1.delay_ticks == 60 && a10_p1.custom_offset);
    assert(std::fabs(a10_p1.offset_x - 0.25f) < 1e-5f);
    assert(std::fabs(a10_p1.offset_y - (-1.6f)) < 1e-5f);
    assert(std::fabs(a10_p1.offset_z - 0.0f) < 1e-5f);

    const auto b30 = cfg.GetMissionSpawn("b30", 2);
    assert(b30.eject && b30.separate && b30.delay_ticks == 60 && b30.during_cutscene);
    assert(std::fabs(b30.offset_x - 1.0f) < 1e-5f);
    assert(std::fabs(b30.offset_y - 0.5f) < 1e-5f);

    const auto c40_p3 = cfg.GetMissionSpawn("c40", 2);
    assert(!c40_p3.eject && !c40_p3.separate);
}

void TestSpawnHelper() {
    ce4p::Vec3 base{10.0f, 20.0f, 5.0f};

    // Player 0 keeps the exact anchor
    ce4p::Vec3 p0 = ce4p::ComputeClonedSpawnPosition(base, 0, 4, 2.0f);
    assert(p0.x == base.x && p0.y == base.y && p0.z == base.z);

    // Players 1, 2, 3 are distributed on a circle of radius 2.0 around base
    ce4p::Vec3 p1 = ce4p::ComputeClonedSpawnPosition(base, 1, 4, 2.0f);
    ce4p::Vec3 p2 = ce4p::ComputeClonedSpawnPosition(base, 2, 4, 2.0f);
    ce4p::Vec3 p3 = ce4p::ComputeClonedSpawnPosition(base, 3, 4, 2.0f);

    auto dist_xy = [&](ce4p::Vec3 a, ce4p::Vec3 b) {
        return std::hypot(a.x - b.x, a.y - b.y);
    };

    assert(std::fabs(dist_xy(p1, base) - 2.0f) < 1e-4f);
    assert(std::fabs(dist_xy(p2, base) - 2.0f) < 1e-4f);
    assert(std::fabs(dist_xy(p3, base) - 2.0f) < 1e-4f);
    // Ensure extra players do not overlap each other
    assert(dist_xy(p1, p2) > 3.0f);
    assert(dist_xy(p2, p3) > 3.0f);
    assert(dist_xy(p1, p3) > 3.0f);
}

}  // namespace

int main() {
    TestConfigParsing();
    TestSpawnHelper();
    std::cout << "All config and spawn helper tests passed.\n";
    return 0;
}
