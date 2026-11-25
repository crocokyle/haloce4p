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
EnableSpawnCloning = true
SpawnCloneRadius = 2.5 ; inline comment
EnableCatchupTeleport = 0

[Signatures]
CampaignPlayerCap = 48 83 F8 02 7F ?
GameCreatePlayer = 48 89 5C 24 ? 57
)";

    ce4p::ModConfig cfg = ce4p::ParseConfigText(ini);
    assert(!cfg.alloc_console);
    assert(cfg.target_max_players == 4);
    assert(cfg.force_test_player_count == 4);
    assert(cfg.enable_spawn_cloning);
    assert(std::fabs(cfg.spawn_clone_radius - 2.5f) < 1e-5f);
    assert(!cfg.enable_catchup_teleport);
    assert(cfg.GetSignature("CampaignPlayerCap", "") == "48 83 F8 02 7F ?");
    assert(cfg.GetSignature("GameCreatePlayer", "") == "48 89 5C 24 ? 57");
    assert(cfg.GetSignature("MissingKey", "DEFAULT") == "DEFAULT");
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
