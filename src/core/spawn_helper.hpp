#pragma once

namespace ce4p {

struct Vec3 {
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
};

// Computes a collision-safe spawn position for player_index when the scenario
// only defines fewer than (player_index + 1) starting locations.
// Players 0..available_spawns-1 keep their exact anchor; extra players are placed
// in a ring around the base anchor at `radius` world units (Halo world units ~ meters/3).
Vec3 ComputeClonedSpawnPosition(Vec3 base_anchor, int player_index, int total_players, float radius);

}  // namespace ce4p
