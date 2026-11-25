#include "core/spawn_helper.hpp"

#include <cmath>

namespace ce4p {

namespace {
constexpr float kPi = 3.14159265358979323846f;
}  // namespace

Vec3 ComputeClonedSpawnPosition(Vec3 base_anchor, int player_index, int total_players, float radius) {
    if (player_index <= 0 || radius <= 0.0f) {
        return base_anchor;
    }

    int extra_count = (total_players > 1) ? (total_players - 1) : 1;
    int slot = (player_index - 1) % extra_count;
    float angle = (2.0f * kPi * static_cast<float>(slot)) / static_cast<float>(extra_count);

    Vec3 out = base_anchor;
    out.x += radius * std::cos(angle);
    out.y += radius * std::sin(angle);
    // Slight +Z lift avoids floor clipping on uneven terrain.
    out.z += 0.05f;
    return out;
}

}  // namespace ce4p
