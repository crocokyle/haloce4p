#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace ce4p {

struct MissionSpawnConfig {
    bool eject = false;
    bool separate = false;
    int delay_ticks = 45;
    float offset_x = 0.0f;
    float offset_y = 0.8f;
    float offset_z = 0.05f;
    bool during_cutscene = false;
    bool custom_offset = false;
};

// Returns the built-in per-mission spawn defaults (a10, a30, a50, c10, c40).
std::unordered_map<std::string, MissionSpawnConfig> DefaultMissionSpawns();

struct ModConfig {
    bool alloc_console = true;
    int target_max_players = 4;
    int force_test_player_count = 0;  // 0 = disabled; set to 2..4 for solo multi-player spawn testing
    int force_test_party_size = 0;    // 0 = disabled; set to 3..4 to spoof MCC lobby GetTotalPlayerCount()
    bool enable_spawn_cloning = true;
    float spawn_clone_radius = 1.25f;
    bool enable_catchup_teleport = true;
    bool enable_input_automation = false;

    // Optional runtime AOB signature overrides loaded from [Signatures] in ce_4player.ini.
    // Allows testing newly discovered signatures without recompiling version.dll.
    std::unordered_map<std::string, std::string> signature_overrides;

    // Per-mission opening seat-eject / overlap-separation rules loaded from [MissionSpawns].
    std::unordered_map<std::string, MissionSpawnConfig> mission_spawns = DefaultMissionSpawns();

    std::string GetSignature(const std::string& key, const char* fallback) const;
    MissionSpawnConfig GetMissionSpawn(const std::string& map_name, int player_index = -1) const;
};

// Parses an INI string (portable, used by both Windows loader and unit tests).
ModConfig ParseConfigText(const std::string& text);

// Loads config from disk; returns defaults if the file does not exist.
ModConfig LoadConfigFile(const std::string& path);

}  // namespace ce4p
