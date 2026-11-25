#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace ce4p {

struct ModConfig {
    bool alloc_console = true;
    int target_max_players = 4;
    int force_test_player_count = 0;  // 0 = disabled; set to 2..4 for solo multi-player spawn testing
    bool enable_spawn_cloning = true;
    float spawn_clone_radius = 1.25f;
    bool enable_catchup_teleport = true;
    bool enable_input_automation = false;

    // Optional runtime AOB signature overrides loaded from [Signatures] in ce_4player.ini.
    // Allows testing newly discovered signatures without recompiling version.dll.
    std::unordered_map<std::string, std::string> signature_overrides;

    std::string GetSignature(const std::string& key, const char* fallback) const;
};

// Parses an INI string (portable, used by both Windows loader and unit tests).
ModConfig ParseConfigText(const std::string& text);

// Loads config from disk; returns defaults if the file does not exist.
ModConfig LoadConfigFile(const std::string& path);

}  // namespace ce4p
