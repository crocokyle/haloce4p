#include "core/config.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace ce4p {

namespace {

std::string Trim(std::string s) {
    auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

bool ParseBool(const std::string& v, bool fallback) {
    std::string lower = v;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (lower == "1" || lower == "true" || lower == "yes" || lower == "on") return true;
    if (lower == "0" || lower == "false" || lower == "no" || lower == "off") return false;
    return fallback;
}

}  // namespace

std::string ModConfig::GetSignature(const std::string& key, const char* fallback) const {
    auto it = signature_overrides.find(key);
    if (it != signature_overrides.end() && !it->second.empty()) {
        return it->second;
    }
    return fallback ? std::string(fallback) : std::string();
}

ModConfig ParseConfigText(const std::string& text) {
    ModConfig cfg;
    std::istringstream stream(text);
    std::string line;
    std::string section;

    while (std::getline(stream, line)) {
        // Strip inline comments starting with '#' or ';'
        size_t comment_pos = line.find_first_of("#;");
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }
        line = Trim(line);
        if (line.empty()) {
            continue;
        }

        if (line.front() == '[' && line.back() == ']') {
            section = Trim(line.substr(1, line.size() - 2));
            continue;
        }

        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }

        std::string key = Trim(line.substr(0, eq));
        std::string val = Trim(line.substr(eq + 1));

        if (section == "Signatures") {
            if (!key.empty()) {
                cfg.signature_overrides[key] = val;
            }
            continue;
        }

        // [General] or top-level keys
        if (key == "AllocConsole") {
            cfg.alloc_console = ParseBool(val, cfg.alloc_console);
        } else if (key == "TargetMaxPlayers") {
            int parsed = std::atoi(val.c_str());
            if (parsed >= 2 && parsed <= 16) {
                cfg.target_max_players = parsed;
            }
        } else if (key == "ForceTestPlayerCount") {
            int parsed = std::atoi(val.c_str());
            if (parsed >= 0 && parsed <= 4) {
                cfg.force_test_player_count = parsed;
            }
        } else if (key == "EnableSpawnCloning") {
            cfg.enable_spawn_cloning = ParseBool(val, cfg.enable_spawn_cloning);
        } else if (key == "SpawnCloneRadius") {
            float parsed = std::strtof(val.c_str(), nullptr);
            if (parsed > 0.0f && parsed <= 10.0f) {
                cfg.spawn_clone_radius = parsed;
            }
        } else if (key == "EnableCatchupTeleport") {
            cfg.enable_catchup_teleport = ParseBool(val, cfg.enable_catchup_teleport);
        }
    }

    return cfg;
}

ModConfig LoadConfigFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return ModConfig{};
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    return ParseConfigText(ss.str());
}

}  // namespace ce4p
