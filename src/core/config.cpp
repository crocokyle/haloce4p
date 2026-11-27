#include "core/config.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
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

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
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

void ApplyMissionMode(const std::string& mode, MissionSpawnConfig& rule) {
    const std::string m = ToLower(Trim(mode));
    if (m == "eject") {
        rule.eject = true;
        rule.separate = false;
    } else if (m == "separate") {
        rule.eject = false;
        rule.separate = true;
    } else if (m == "both") {
        rule.eject = true;
        rule.separate = true;
    } else if (m == "none" || m == "off") {
        rule.eject = false;
        rule.separate = false;
    }
}

MissionSpawnConfig ParseMissionSpawnValue(const std::string& val,
                                          const MissionSpawnConfig& base,
                                          bool is_player_override) {
    MissionSpawnConfig rule = base;
    std::istringstream tokens(val);
    std::string tok;
    while (std::getline(tokens, tok, ',')) {
        tok = Trim(tok);
        if (tok.empty()) {
            continue;
        }
        const auto eq = tok.find('=');
        if (eq == std::string::npos) {
            ApplyMissionMode(tok, rule);
            continue;
        }
        const std::string k = ToLower(Trim(tok.substr(0, eq)));
        const std::string v = Trim(tok.substr(eq + 1));
        try {
            if (k == "mode") {
                ApplyMissionMode(v, rule);
            } else if (k == "x") {
                rule.offset_x = std::stof(v);
                if (is_player_override) rule.custom_offset = true;
            } else if (k == "y") {
                rule.offset_y = std::stof(v);
                if (is_player_override) rule.custom_offset = true;
            } else if (k == "z") {
                rule.offset_z = std::stof(v);
                if (is_player_override) rule.custom_offset = true;
            } else if (k == "delay") {
                const float secs = std::stof(v);
                rule.delay_ticks = std::max(0, static_cast<int>(std::lround(secs * 30.0f)));
            } else if (k == "delay_ticks") {
                rule.delay_ticks = std::max(0, std::stoi(v));
            } else if (k == "cutscene") {
                rule.during_cutscene = ParseBool(v, rule.during_cutscene);
            }
        } catch (...) {
        }
    }
    return rule;
}

}  // namespace

std::unordered_map<std::string, MissionSpawnConfig> DefaultMissionSpawns() {
    std::unordered_map<std::string, MissionSpawnConfig> m;
    // a10: Pillar of Autumn — Player 0 starts locked in cryochamber
    m["a10"] = MissionSpawnConfig{true, false, 45, 0.0f, -0.8f, 0.05f, false};
    // a30: Halo — Players 1 and 2 spawn overlapping during/after intro
    m["a30"] = MissionSpawnConfig{false, true, 45, 0.8f, 0.0f, 0.05f, true};
    // a50: Truth and Reconciliation — Player 0 starts seated in Pelican
    m["a50"] = MissionSpawnConfig{true, false, 45, 0.0f, 0.8f, 0.05f, false};
    // c10: 343 Guilty Spark — Players 2..3 start seated in Pelican
    m["c10"] = MissionSpawnConfig{true, false, 45, 0.0f, 0.8f, 0.05f, false};
    // c40: Two Betrayals — Players 0 and 1 spawn overlapping in Control Room
    m["c40"] = MissionSpawnConfig{false, true, 45, 0.8f, 0.0f, 0.05f, false};
    return m;
}

std::string ModConfig::GetSignature(const std::string& key, const char* fallback) const {
    auto it = signature_overrides.find(key);
    if (it != signature_overrides.end() && !it->second.empty()) {
        return it->second;
    }
    return fallback ? std::string(fallback) : std::string();
}

MissionSpawnConfig ModConfig::GetMissionSpawn(const std::string& map_name, int player_index) const {
    const std::string map_key = ToLower(map_name);
    if (player_index >= 0 && player_index < 4) {
        const auto pit = mission_spawns.find(map_key + ".p" + std::to_string(player_index));
        if (pit != mission_spawns.end()) {
            return pit->second;
        }
    }
    const auto it = mission_spawns.find(map_key);
    if (it != mission_spawns.end()) {
        return it->second;
    }
    return MissionSpawnConfig{};
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

        if (section == "MissionSpawns") {
            if (!key.empty()) {
                const std::string map_key = ToLower(key);
                const size_t dot = map_key.rfind('.');
                const bool is_player_override =
                    (dot != std::string::npos && map_key.size() == dot + 3 &&
                     map_key[dot + 1] == 'p' &&
                     map_key[dot + 2] >= '0' && map_key[dot + 2] <= '3');
                MissionSpawnConfig base{};
                if (const auto it = cfg.mission_spawns.find(map_key); it != cfg.mission_spawns.end()) {
                    base = it->second;
                } else if (is_player_override) {
                    const std::string mission_key = map_key.substr(0, dot);
                    if (const auto mit = cfg.mission_spawns.find(mission_key); mit != cfg.mission_spawns.end()) {
                        base = mit->second;
                    }
                }
                cfg.mission_spawns[map_key] = ParseMissionSpawnValue(val, base, is_player_override);
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
        } else if (key == "ForceTestPartySize") {
            int parsed = std::atoi(val.c_str());
            if (parsed >= 0 && parsed <= 16) {
                cfg.force_test_party_size = parsed;
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
        } else if (key == "EnableInputAutomation") {
            cfg.enable_input_automation = ParseBool(val, cfg.enable_input_automation);
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
