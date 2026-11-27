#pragma once

#include "core/config.hpp"
#include "core/module_watcher.hpp"

namespace ce4p::h1 {

// Sets the path to ce_4player.ini for automatic hot-reload on mission launch.
void SetConfigPath(const std::string& path);

// Called when halo1.dll is loaded by MCC.
void OnModuleLoaded(const ModuleSnapshot& snapshot, const ModConfig& config);

// Re-runs pattern probes against halo1.dll if currently loaded.
void RescanIfLoaded(const ModConfig& config);

// Called when halo1.dll is unloaded by MCC.
void OnModuleUnloaded(const ModuleSnapshot& snapshot);

}  // namespace ce4p::h1
