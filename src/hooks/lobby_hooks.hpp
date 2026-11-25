#pragma once

#include "core/config.hpp"

namespace ce4p::lobby {

// Installs hooks/probes on MCC-Win64-Shipping.exe to allow 4-player parties
// in Halo: CE Campaign lobbies and pass 4 players into halo1.dll.
bool Initialize(const ModConfig& config);
void Rescan(const ModConfig& config);
void Shutdown();

}  // namespace ce4p::lobby
