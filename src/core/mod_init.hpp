#pragma once

namespace ce4p {

// Safe to call from Proxy_GetFileVersionInfo* (outside loader lock).
// Initializes logging, MinHook, and MCC lobby hooks once before UE4 finishes booting.
void EnsureEarlyInit();

}  // namespace ce4p
