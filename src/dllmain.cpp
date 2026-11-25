#include <windows.h>

#include "core/config.hpp"
#include "core/hook_manager.hpp"
#include "core/logger.hpp"
#include "core/module_watcher.hpp"
#include "hooks/h1_engine_hooks.hpp"
#include "hooks/lobby_hooks.hpp"

#include <cstdio>
#include <iostream>
#include <mutex>
#include <string>

namespace {

ce4p::ModuleWatcher g_h1_watcher;
ce4p::ModConfig g_config;
std::mutex g_config_mutex;
std::string g_base_dir;
HANDLE g_init_thread = nullptr;
volatile bool g_stop_console = false;

std::string GetModuleDir(HMODULE self) {
    char path[MAX_PATH]{};
    DWORD len = GetModuleFileNameA(self, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return "";
    }
    std::string full(path, len);
    size_t slash = full.find_last_of("\\/");
    if (slash == std::string::npos) {
        return "";
    }
    return full.substr(0, slash + 1);
}

void RunConsoleCommandLoop() {
    FILE* dummy = nullptr;
    freopen_s(&dummy, "CONIN$", "r", stdin);

    CE4P_LOG_INFO("Diagnostic console ready. Type 'help' for commands.");
    std::string line;
    while (!g_stop_console && std::getline(std::cin, line)) {
        if (line == "help") {
            CE4P_LOG_INFO("Commands: help | status | reload | rescan");
        } else if (line == "status") {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            CE4P_LOG_INFO(
                "Status: target_max_players=%d, spawn_cloning=%s, overrides=%zu",
                g_config.target_max_players,
                g_config.enable_spawn_cloning ? "true" : "false",
                g_config.signature_overrides.size()
            );
        } else if (line == "reload") {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            g_config = ce4p::LoadConfigFile(g_base_dir + "ce_4player.ini");
            CE4P_LOG_INFO("Reloaded ce_4player.ini (%zu signature overrides).", g_config.signature_overrides.size());
        } else if (line == "rescan") {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            ce4p::lobby::Rescan(g_config);
            ce4p::h1::RescanIfLoaded(g_config);
        } else if (!line.empty()) {
            CE4P_LOG_WARN("Unknown command '%s'. Type 'help' for commands.", line.c_str());
        }
    }
}

DWORD WINAPI InitializeModThread(LPVOID param) {
    auto self = static_cast<HMODULE>(param);
    g_base_dir = GetModuleDir(self);

    {
        std::lock_guard<std::mutex> lock(g_config_mutex);
        g_config = ce4p::LoadConfigFile(g_base_dir + "ce_4player.ini");
    }

    ce4p::Logger::Instance().Init(g_base_dir + "ce_4player.log", g_config.alloc_console);
    CE4P_LOG_INFO("====================================================");
    CE4P_LOG_INFO("Halo: CE 4-Player Co-op Mod (Diagnostic Proxy) v0.1");
    CE4P_LOG_INFO("====================================================");

    if (!ce4p::HookManager::Instance().Initialize()) {
        CE4P_LOG_ERROR("HookManager initialization failed; aborting hook setup.");
        return 1;
    }

    {
        std::lock_guard<std::mutex> lock(g_config_mutex);
        ce4p::lobby::Initialize(g_config);
    }

    g_h1_watcher.Start(
        "halo1.dll",
        [](const ce4p::ModuleSnapshot& snap) {
            std::lock_guard<std::mutex> lock(g_config_mutex);
            ce4p::h1::OnModuleLoaded(snap, g_config);
        },
        [](const ce4p::ModuleSnapshot& snap) { ce4p::h1::OnModuleUnloaded(snap); }
    );

    CE4P_LOG_INFO("Mod initialization complete. Watching for halo1.dll...");

    if (g_config.alloc_console) {
        RunConsoleCommandLoop();
    }
    return 0;
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        g_init_thread = CreateThread(nullptr, 0, InitializeModThread, hModule, 0, nullptr);
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        g_stop_console = true;
        g_h1_watcher.Stop();
        ce4p::lobby::Shutdown();
        ce4p::HookManager::Instance().Shutdown();
        ce4p::Logger::Instance().Shutdown();
        if (g_init_thread) {
            CloseHandle(g_init_thread);
            g_init_thread = nullptr;
        }
    }
    return TRUE;
}
