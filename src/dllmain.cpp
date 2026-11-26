#include <windows.h>

#include "core/config.hpp"
#include "core/hook_manager.hpp"
#include "core/input_automation.hpp"
#include "core/logger.hpp"
#include "core/mod_init.hpp"
#include "core/module_watcher.hpp"
#include "hooks/h1_engine_hooks.hpp"
#include "hooks/lobby_hooks.hpp"

#include <intrin.h>
#include <atomic>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <string>

namespace {

void LogCallerAddress(const char* tag, uintptr_t addr, uint64_t arg1) {
    HMODULE mod = nullptr;
    char mod_name[MAX_PATH] = "<unknown>";
    uintptr_t offset = 0;
    if (GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(addr),
            &mod) && mod) {
        GetModuleFileNameA(mod, mod_name, MAX_PATH);
        offset = addr - reinterpret_cast<uintptr_t>(mod);
    }
    const char* base_name = mod_name;
    for (const char* p = mod_name; *p; ++p) {
        if (*p == '\\' || *p == '/') {
            base_name = p + 1;
        }
    }
    CE4P_LOG_ERROR(
        "[CRASH:%s] arg=0x%llX caller=0x%llX (%s+0x%llX)",
        tag,
        static_cast<unsigned long long>(arg1),
        static_cast<unsigned long long>(addr),
        base_name,
        static_cast<unsigned long long>(offset)
    );
}

using FnExitProcess = void(WINAPI*)(UINT);
FnExitProcess g_orig_exit_process = nullptr;
void WINAPI Hook_ExitProcess(UINT code) {
    LogCallerAddress("ExitProcess", reinterpret_cast<uintptr_t>(__builtin_return_address(0)), code);
    g_orig_exit_process(code);
}

using FnTerminateProcess = BOOL(WINAPI*)(HANDLE, UINT);
FnTerminateProcess g_orig_terminate_process = nullptr;
BOOL WINAPI Hook_TerminateProcess(HANDLE proc, UINT code) {
    if (proc == GetCurrentProcess() || GetProcessId(proc) == GetCurrentProcessId()) {
        LogCallerAddress("TerminateProcess", reinterpret_cast<uintptr_t>(__builtin_return_address(0)), code);
    }
    return g_orig_terminate_process(proc, code);
}

using FnRaiseFailFastException = void(WINAPI*)(PEXCEPTION_RECORD, PCONTEXT, DWORD);
FnRaiseFailFastException g_orig_raise_fail_fast = nullptr;
void WINAPI Hook_RaiseFailFastException(PEXCEPTION_RECORD rec, PCONTEXT ctx, DWORD flags) {
    uintptr_t addr = rec ? reinterpret_cast<uintptr_t>(rec->ExceptionAddress)
                         : reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    LogCallerAddress("RaiseFailFast", addr, rec ? rec->ExceptionCode : flags);
    g_orig_raise_fail_fast(rec, ctx, flags);
}

std::atomic<bool> g_crash_logged{false};

LONG CALLBACK CrashVectoredHandler(PEXCEPTION_POINTERS ep) {
    if (!ep || !ep->ExceptionRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_INT_DIVIDE_BY_ZERO &&
        code != EXCEPTION_ARRAY_BOUNDS_EXCEEDED &&
        code != EXCEPTION_STACK_OVERFLOW &&
        code != EXCEPTION_BREAKPOINT &&
        code != 0xC0000409ul) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (g_crash_logged.exchange(true)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    uintptr_t addr = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
    HMODULE mod = nullptr;
    char mod_name[MAX_PATH] = "<unknown>";
    uintptr_t offset = 0;
    if (GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(addr),
            &mod) && mod) {
        GetModuleFileNameA(mod, mod_name, MAX_PATH);
        offset = addr - reinterpret_cast<uintptr_t>(mod);
    }
    const char* base_name = mod_name;
    for (const char* p = mod_name; *p; ++p) {
        if (*p == '\\' || *p == '/') {
            base_name = p + 1;
        }
    }

    auto* ctx = ep->ContextRecord;
    CE4P_LOG_ERROR(
        "[CRASH] code=0x%08lX addr=0x%llX (%s+0x%llX) rsp=0x%llX rcx=0x%llX rdx=0x%llX r8=0x%llX r9=0x%llX",
        code,
        static_cast<unsigned long long>(addr),
        base_name,
        static_cast<unsigned long long>(offset),
        ctx ? static_cast<unsigned long long>(ctx->Rsp) : 0ull,
        ctx ? static_cast<unsigned long long>(ctx->Rcx) : 0ull,
        ctx ? static_cast<unsigned long long>(ctx->Rdx) : 0ull,
        ctx ? static_cast<unsigned long long>(ctx->R8) : 0ull,
        ctx ? static_cast<unsigned long long>(ctx->R9) : 0ull
    );
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        CE4P_LOG_ERROR(
            "[CRASH] AV type=%llu target=0x%llX",
            static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[0]),
            static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[1])
        );
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

HMODULE g_self_module = nullptr;
ce4p::ModuleWatcher g_h1_watcher;
ce4p::InputAutomation g_input_automation;
ce4p::ModConfig g_config;
std::mutex g_config_mutex;
std::string g_base_dir;
HANDLE g_init_thread = nullptr;
INIT_ONCE g_early_init_once = INIT_ONCE_STATIC_INIT;
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

BOOL CALLBACK DoEarlyInit(PINIT_ONCE /*init_once*/, PVOID /*param*/, PVOID* /*context*/) {
    g_base_dir = GetModuleDir(g_self_module);

    {
        std::lock_guard<std::mutex> lock(g_config_mutex);
        g_config = ce4p::LoadConfigFile(g_base_dir + "ce_4player.ini");
    }

    ce4p::Logger::Instance().Init(g_base_dir + "ce_4player.log", g_config.alloc_console);
    AddVectoredExceptionHandler(1, CrashVectoredHandler);
    SetUnhandledExceptionFilter(CrashVectoredHandler);
    CE4P_LOG_INFO("====================================================");
    CE4P_LOG_INFO("Halo: CE 4-Player Co-op Mod (Diagnostic Proxy) v0.1");
    CE4P_LOG_INFO("====================================================");

    if (!ce4p::HookManager::Instance().Initialize()) {
        CE4P_LOG_ERROR("HookManager initialization failed; aborting hook setup.");
        return TRUE;
    }

    if (HMODULE k32 = GetModuleHandleA("kernel32.dll")) {
        if (auto p = reinterpret_cast<uintptr_t>(GetProcAddress(k32, "ExitProcess"))) {
            ce4p::HookManager::Instance().InstallHook("K32::ExitProcess", p, reinterpret_cast<void*>(&Hook_ExitProcess), reinterpret_cast<void**>(&g_orig_exit_process));
        }
        if (auto p = reinterpret_cast<uintptr_t>(GetProcAddress(k32, "TerminateProcess"))) {
            ce4p::HookManager::Instance().InstallHook("K32::TerminateProcess", p, reinterpret_cast<void*>(&Hook_TerminateProcess), reinterpret_cast<void**>(&g_orig_terminate_process));
        }
        if (auto p = reinterpret_cast<uintptr_t>(GetProcAddress(k32, "RaiseFailFastException"))) {
            ce4p::HookManager::Instance().InstallHook("K32::RaiseFailFastException", p, reinterpret_cast<void*>(&Hook_RaiseFailFastException), reinterpret_cast<void**>(&g_orig_raise_fail_fast));
        }
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

    if (g_config.enable_input_automation) {
        g_input_automation.Start(g_base_dir + "ce_4player_input.txt");
    }

    CE4P_LOG_INFO("Early init complete. Watching for halo1.dll...");
    return TRUE;
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

DWORD WINAPI InitializeModThread(LPVOID /*param*/) {
    ce4p::EnsureEarlyInit();
    if (g_config.alloc_console) {
        RunConsoleCommandLoop();
    }
    return 0;
}

}  // namespace

namespace ce4p {

void EnsureEarlyInit() {
    InitOnceExecuteOnce(&g_early_init_once, DoEarlyInit, nullptr, nullptr);
}

}  // namespace ce4p

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_self_module = hModule;
        DisableThreadLibraryCalls(hModule);
        g_init_thread = CreateThread(nullptr, 0, InitializeModThread, hModule, 0, nullptr);
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        g_stop_console = true;
        g_input_automation.Stop();
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
