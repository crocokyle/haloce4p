#pragma once

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>

namespace ce4p {

struct ModuleSnapshot {
    std::string name;
    HMODULE handle = nullptr;
    uintptr_t base = 0;
    size_t size = 0;
    uint32_t pe_timestamp = 0;
};

using ModuleCallback = std::function<void(const ModuleSnapshot&)>;

class ModuleWatcher {
public:
    ModuleWatcher() = default;
    ~ModuleWatcher();

    void Start(
        std::string target_module,
        ModuleCallback on_loaded,
        ModuleCallback on_unloaded
    );
    void Stop();

private:
    void PollLoop();
    void RegisterDllNotification();
    void UnregisterDllNotification();

    std::string target_module_;
    std::wstring target_module_wide_;
    ModuleCallback on_loaded_;
    ModuleCallback on_unloaded_;
    HANDLE thread_ = nullptr;
    HANDLE wake_event_ = nullptr;
    PVOID ldr_cookie_ = nullptr;
    std::atomic<uint64_t> unload_seq_{0};
    volatile bool stop_requested_ = false;
};

}  // namespace ce4p
