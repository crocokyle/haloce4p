#pragma once

#include <windows.h>

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

    std::string target_module_;
    ModuleCallback on_loaded_;
    ModuleCallback on_unloaded_;
    HANDLE thread_ = nullptr;
    volatile bool stop_requested_ = false;
};

}  // namespace ce4p
