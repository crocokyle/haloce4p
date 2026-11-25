#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ce4p {

class HookManager {
public:
    static HookManager& Instance();

    bool Initialize();
    void Shutdown();

    bool InstallHook(const std::string& name, uintptr_t target, void* detour, void** original);
    bool RemoveHook(uintptr_t target);

private:
    HookManager() = default;
    ~HookManager() = default;

    bool initialized_ = false;
    std::vector<uintptr_t> installed_targets_;
};

}  // namespace ce4p
