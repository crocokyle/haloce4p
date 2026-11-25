#include "core/hook_manager.hpp"

#include "core/logger.hpp"

#include <MinHook.h>

#include <algorithm>

namespace ce4p {

HookManager& HookManager::Instance() {
    static HookManager instance;
    return instance;
}

bool HookManager::Initialize() {
    if (initialized_) {
        return true;
    }
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED) {
        CE4P_LOG_ERROR("MH_Initialize failed: %s", MH_StatusToString(status));
        return false;
    }
    initialized_ = true;
    CE4P_LOG_INFO("MinHook initialized.");
    return true;
}

void HookManager::Shutdown() {
    if (!initialized_) {
        return;
    }
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    installed_targets_.clear();
    initialized_ = false;
    CE4P_LOG_INFO("MinHook shut down.");
}

bool HookManager::InstallHook(const std::string& name, uintptr_t target, void* detour, void** original) {
    if (!initialized_ || !target || !detour) {
        return false;
    }

    MH_STATUS status = MH_CreateHook(reinterpret_cast<LPVOID>(target), detour, original);
    if (status != MH_OK) {
        CE4P_LOG_ERROR(
            "MH_CreateHook failed for '%s' @ 0x%llX: %s",
            name.c_str(),
            static_cast<unsigned long long>(target),
            MH_StatusToString(status)
        );
        return false;
    }

    status = MH_EnableHook(reinterpret_cast<LPVOID>(target));
    if (status != MH_OK) {
        CE4P_LOG_ERROR(
            "MH_EnableHook failed for '%s' @ 0x%llX: %s",
            name.c_str(),
            static_cast<unsigned long long>(target),
            MH_StatusToString(status)
        );
        return false;
    }

    installed_targets_.push_back(target);
    CE4P_LOG_INFO(
        "Installed hook '%s' @ 0x%llX",
        name.c_str(),
        static_cast<unsigned long long>(target)
    );
    return true;
}

bool HookManager::RemoveHook(uintptr_t target) {
    if (!initialized_ || !target) {
        return false;
    }
    MH_DisableHook(reinterpret_cast<LPVOID>(target));
    MH_RemoveHook(reinterpret_cast<LPVOID>(target));
    installed_targets_.erase(
        std::remove(installed_targets_.begin(), installed_targets_.end(), target),
        installed_targets_.end()
    );
    return true;
}

}  // namespace ce4p
