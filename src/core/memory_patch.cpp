#include "core/memory_patch.hpp"

#include "core/logger.hpp"

#include <windows.h>

#include <cstring>

namespace ce4p {

bool PatchRegistry::WriteBytes(const std::string& name, uintptr_t address, const std::vector<uint8_t>& bytes) {
    if (!address || bytes.empty()) {
        return false;
    }

    auto* target = reinterpret_cast<uint8_t*>(address);
    DWORD old_protect = 0;
    if (!VirtualProtect(target, bytes.size(), PAGE_EXECUTE_READWRITE, &old_protect)) {
        CE4P_LOG_ERROR(
            "VirtualProtect failed for patch '%s' @ 0x%llX (err=%lu)",
            name.c_str(),
            static_cast<unsigned long long>(address),
            GetLastError()
        );
        return false;
    }

    AppliedPatch record;
    record.name = name;
    record.address = address;
    record.original_bytes.assign(target, target + bytes.size());

    std::memcpy(target, bytes.data(), bytes.size());
    FlushInstructionCache(GetCurrentProcess(), target, bytes.size());

    DWORD dummy = 0;
    VirtualProtect(target, bytes.size(), old_protect, &dummy);

    patches_.push_back(std::move(record));
    CE4P_LOG_INFO(
        "Applied patch '%s' @ 0x%llX (%zu bytes)",
        name.c_str(),
        static_cast<unsigned long long>(address),
        bytes.size()
    );
    return true;
}

bool PatchRegistry::PatchByte(const std::string& name, uintptr_t address, uint8_t value) {
    return WriteBytes(name, address, {value});
}

bool PatchRegistry::NopRange(const std::string& name, uintptr_t address, size_t count) {
    if (count == 0) {
        return false;
    }
    return WriteBytes(name, address, std::vector<uint8_t>(count, 0x90));
}

void PatchRegistry::RevertAll() {
    for (auto it = patches_.rbegin(); it != patches_.rend(); ++it) {
        auto* target = reinterpret_cast<uint8_t*>(it->address);
        DWORD old_protect = 0;
        if (VirtualProtect(target, it->original_bytes.size(), PAGE_EXECUTE_READWRITE, &old_protect)) {
            std::memcpy(target, it->original_bytes.data(), it->original_bytes.size());
            FlushInstructionCache(GetCurrentProcess(), target, it->original_bytes.size());
            DWORD dummy = 0;
            VirtualProtect(target, it->original_bytes.size(), old_protect, &dummy);
            CE4P_LOG_INFO("Reverted patch '%s' @ 0x%llX", it->name.c_str(), static_cast<unsigned long long>(it->address));
        }
    }
    patches_.clear();
}

}  // namespace ce4p
