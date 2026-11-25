#include "core/module_watcher.hpp"

#include "core/logger.hpp"

#include <psapi.h>

namespace ce4p {

namespace {

uint32_t ReadPeTimestamp(HMODULE mod) {
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(mod) + dos->e_lfanew
    );
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    return nt->FileHeader.TimeDateStamp;
}

}  // namespace

ModuleWatcher::~ModuleWatcher() {
    Stop();
}

void ModuleWatcher::Start(
    std::string target_module,
    ModuleCallback on_loaded,
    ModuleCallback on_unloaded
) {
    target_module_ = std::move(target_module);
    on_loaded_ = std::move(on_loaded);
    on_unloaded_ = std::move(on_unloaded);
    stop_requested_ = false;

    thread_ = CreateThread(
        nullptr,
        0,
        [](LPVOID param) -> DWORD {
            static_cast<ModuleWatcher*>(param)->PollLoop();
            return 0;
        },
        this,
        0,
        nullptr
    );
}

void ModuleWatcher::Stop() {
    stop_requested_ = true;
    if (thread_) {
        WaitForSingleObject(thread_, 2000);
        CloseHandle(thread_);
        thread_ = nullptr;
    }
}

void ModuleWatcher::PollLoop() {
    HMODULE last_handle = nullptr;
    ModuleSnapshot last_snapshot{};

    while (!stop_requested_) {
        HMODULE current = GetModuleHandleA(target_module_.c_str());

        if (current && current != last_handle) {
            MODULEINFO info{};
            if (GetModuleInformation(GetCurrentProcess(), current, &info, sizeof(info))) {
                last_snapshot = ModuleSnapshot{
                    target_module_,
                    current,
                    reinterpret_cast<uintptr_t>(info.lpBaseOfDll),
                    static_cast<size_t>(info.SizeOfImage),
                    ReadPeTimestamp(current),
                };
                last_handle = current;
                CE4P_LOG_INFO(
                    "Module loaded: %s | base=0x%llX | size=0x%zX | timestamp=0x%08X",
                    last_snapshot.name.c_str(),
                    static_cast<unsigned long long>(last_snapshot.base),
                    last_snapshot.size,
                    last_snapshot.pe_timestamp
                );
                if (on_loaded_) {
                    on_loaded_(last_snapshot);
                }
            }
        } else if (!current && last_handle) {
            CE4P_LOG_INFO("Module unloaded: %s", last_snapshot.name.c_str());
            if (on_unloaded_) {
                on_unloaded_(last_snapshot);
            }
            last_handle = nullptr;
            last_snapshot = {};
        }

        Sleep(100);
    }
}

}  // namespace ce4p
