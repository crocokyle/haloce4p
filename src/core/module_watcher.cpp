#include "core/module_watcher.hpp"

#include "core/logger.hpp"

#include <psapi.h>

#include <cwchar>

namespace ce4p {

namespace {

struct UnicodeStr {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct LdrDllNotificationData {
    ULONG Flags;
    const UnicodeStr* FullDllName;
    const UnicodeStr* BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
};

using FnLdrDllNotification = void(CALLBACK*)(ULONG reason, const LdrDllNotificationData* data, PVOID context);
using FnLdrRegisterDllNotification = LONG(NTAPI*)(ULONG flags, FnLdrDllNotification cb, PVOID context, PVOID* cookie);
using FnLdrUnregisterDllNotification = LONG(NTAPI*)(PVOID cookie);

constexpr ULONG kLdrReasonLoaded = 1;
constexpr ULONG kLdrReasonUnloaded = 2;

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

void ModuleWatcher::RegisterDllNotification() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return;
    }
    auto reg = reinterpret_cast<FnLdrRegisterDllNotification>(
        GetProcAddress(ntdll, "LdrRegisterDllNotification")
    );
    if (!reg) {
        return;
    }
    auto cb = [](ULONG reason, const LdrDllNotificationData* data, PVOID ctx) CALLBACK {
        auto* self = static_cast<ModuleWatcher*>(ctx);
        if (!self || !data || !data->BaseDllName || !data->BaseDllName->Buffer) {
            return;
        }
        const size_t chars = data->BaseDllName->Length / sizeof(wchar_t);
        if (chars == self->target_module_wide_.size() &&
            _wcsnicmp(data->BaseDllName->Buffer, self->target_module_wide_.c_str(), chars) == 0) {
            if (reason == kLdrReasonUnloaded) {
                self->unload_seq_.fetch_add(1, std::memory_order_release);
                if (self->wake_event_) {
                    SetEvent(self->wake_event_);
                }
            } else if (reason == kLdrReasonLoaded) {
                if (self->wake_event_) {
                    SetEvent(self->wake_event_);
                }
            }
        }
    };
    reg(0, cb, this, &ldr_cookie_);
}

void ModuleWatcher::UnregisterDllNotification() {
    if (!ldr_cookie_) {
        return;
    }
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        auto unreg = reinterpret_cast<FnLdrUnregisterDllNotification>(
            GetProcAddress(ntdll, "LdrUnregisterDllNotification")
        );
        if (unreg) {
            unreg(ldr_cookie_);
        }
    }
    ldr_cookie_ = nullptr;
}

void ModuleWatcher::Start(
    std::string target_module,
    ModuleCallback on_loaded,
    ModuleCallback on_unloaded
) {
    target_module_ = std::move(target_module);
    target_module_wide_.assign(target_module_.begin(), target_module_.end());
    on_loaded_ = std::move(on_loaded);
    on_unloaded_ = std::move(on_unloaded);
    unload_seq_.store(0, std::memory_order_relaxed);
    stop_requested_ = false;
    wake_event_ = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    RegisterDllNotification();

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
    if (wake_event_) {
        SetEvent(wake_event_);
    }
    if (thread_) {
        WaitForSingleObject(thread_, 2000);
        CloseHandle(thread_);
        thread_ = nullptr;
    }
    UnregisterDllNotification();
    if (wake_event_) {
        CloseHandle(wake_event_);
        wake_event_ = nullptr;
    }
}

void ModuleWatcher::PollLoop() {
    HMODULE last_handle = nullptr;
    ModuleSnapshot last_snapshot{};
    uint64_t seen_unload_seq = 0;

    while (!stop_requested_) {
        const uint64_t cur_unload_seq = unload_seq_.load(std::memory_order_acquire);
        HMODULE current = GetModuleHandleA(target_module_.c_str());

        if (last_handle && (!current || cur_unload_seq != seen_unload_seq)) {
            CE4P_LOG_INFO(
                "Module unloaded: %s (seq=%llu)",
                last_snapshot.name.c_str(),
                static_cast<unsigned long long>(cur_unload_seq)
            );
            if (on_unloaded_) {
                on_unloaded_(last_snapshot);
            }
            last_handle = nullptr;
            last_snapshot = {};
            seen_unload_seq = cur_unload_seq;
        } else if (cur_unload_seq != seen_unload_seq) {
            seen_unload_seq = cur_unload_seq;
        }

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
        }

        if (wake_event_) {
            WaitForSingleObject(wake_event_, 100);
        } else {
            Sleep(100);
        }
    }
}

}  // namespace ce4p
