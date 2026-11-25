#include "core/pattern_scanner.hpp"

#include <cctype>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace ce4p {

namespace {

std::optional<uint8_t> ParseHexByte(std::string_view token) {
    if (token.size() != 2) {
        return std::nullopt;
    }
    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    int hi = hex_val(token[0]);
    int lo = hex_val(token[1]);
    if (hi < 0 || lo < 0) {
        return std::nullopt;
    }
    return static_cast<uint8_t>((hi << 4) | lo);
}

}  // namespace

std::optional<std::vector<PatternByte>> ParsePattern(std::string_view pattern) {
    std::vector<PatternByte> result;
    size_t i = 0;

    while (i < pattern.size()) {
        while (i < pattern.size() && std::isspace(static_cast<unsigned char>(pattern[i]))) {
            ++i;
        }
        if (i >= pattern.size()) {
            break;
        }

        size_t start = i;
        while (i < pattern.size() && !std::isspace(static_cast<unsigned char>(pattern[i]))) {
            ++i;
        }
        std::string_view token = pattern.substr(start, i - start);

        if (token == "?" || token == "??") {
            result.push_back(PatternByte{0, true});
        } else {
            auto byte = ParseHexByte(token);
            if (!byte.has_value()) {
                return std::nullopt;
            }
            result.push_back(PatternByte{*byte, false});
        }
    }

    if (result.empty()) {
        return std::nullopt;
    }
    return result;
}

std::optional<uintptr_t> FindPattern(MemorySpan span, const std::vector<PatternByte>& pattern) {
    if (!span.data || pattern.empty() || span.size < pattern.size()) {
        return std::nullopt;
    }

    const size_t limit = span.size - pattern.size();
    for (size_t i = 0; i <= limit; ++i) {
        bool matched = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (!pattern[j].wildcard && span.data[i + j] != pattern[j].value) {
                matched = false;
                break;
            }
        }
        if (matched) {
            return reinterpret_cast<uintptr_t>(span.data + i);
        }
    }
    return std::nullopt;
}

std::optional<uintptr_t> FindPattern(MemorySpan span, std::string_view pattern) {
    auto parsed = ParsePattern(pattern);
    if (!parsed.has_value()) {
        return std::nullopt;
    }
    return FindPattern(span, *parsed);
}

std::vector<uintptr_t> FindAllPatterns(MemorySpan span, std::string_view pattern) {
    std::vector<uintptr_t> matches;
    auto parsed = ParsePattern(pattern);
    if (!parsed.has_value() || !span.data || span.size < parsed->size()) {
        return matches;
    }

    const size_t limit = span.size - parsed->size();
    for (size_t i = 0; i <= limit; ++i) {
        bool matched = true;
        for (size_t j = 0; j < parsed->size(); ++j) {
            if (!(*parsed)[j].wildcard && span.data[i + j] != (*parsed)[j].value) {
                matched = false;
                break;
            }
        }
        if (matched) {
            matches.push_back(reinterpret_cast<uintptr_t>(span.data + i));
        }
    }
    return matches;
}

uintptr_t ResolveRipRelative(uintptr_t instruction_addr, size_t disp_offset, size_t instruction_len) {
    int32_t disp = 0;
    std::memcpy(&disp, reinterpret_cast<const void*>(instruction_addr + disp_offset), sizeof(disp));
    return static_cast<uintptr_t>(static_cast<intptr_t>(instruction_addr + instruction_len) + disp);
}

#ifdef _WIN32
std::optional<MemorySpan> GetModuleSpan(const char* module_name) {
    HMODULE mod = module_name ? GetModuleHandleA(module_name) : GetModuleHandleA(nullptr);
    if (!mod) {
        return std::nullopt;
    }
    MODULEINFO info{};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &info, sizeof(info))) {
        return std::nullopt;
    }
    return MemorySpan{
        reinterpret_cast<const uint8_t*>(info.lpBaseOfDll),
        static_cast<size_t>(info.SizeOfImage),
    };
}

std::optional<MemorySpan> GetModuleTextSpan(const char* module_name) {
    HMODULE mod = module_name ? GetModuleHandleA(module_name) : GetModuleHandleA(nullptr);
    if (!mod) {
        return std::nullopt;
    }
    const auto* base = reinterpret_cast<const uint8_t*>(mod);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return GetModuleSpan(module_name);
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return GetModuleSpan(module_name);
    }
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (std::memcmp(sec->Name, ".text", 5) == 0) {
            return MemorySpan{
                base + sec->VirtualAddress,
                static_cast<size_t>(sec->Misc.VirtualSize),
            };
        }
    }
    return GetModuleSpan(module_name);
}
#endif

}  // namespace ce4p
