#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace ce4p {

struct PatternByte {
    uint8_t value = 0;
    bool wildcard = false;
};

struct MemorySpan {
    const uint8_t* data = nullptr;
    size_t size = 0;
};

// Parses an IDA-style AOB pattern string, e.g. "48 89 5C 24 ? 57 48 83 EC 20".
// Returns std::nullopt if the pattern is empty or malformed.
std::optional<std::vector<PatternByte>> ParsePattern(std::string_view pattern);

// Scans a memory span for the first occurrence of a compiled or string pattern.
std::optional<uintptr_t> FindPattern(MemorySpan span, const std::vector<PatternByte>& pattern);
std::optional<uintptr_t> FindPattern(MemorySpan span, std::string_view pattern);

// Scans a memory span for all occurrences of a pattern.
std::vector<uintptr_t> FindAllPatterns(MemorySpan span, std::string_view pattern);

// Resolves an x86-64 RIP-relative displacement (e.g., lea rax, [rip + disp32]).
// disp_offset: byte offset from instruction_addr to the 32-bit signed displacement.
// instruction_len: total byte length of the instruction.
uintptr_t ResolveRipRelative(uintptr_t instruction_addr, size_t disp_offset, size_t instruction_len);

#ifdef _WIN32
// Returns the full image span of a loaded Windows module (PE SizeOfImage).
std::optional<MemorySpan> GetModuleSpan(const char* module_name);
#endif

}  // namespace ce4p
