#include "core/pattern_scanner.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

namespace {

void TestParsePatternValid() {
    auto p = ce4p::ParsePattern("48 89 5C 24 ? 57 ?? 48 83 EC 20");
    assert(p.has_value());
    assert(p->size() == 11);
    assert((*p)[0].value == 0x48 && !(*p)[0].wildcard);
    assert((*p)[4].wildcard);
    assert((*p)[6].wildcard);
    assert((*p)[10].value == 0x20 && !(*p)[10].wildcard);
}

void TestParsePatternInvalid() {
    assert(!ce4p::ParsePattern("").has_value());
    assert(!ce4p::ParsePattern("   ").has_value());
    assert(!ce4p::ParsePattern("48 ZZ 24").has_value());
    assert(!ce4p::ParsePattern("4").has_value());
}

void TestFindPatternAndAll() {
    const std::vector<uint8_t> mem = {
        0x90, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57,
        0x90, 0x48, 0x89, 0x5C, 0x24, 0x10, 0x57,
        0xC3
    };
    ce4p::MemorySpan span{mem.data(), mem.size()};

    auto first = ce4p::FindPattern(span, "48 89 5C 24 ? 57");
    assert(first.has_value());
    assert(*first == reinterpret_cast<uintptr_t>(mem.data() + 1));

    auto all = ce4p::FindAllPatterns(span, "48 89 5C 24 ? 57");
    assert(all.size() == 2);
    assert(all[0] == reinterpret_cast<uintptr_t>(mem.data() + 1));
    assert(all[1] == reinterpret_cast<uintptr_t>(mem.data() + 8));

    auto missing = ce4p::FindPattern(span, "FF EE DD CC");
    assert(!missing.has_value());
}

void TestResolveRipRelative() {
    // Simulated instruction at 0x1000: 7 bytes long, disp32 = +0x10 at offset 3 -> target = 0x1017
    uint8_t code[7] = {0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00};
    uintptr_t addr = reinterpret_cast<uintptr_t>(code);
    uintptr_t resolved = ce4p::ResolveRipRelative(addr, 3, 7);
    assert(resolved == addr + 7 + 0x10);
}

}  // namespace

int main() {
    TestParsePatternValid();
    TestParsePatternInvalid();
    TestFindPatternAndAll();
    TestResolveRipRelative();
    std::cout << "All pattern scanner tests passed.\n";
    return 0;
}
