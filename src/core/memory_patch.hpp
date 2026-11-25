#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ce4p {

struct AppliedPatch {
    std::string name;
    uintptr_t address = 0;
    std::vector<uint8_t> original_bytes;
};

class PatchRegistry {
public:
    bool WriteBytes(const std::string& name, uintptr_t address, const std::vector<uint8_t>& bytes);
    bool PatchByte(const std::string& name, uintptr_t address, uint8_t value);
    bool NopRange(const std::string& name, uintptr_t address, size_t count);

    void RevertAll();
    size_t Count() const { return patches_.size(); }

private:
    std::vector<AppliedPatch> patches_;
};

}  // namespace ce4p
