#pragma once

#include <string>

namespace ce4p {

// Polls <base_dir>/ce_4player_input.txt for automated Win32 input commands
// (KEY, HOLD, CLICK, WAIT, STATUS) when EnableInputAutomation = true.
class InputAutomation {
public:
    InputAutomation() = default;
    ~InputAutomation();

    void Start(std::string command_file_path);
    void Stop();

private:
    void PollLoop();
    void ExecuteLine(const std::string& line);

    std::string command_file_path_;
    void* thread_ = nullptr;
    volatile bool stop_requested_ = false;
};

}  // namespace ce4p
