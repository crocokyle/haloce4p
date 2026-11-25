#include "core/input_automation.hpp"

#include "core/logger.hpp"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace ce4p {

namespace {

struct WindowSearch {
    DWORD pid = 0;
    HWND hwnd = nullptr;
};

BOOL CALLBACK FindProcessWindowProc(HWND hwnd, LPARAM lparam) {
    auto* search = reinterpret_cast<WindowSearch*>(lparam);
    DWORD win_pid = 0;
    GetWindowThreadProcessId(hwnd, &win_pid);
    if (win_pid == search->pid && IsWindowVisible(hwnd)) {
        char title[128]{};
        GetWindowTextA(hwnd, title, sizeof(title));
        if (title[0] != '\0' && std::string(title).find("Diagnostic Console") == std::string::npos) {
            search->hwnd = hwnd;
            return FALSE;
        }
    }
    return TRUE;
}

HWND FindMccWindow() {
    WindowSearch search{GetCurrentProcessId(), nullptr};
    EnumWindows(FindProcessWindowProc, reinterpret_cast<LPARAM>(&search));
    return search.hwnd;
}

std::string ToUpper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return s;
}

WORD ParseVirtualKey(const std::string& token) {
    std::string k = ToUpper(token);
    if (k == "RETURN" || k == "ENTER") return VK_RETURN;
    if (k == "ESCAPE" || k == "ESC") return VK_ESCAPE;
    if (k == "SPACE") return VK_SPACE;
    if (k == "TAB") return VK_TAB;
    if (k == "BACK" || k == "BACKSPACE") return VK_BACK;
    if (k == "UP") return VK_UP;
    if (k == "DOWN") return VK_DOWN;
    if (k == "LEFT") return VK_LEFT;
    if (k == "RIGHT") return VK_RIGHT;
    if (k == "SHIFT") return VK_LSHIFT;
    if (k == "CTRL" || k == "CONTROL") return VK_LCONTROL;
    if (k == "ALT") return VK_LMENU;
    if (k == "F1") return VK_F1;
    if (k == "F2") return VK_F2;
    if (k == "F3") return VK_F3;
    if (k == "F4") return VK_F4;
    if (k == "F5") return VK_F5;
    if (k == "F10") return VK_F10;
    if (k.size() == 1 && ((k[0] >= 'A' && k[0] <= 'Z') || (k[0] >= '0' && k[0] <= '9'))) {
        return static_cast<WORD>(k[0]);
    }
    if (k.rfind("0X", 0) == 0) {
        return static_cast<WORD>(std::strtoul(k.c_str(), nullptr, 16));
    }
    return 0;
}

bool IsExtendedKey(WORD vk) {
    return vk == VK_UP || vk == VK_DOWN || vk == VK_LEFT || vk == VK_RIGHT ||
           vk == VK_INSERT || vk == VK_DELETE || vk == VK_HOME || vk == VK_END ||
           vk == VK_PRIOR || vk == VK_NEXT;
}

void SendKeyEvent(WORD vk, bool key_up) {
    UINT scan = MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
    INPUT input{};
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = vk;
    input.ki.wScan = static_cast<WORD>(scan);
    input.ki.dwFlags = KEYEVENTF_SCANCODE;
    if (IsExtendedKey(vk)) {
        input.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
    }
    if (key_up) {
        input.ki.dwFlags |= KEYEVENTF_KEYUP;
    }
    SendInput(1, &input, sizeof(INPUT));
}

void SendMouseClickAt(HWND hwnd, int client_x, int client_y) {
    if (hwnd) {
        SetForegroundWindow(hwnd);
        POINT pt{client_x, client_y};
        ClientToScreen(hwnd, &pt);
        SetCursorPos(pt.x, pt.y);
    } else {
        SetCursorPos(client_x, client_y);
    }
    Sleep(30);

    INPUT down{};
    down.type = INPUT_MOUSE;
    down.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
    SendInput(1, &down, sizeof(INPUT));

    Sleep(40);

    INPUT up{};
    up.type = INPUT_MOUSE;
    up.mi.dwFlags = MOUSEEVENTF_LEFTUP;
    SendInput(1, &up, sizeof(INPUT));
}

}  // namespace

InputAutomation::~InputAutomation() {
    Stop();
}

void InputAutomation::Start(std::string command_file_path) {
    command_file_path_ = std::move(command_file_path);
    stop_requested_ = false;
    thread_ = CreateThread(
        nullptr,
        0,
        [](LPVOID param) -> DWORD {
            static_cast<InputAutomation*>(param)->PollLoop();
            return 0;
        },
        this,
        0,
        nullptr
    );
    CE4P_LOG_INFO("[Input] Automation watcher started: %s", command_file_path_.c_str());
}

void InputAutomation::Stop() {
    stop_requested_ = true;
    if (thread_) {
        WaitForSingleObject(static_cast<HANDLE>(thread_), 2000);
        CloseHandle(static_cast<HANDLE>(thread_));
        thread_ = nullptr;
    }
}

void InputAutomation::PollLoop() {
    while (!stop_requested_) {
        std::ifstream in(command_file_path_);
        if (in.is_open()) {
            std::vector<std::string> lines;
            std::string line;
            while (std::getline(in, line)) {
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                if (!line.empty() && line[0] != '#') {
                    lines.push_back(line);
                }
            }
            in.close();

            if (!lines.empty()) {
                DeleteFileA(command_file_path_.c_str());
                for (const auto& cmd : lines) {
                    if (stop_requested_) break;
                    ExecuteLine(cmd);
                }
            }
        }
        Sleep(100);
    }
}

void InputAutomation::ExecuteLine(const std::string& line) {
    std::istringstream ss(line);
    std::string op;
    ss >> op;
    op = ToUpper(op);

    if (op == "WAIT") {
        int ms = 100;
        ss >> ms;
        if (ms > 0 && ms <= 60000) {
            Sleep(static_cast<DWORD>(ms));
        }
    } else if (op == "KEY") {
        std::string key_tok;
        ss >> key_tok;
        WORD vk = ParseVirtualKey(key_tok);
        if (vk) {
            if (HWND hwnd = FindMccWindow()) {
                SetForegroundWindow(hwnd);
            }
            SendKeyEvent(vk, false);
            Sleep(60);
            SendKeyEvent(vk, true);
            CE4P_LOG_INFO("[Input] KEY %s (vk=0x%X)", key_tok.c_str(), vk);
        } else {
            CE4P_LOG_WARN("[Input] Unknown key '%s'", key_tok.c_str());
        }
    } else if (op == "HOLD") {
        std::string key_tok;
        int ms = 250;
        ss >> key_tok >> ms;
        WORD vk = ParseVirtualKey(key_tok);
        if (vk) {
            if (HWND hwnd = FindMccWindow()) {
                SetForegroundWindow(hwnd);
            }
            SendKeyEvent(vk, false);
            Sleep(static_cast<DWORD>(std::clamp(ms, 10, 10000)));
            SendKeyEvent(vk, true);
            CE4P_LOG_INFO("[Input] HOLD %s %dms", key_tok.c_str(), ms);
        }
    } else if (op == "CLICK") {
        int x = 0;
        int y = 0;
        ss >> x >> y;
        HWND hwnd = FindMccWindow();
        SendMouseClickAt(hwnd, x, y);
        CE4P_LOG_INFO("[Input] CLICK (%d, %d) hwnd=0x%llX", x, y, reinterpret_cast<unsigned long long>(hwnd));
    } else if (op == "STATUS") {
        HWND hwnd = FindMccWindow();
        char title[128]{};
        RECT rect{};
        if (hwnd) {
            GetWindowTextA(hwnd, title, sizeof(title));
            GetClientRect(hwnd, &rect);
        }
        CE4P_LOG_INFO(
            "[Input] STATUS hwnd=0x%llX title='%s' client=%ldx%ld",
            reinterpret_cast<unsigned long long>(hwnd),
            title,
            rect.right - rect.left,
            rect.bottom - rect.top
        );
    } else {
        CE4P_LOG_WARN("[Input] Unknown command: %s", line.c_str());
    }
}

}  // namespace ce4p
