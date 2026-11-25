#include "core/logger.hpp"

#include <windows.h>

#include <chrono>
#include <cstdio>
#include <ctime>
#include <mutex>

namespace ce4p {

namespace {

std::mutex g_log_mutex;
FILE* g_log_file = nullptr;
bool g_console_allocated = false;

const char* LevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO ";
        case LogLevel::Warn:  return "WARN ";
        case LogLevel::Error: return "ERROR";
    }
    return "UNK  ";
}

}  // namespace

Logger& Logger::Instance() {
    static Logger instance;
    return instance;
}

Logger::~Logger() {
    Shutdown();
}

void Logger::Init(const std::string& log_path, bool alloc_console) {
    std::lock_guard<std::mutex> lock(g_log_mutex);

    if (alloc_console && !g_console_allocated) {
        if (AllocConsole()) {
            g_console_allocated = true;
            FILE* dummy = nullptr;
            freopen_s(&dummy, "CONOUT$", "w", stdout);
            freopen_s(&dummy, "CONOUT$", "w", stderr);
            SetConsoleTitleA("CE 4-Player Co-op Mod [Diagnostic Console]");
        }
    }

    if (!g_log_file && !log_path.empty()) {
        fopen_s(&g_log_file, log_path.c_str(), "w");
    }
}

void Logger::Shutdown() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = nullptr;
    }
    if (g_console_allocated) {
        FreeConsole();
        g_console_allocated = false;
    }
}

void Logger::Log(LogLevel level, const char* fmt, ...) {
    std::lock_guard<std::mutex> lock(g_log_mutex);

    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm tm_now{};
    localtime_s(&tm_now, &time_t_now);

    char msg_buf[2048]{};
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
    va_end(args);

    char line_buf[2304]{};
    snprintf(
        line_buf,
        sizeof(line_buf),
        "[%02d:%02d:%02d.%03d] [%s] %s\n",
        tm_now.tm_hour,
        tm_now.tm_min,
        tm_now.tm_sec,
        static_cast<int>(ms.count()),
        LevelToString(level),
        msg_buf
    );

    if (g_console_allocated) {
        fputs(line_buf, stdout);
        fflush(stdout);
    }

    if (g_log_file) {
        fputs(line_buf, g_log_file);
        fflush(g_log_file);
    }

    OutputDebugStringA(line_buf);
}

}  // namespace ce4p
