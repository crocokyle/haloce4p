#pragma once

#include <cstdarg>
#include <string>

namespace ce4p {

enum class LogLevel {
    Debug,
    Info,
    Warn,
    Error,
};

class Logger {
public:
    static Logger& Instance();

    void Init(const std::string& log_path, bool alloc_console = true);
    void Shutdown();

    void Log(LogLevel level, const char* fmt, ...);

private:
    Logger() = default;
    ~Logger();

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
};

#define CE4P_LOG_DEBUG(fmt, ...) ::ce4p::Logger::Instance().Log(::ce4p::LogLevel::Debug, fmt, ##__VA_ARGS__)
#define CE4P_LOG_INFO(fmt, ...)  ::ce4p::Logger::Instance().Log(::ce4p::LogLevel::Info, fmt, ##__VA_ARGS__)
#define CE4P_LOG_WARN(fmt, ...)  ::ce4p::Logger::Instance().Log(::ce4p::LogLevel::Warn, fmt, ##__VA_ARGS__)
#define CE4P_LOG_ERROR(fmt, ...) ::ce4p::Logger::Instance().Log(::ce4p::LogLevel::Error, fmt, ##__VA_ARGS__)

}  // namespace ce4p
