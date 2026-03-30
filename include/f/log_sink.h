/// @file log_sink.h
/// @brief Fixed-capacity ring buffer spdlog sink for HTTP API.

#ifndef INCLUDE_F_LOG_SINK_H_
#define INCLUDE_F_LOG_SINK_H_

#include <deque>
#include <mutex>
#include <string>
#include <vector>

#include <spdlog/details/null_mutex.h>
#include <spdlog/sinks/base_sink.h>

namespace f {

/// A single captured log entry.
struct LogEntry {
  std::string timestamp;
  std::string level;
  std::string message;
};

/// Ring buffer spdlog sink that retains the most recent entries.
template <typename Mutex>
class RingBufferSink : public spdlog::sinks::base_sink<Mutex> {
 public:
  explicit RingBufferSink(size_t max_items = 1000)
      : max_items_(max_items) {}

  /// Return a snapshot of all buffered log entries.
  auto GetLogs() -> std::vector<LogEntry> {
    std::lock_guard<Mutex> lock(
        spdlog::sinks::base_sink<Mutex>::mutex_);
    return {buffer_.begin(), buffer_.end()};
  }

 protected:
  void sink_it_(
      const spdlog::details::log_msg& msg) override {
    LogEntry entry;
    std::time_t time =
        std::chrono::system_clock::to_time_t(msg.time);
    std::tm tm = *std::localtime(&time);
    char buf[64];
    std::strftime(
        buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    entry.timestamp = buf;
    auto lv = spdlog::level::to_string_view(msg.level);
    entry.level = std::string(lv.data(), lv.size());
    entry.message = std::string(
        msg.payload.data(), msg.payload.size());
    buffer_.push_back(std::move(entry));
    if (buffer_.size() > max_items_) {
      buffer_.pop_front();
    }
  }

  void flush_() override {}

 private:
  size_t max_items_;
  std::deque<LogEntry> buffer_;
};

using RingBufferSink_mt = RingBufferSink<std::mutex>;
using RingBufferSink_st =
    RingBufferSink<spdlog::details::null_mutex>;

}  // namespace f

#endif  // INCLUDE_F_LOG_SINK_H_
