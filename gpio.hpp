// -*- C++ -*-
//
// Copyright 2023 Dmitry Igrishin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef DMITIGR_GPIO_HPP
#define DMITIGR_GPIO_HPP

#include <gpiod.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace dmitigr::gpio {

class Chip_info {
public:
  ~Chip_info()
  {
    if (handle_) {
      gpiod_chip_info_free(handle_);
      handle_ = nullptr;
    }
  }

  Chip_info(const Chip_info& rhs) = delete;
  Chip_info& operator=(const Chip_info&) = delete;

  Chip_info(Chip_info&& rhs)
    : handle_{rhs.handle_}
  {
    rhs.handle_ = nullptr;
  }

  Chip_info& operator=(Chip_info&& rhs)
  {
    Chip_info tmp{std::move(rhs)};
    swap(tmp);
    return *this;
  }

  void swap(Chip_info& other)
  {
    using std::swap;
    swap(handle_, other.handle_);
  }

  std::string name() const
  {
    return gpiod_chip_info_get_name(handle_);
  }

  std::string label() const
  {
    return gpiod_chip_info_get_label(handle_);
  }

  std::size_t line_count() const noexcept
  {
    return gpiod_chip_info_get_num_lines(handle_);
  }

private:
  friend class Chip;
  gpiod_chip_info* handle_;

  explicit Chip_info(gpiod_chip_info* const handle)
    : handle_{handle}
  {
    assert(handle_);
  }
};

class Line_info {
public:
  ~Line_info()
  {
    if (is_owner_ && handle_) {
      gpiod_line_info_free(handle_);
      handle_ = nullptr;
    }
  }

  Line_info(const Line_info& rhs)
    : is_owner_{true}
    , handle_{gpiod_line_info_copy(rhs.handle_)}
  {
    if (!handle_)
      throw std::runtime_error{"cannot copy line info object"};
  }

  Line_info& operator=(const Line_info& rhs)
  {
    Line_info tmp{rhs};
    swap(tmp);
    return *this;
  }

  Line_info(Line_info&& rhs)
    : is_owner_{rhs.is_owner_}
    , handle_{rhs.handle_}
  {
    rhs.handle_ = nullptr;
  }

  Line_info& operator=(Line_info&& rhs)
  {
    Line_info tmp{std::move(rhs)};
    swap(tmp);
    return *this;
  }

  void swap(Line_info& other)
  {
    using std::swap;
    swap(is_owner_, other.is_owner_);
    swap(handle_, other.handle_);
  }

  unsigned offset() const noexcept
  {
    return gpiod_line_info_get_offset(handle_);
  }

  std::string name() const
  {
    const char* const result{gpiod_line_info_get_name(handle_)};
    return result ? result : "";
  }

  bool is_used() const noexcept
  {
    return gpiod_line_info_is_used(handle_);
  }

  std::string consumer() const
  {
    const char* const result{gpiod_line_info_get_consumer(handle_)};
    return result ? result : "";
  }

  gpiod_line_direction direction() const noexcept
  {
    return gpiod_line_info_get_direction(handle_);
  }

  gpiod_line_edge edge() const noexcept
  {
    return gpiod_line_info_get_edge_detection(handle_);
  }

  gpiod_line_bias bias() const noexcept
  {
    return gpiod_line_info_get_bias(handle_);
  }

  gpiod_line_drive drive() const noexcept
  {
    return gpiod_line_info_get_drive(handle_);
  }

  bool is_active_low() const noexcept
  {
    return gpiod_line_info_is_active_low(handle_);
  }

  bool is_debounced() const noexcept
  {
    return gpiod_line_info_is_debounced(handle_);
  }

  std::chrono::microseconds debounce_period() const noexcept
  {
    return std::chrono::microseconds{gpiod_line_info_get_debounce_period_us(handle_)};
  }

  gpiod_line_clock event_clock() const noexcept
  {
    return gpiod_line_info_get_event_clock(handle_);
  }

private:
  friend class Chip;
  friend class Info_event;
  bool is_owner_;
  gpiod_line_info* handle_;

  explicit Line_info(gpiod_line_info* const handle, const bool is_owner = true)
    : is_owner_{is_owner}
    , handle_{handle}
  {
    assert(handle_);
  }
};

class Info_event {
public:
  ~Info_event()
  {
    if (handle_) {
      gpiod_info_event_free(handle_);
      handle_ = nullptr;
    }
  }

  Info_event(const Info_event&) = delete;
  Info_event& operator=(const Info_event&) = delete;

  Info_event(Info_event&& rhs)
    : Info_event{rhs.handle_}
  {
    rhs.handle_ = nullptr;
  }

  Info_event& operator=(Info_event&& rhs)
  {
    Info_event tmp{std::move(rhs)};
    swap(tmp);
    return *this;
  }

  void swap(Info_event& other)
  {
    using std::swap;
    swap(handle_, other.handle_);
  }

  gpiod_info_event_type type() const noexcept
  {
    return gpiod_info_event_get_event_type(handle_);
  }

  std::chrono::nanoseconds timestamp() const noexcept
  {
    return std::chrono::nanoseconds{gpiod_info_event_get_timestamp_ns(handle_)};
  }

  const Line_info& line_info() const noexcept
  {
    return line_info_;
  }

private:
  friend class Chip;
  gpiod_info_event* handle_;
  Line_info line_info_;

  explicit Info_event(gpiod_info_event* const handle)
    : handle_{handle}
    , line_info_{gpiod_info_event_get_line_info(handle_), false}
  {
    assert(handle_);
  }
};

class Line_request {
public:
  ~Line_request()
  {
    if (handle_) {
      gpiod_line_request_release(handle_);
      handle_ = nullptr;
    }
  }

  Line_request(const Line_request&) = delete;
  Line_request& operator=(const Line_request&) = delete;

  Line_request(Line_request&& rhs)
    : handle_{rhs.handle_}
  {
    rhs.handle_ = nullptr;
  }

  Line_request& operator=(Line_request&& rhs)
  {
    Line_request tmp{std::move(rhs)};
    swap(tmp);
    return *this;
  }

  void swap(Line_request& other)
  {
    using std::swap;
    swap(handle_, other.handle_);
  }

private:
  friend class Chip;
  gpiod_line_request* handle_;

  explicit Line_request(gpiod_line_request* const handle)
    : handle_{handle}
  {
    assert(handle_);
  }
};

class Request_config {
public:
  ~Request_config()
  {
    if (handle_) {
      gpiod_request_config_free(handle_);
      handle_ = nullptr;
    }
  }

  Request_config()
    : handle_{gpiod_request_config_new()}
  {
    if (!handle_)
      throw std::runtime_error{"cannot create request config object"};
  }

  Request_config(const Request_config&) = delete;
  Request_config& operator=(const Request_config&) = delete;

  Request_config(Request_config&& rhs)
    : handle_{rhs.handle_}
  {
    rhs.handle_ = nullptr;
  }

  Request_config& operator=(Request_config&& rhs)
  {
    Request_config tmp{std::move(rhs)};
    swap(tmp);
    return *this;
  }

  void swap(Request_config& other)
  {
    using std::swap;
    swap(handle_, other.handle_);
  }

  void set_consumer(const std::string& name)
  {
    gpiod_request_config_set_consumer(handle_, name.c_str());
  }

  std::string consumer() const noexcept
  {
    return gpiod_request_config_get_consumer(handle_);
  }

  void set_event_buffer_size(const std::size_t size)
  {
    gpiod_request_config_set_event_buffer_size(handle_, size);
  }

  std::size_t event_buffer_size() const noexcept
  {
    return gpiod_request_config_get_event_buffer_size(handle_);
  }

private:
  friend class Chip;
  mutable gpiod_request_config* handle_;
};

class Line_settings {
public:
  ~Line_settings()
  {
    if (handle_) {
      gpiod_line_settings_free(handle_);
      handle_ = nullptr;
    }
  }

  Line_settings()
    : Line_settings{gpiod_line_settings_new()}
  {}

  Line_settings(const Line_settings& rhs)
    : handle_{gpiod_line_settings_copy(rhs.handle_)}
  {
    if (!handle_)
      throw std::runtime_error{"cannot copy line settings"};
  }

  Line_settings& operator=(const Line_settings& rhs)
  {
    Line_settings tmp{rhs};
    swap(tmp);
    return *this;
  }

  Line_settings(Line_settings&& rhs)
    : handle_{rhs.handle_}
  {
    rhs.handle_ = nullptr;
  }

  Line_settings& operator=(Line_settings&& rhs)
  {
    Line_settings tmp{std::move(rhs)};
    swap(tmp);
    return *this;
  }

  void swap(Line_settings& other)
  {
    using std::swap;
    swap(handle_, other.handle_);
  }

  void reset()
  {
    gpiod_line_settings_reset(handle_);
  }

  void set_direction(const gpiod_line_direction direction)
  {
    if (gpiod_line_settings_set_direction(handle_, direction) == -1)
      throw std::runtime_error{"cannot set line direction"};
  }

  gpiod_line_direction direction() const noexcept
  {
    return gpiod_line_settings_get_direction(handle_);
  }

  void set_edge_detection(const gpiod_line_edge edge)
  {
    if (gpiod_line_settings_set_edge_detection(handle_, edge) == -1)
      throw std::runtime_error{"cannot set edge detection"};
  }

  gpiod_line_edge edge_detection() const noexcept
  {
    return gpiod_line_settings_get_edge_detection(handle_);
  }

  void set_bias(const gpiod_line_bias bias)
  {
    if (gpiod_line_settings_set_bias(handle_, bias) == -1)
      throw std::runtime_error{"cannot set bias"};
  }

  gpiod_line_bias bias() const noexcept
  {
    return gpiod_line_settings_get_bias(handle_);
  }

  void set_drive(const gpiod_line_drive drive)
  {
    if (gpiod_line_settings_set_drive(handle_, drive) == -1)
      throw std::runtime_error{"cannot set drive"};
  }

  gpiod_line_drive drive() const noexcept
  {
    return gpiod_line_settings_get_drive(handle_);
  }

  void set_active_low(const bool active)
  {
    gpiod_line_settings_set_active_low(handle_, active);
  }

  bool active_low() const noexcept
  {
    return gpiod_line_settings_get_active_low(handle_);
  }

  void set_debounce_period(const std::chrono::microseconds period)
  {
    gpiod_line_settings_set_debounce_period_us(handle_, period.count());
  }

  std::chrono::microseconds debounce_period() const noexcept
  {
    return std::chrono::microseconds{gpiod_line_settings_get_debounce_period_us(handle_)};
  }

  void set_event_clock(const gpiod_line_clock event_clock)
  {
    if (gpiod_line_settings_set_event_clock(handle_, event_clock) == -1)
      throw std::runtime_error{"cannot set event clock"};
  }

  gpiod_line_clock event_clock() const noexcept
  {
    return gpiod_line_settings_get_event_clock(handle_);
  }

  void set_output_value(const gpiod_line_value value)
  {
    if (gpiod_line_settings_set_output_value(handle_, value) == -1)
      throw std::runtime_error{"cannot set output value"};
  }

  gpiod_line_value output_value() const noexcept
  {
    return gpiod_line_settings_get_output_value(handle_);
  }

private:
  friend class Line_config;
  mutable gpiod_line_settings* handle_;

  explicit Line_settings(gpiod_line_settings* const handle)
    : handle_{handle}
  {
    if (!handle_)
      throw std::runtime_error{"cannot create line settings object"};
  }
};

class Line_config {
public:
  ~Line_config()
  {
    if (handle_) {
      gpiod_line_config_free(handle_);
      handle_ = nullptr;
    }
  }

  Line_config()
    : handle_{gpiod_line_config_new()}
  {
    if (!handle_)
      throw std::runtime_error{"cannot create line config object"};
  }

  Line_config(const Line_config&) = delete;
  Line_config& operator=(const Line_config&) = delete;

  Line_config(Line_config&& rhs)
    : handle_{rhs.handle_}
  {
    rhs.handle_ = nullptr;
  }

  Line_config& operator=(Line_config&& rhs)
  {
    Line_config tmp{std::move(rhs)};
    swap(tmp);
    return *this;
  }

  void swap(Line_config& other)
  {
    using std::swap;
    swap(handle_, other.handle_);
  }

  void reset()
  {
    gpiod_line_config_reset(handle_);
  }

  void add_line_settings(const std::vector<unsigned>& offsets,
    const Line_settings& settings)
  {
    if (gpiod_line_config_add_line_settings(handle_, offsets.data(),
        offsets.size(), settings.handle_))
      throw std::runtime_error{"cannot add line settings for a set of offsets"};
  }

  Line_settings line_settings(const unsigned offset)
  {
    auto* const result = gpiod_line_config_get_line_settings(handle_, offset);
    if (!result)
      throw std::runtime_error{"cannot get line settings for offset "
        + std::to_string(offset)};
    return Line_settings{result};
  }

  void set_output_values(const std::vector<gpiod_line_value>& values)
  {
    if (gpiod_line_config_set_output_values(handle_, values.data(), values.size()))
      throw std::runtime_error{"cannot set output values for a number of lines"};
  }

  std::size_t configured_line_offsets_count() const noexcept
  {
    return gpiod_line_config_get_num_configured_offsets(handle_);
  }

  std::vector<unsigned> configured_offsets(const std::size_t max_size)
  {
    std::vector<unsigned> result(max_size);
    const auto size = gpiod_line_config_get_configured_offsets(handle_,
      result.data(), result.size());
    result.resize(size);
    return result;
  }

private:
  friend class Chip;
  mutable gpiod_line_config* handle_;
};

// -----------------------------------------------------------------------------

class Chip {
public:
  ~Chip()
  {
    if (handle_) {
      gpiod_chip_close(handle_);
      handle_ = nullptr;
    }
  }

  explicit Chip(const std::filesystem::path& path)
  {
    if ( !(handle_ = gpiod_chip_open(path.string().c_str())))
      throw std::runtime_error{"cannot open gpiochip device file"};
  }

  Chip(const Chip&) = delete;
  Chip& operator=(const Chip&) = delete;

  Chip(Chip&& rhs)
    : handle_{rhs.handle_}
  {
    rhs.handle_ = nullptr;
  }

  Chip& operator=(Chip&& rhs)
  {
    Chip tmp{std::move(rhs)};
    swap(tmp);
    return *this;
  }

  void swap(Chip& other)
  {
    using std::swap;
    swap(handle_, other.handle_);
  }

  std::filesystem::path path() const
  {
    return {gpiod_chip_get_path(handle_)};
  }

  Chip_info chip_info()
  {
    if (auto* const info = gpiod_chip_get_info(handle_); !info)
      throw std::runtime_error{"cannot get information about the chip"};
    else
      return Chip_info{info};
  }

  Line_info line_info(const unsigned offset)
  {
    if (auto* const info = gpiod_chip_get_line_info(handle_, offset); !info)
      throw std::runtime_error{"cannot get information about the chip"};
    else
      return Line_info{info};
  }

  Line_info watch_line_info(const unsigned offset)
  {
    if (auto* const info = gpiod_chip_watch_line_info(handle_, offset); !info)
      throw std::runtime_error{"cannot get information about the chip"};
    else
      return Line_info{info};
  }

  void unwatch_line_info(const unsigned offset)
  {
    if (gpiod_chip_unwatch_line_info(handle_, offset))
      throw std::runtime_error{"cannot stop watching a line for status changes"};
  }

  int fd() const noexcept
  {
    return gpiod_chip_get_fd(handle_);
  }

  int wait_info_event(const std::chrono::nanoseconds timeout)
  {
    const int result{gpiod_chip_wait_info_event(handle_, timeout.count())};
    if (result == -1)
      throw std::runtime_error{"cannot wait info event"};
    return result;
  }

  Info_event info_event()
  {
    if (auto* const result = gpiod_chip_read_info_event(handle_); !result)
      throw std::runtime_error{"cannot read a single line status change event from chip"};
    else
      return Info_event{result};
  }

  int line_offset_from_name(const std::string& name)
  {
    const int result{gpiod_chip_get_line_offset_from_name(handle_, name.c_str())};
    if (result == -1)
      throw std::runtime_error{"cannot map a line's name \""+name+"\" to its"
        " offset within the chip"};
    return result;
  }

  Line_request line_request(const Request_config& request_config,
    const Line_config& line_config)
  {
    auto* const result = gpiod_chip_request_lines(handle_,
      request_config.handle_, line_config.handle_);
    if (!result)
      throw std::runtime_error{"cannot request a set of lines for exclusive usage"};
    return Line_request{result};
  }

private:
  gpiod_chip* handle_;
};

} // namespace dmitigr::gpio

#endif  // DMITIGR_GPIO_HPP
