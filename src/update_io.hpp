/*
  ISC License

  Copyright (c) 2026, Antonio SJ Musumeci <trapexit@spawn.link>

  Permission to use, copy, modify, and/or distribute this software for any
  purpose with or without fee is hereby granted, provided that the above
  copyright notice and this permission notice appear in all copies.

  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace UpdateIO
{
  struct FD
  {
    static constexpr int invalid_fd = -1;
    int value = invalid_fd;
    explicit
    FD(int fd = invalid_fd)
      : value(fd)
    {
    }
    ~FD();
    FD(const FD &) = delete;
    FD &operator=(const FD &) = delete;
  };

  int
  fail(std::string       *error,
       int                code,
       const std::string &message);
  int
  run(const std::vector<std::string> &args,
      int                             destination,
      std::string                    *output,
      size_t                          limit,
      std::string                    *error,
      int                            *exit_status = nullptr,
      bool                            capture_stderr = false,
      int                             timeout_seconds = 0);
  int
  curl(const std::string &url,
       uint64_t           limit,
       int                destination,
       std::string       *output,
       std::string       *error);
  int
  hash_file(int          fd,
            std::string *digest,
            std::string *error);
  bool
  hex_digest(std::string_view digest);
  bool
  safe_tag(std::string_view tag);
  bool
  compatible_elf(int fd);
}
