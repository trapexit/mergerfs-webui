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

#include <cstdint>
#include <string>
#include <vector>

namespace MergerfsUpdate
{
  struct Status
  {
    std::string state, path, version, manager, package, static_version;
    bool in_place_allowed = false, static_install_allowed = false;
    std::vector<std::string> warnings;
  };

  struct Release
  {
    std::string tag, asset, digest;
    uint64_t size = 0;
  };

  struct Result
  {
    std::string path;
    std::vector<std::string> warnings;
  };

  int
  status(Status      *,
         std::string *);
  int
  latest(Release     *,
         std::string *);
  int
  install(const std::string &tag,
          const std::string &digest,
          const std::string &target,
          Result            *,
          std::string       *);

#ifdef MERGERFS_UPDATE_TEST
  enum class Owner
  {
    PACKAGE,
    UNOWNED,
    UNKNOWN
  };

  using OwnerLookup = Owner (*)(const std::string &, void *);

  struct Fixture
  {
    std::string root, path_env;
    OwnerLookup lookup;
    void *context;
  };

  int
  test_status(const Fixture &,
              Status        *,
              std::string   *);
  int
  test_install_archive(const Fixture     &,
                       const Release     &,
                       const std::string &archive,
                       const std::string &target,
                       Result            *,
                       std::string       *);
#endif
}
