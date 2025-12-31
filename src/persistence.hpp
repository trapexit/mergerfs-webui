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
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace Persistence
{
  struct Source
  {
    std::string type;
    std::string path;
    std::map<std::string,std::string> options;
  };

  struct Roots
  {
    std::string fstab;
    std::vector<std::string> systemd_dirs;
  };

  struct Definition
  {
    std::string type;
    std::string mountpoint;
    std::string branches;
    std::vector<std::pair<std::string,std::string>> options;
    std::string ini_path;
  };

  struct Created
  {
    std::string type;
    std::string path;
    std::string mountpoint;
    std::string ini_path;
  };

  struct Directory
  {
    std::string name;
    std::string path;
  };

  struct DirectoryListing
  {
    std::string path;
    std::string parent;
    std::vector<Directory> directories;
  };

  int
  list_directories(const std::string &path,
                   DirectoryListing  *listing,
                   std::string       *error);

  int
  create(const Definition &definition,
         const Roots      &roots,
         Created          *created,
         std::string      *error);

  int
  list_mountpoints(const Roots              &roots,
                   std::vector<std::string> *mounts,
                   std::string              *error);

  int
  discover(const std::string   &mount,
           const Roots         &roots,
           std::vector<Source> *sources,
           std::string         *error);

  struct Preview
  {
    std::string path;
    std::string before;
    std::string after;
    std::size_t before_line = 0;
    std::size_t after_line = 0;
    std::vector<std::string> config_before;
    std::vector<std::string> config_after;
    std::string revision;
    bool changed = false;
  };

  struct Raw
  {
    std::string type;
    std::string path;
    std::string text;
    std::string revision;
    std::string scope;
  };

  int
  raw_read(const std::string &mount,
           const Roots       &roots,
           const std::string &type,
           const std::string &path,
           Raw               *result,
           std::string       *error);

  int
  raw_save(const std::string &mount,
           const Roots       &roots,
           const std::string &type,
           const std::string &path,
           const std::string &text,
           const std::string &expected_revision,
           std::string       *error);

  int
  preview(const std::string &mount,
          const Roots       &roots,
          const std::string &type,
          const std::string &path,
          const std::string &key,
          const std::string &value,
          Preview           *result,
          std::string       *error,
          bool               remove = false);

  int
  save(const std::string &mount,
       const Roots       &roots,
       const std::string &type,
       const std::string &path,
       const std::string &key,
       const std::string &value,
       std::string       *error,
       const std::string *expected_revision = nullptr,
       bool               remove = false);
  int
  remove(const std::string &mount,
         const Roots       &roots,
         const std::string &type,
         const std::string &path,
         std::string       *retained_ini_path,
         std::string       *error);
}
