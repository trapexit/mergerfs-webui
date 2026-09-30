/*
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

#include <string>

namespace ServiceInstall
{
  constexpr const char *UNIT_NAME      = "mergerfs-webui.service";
  constexpr const char *UNIT_DIRECTORY = "/etc/systemd/system";
  constexpr const char *MANAGED_EXECUTABLE = "/usr/local/bin/mergerfs-webui";
  constexpr const char *MANAGED_PASSWORD_DIRECTORY = "/etc/mergerfs-webui";
  constexpr const char *MANAGED_PASSWORD = "/etc/mergerfs-webui/password";
  constexpr int DEFAULT_PORT = 8080;

  struct Spec
  {
    std::string executable;
    std::string host;
    int port = DEFAULT_PORT;
    // Empty when the service intentionally runs without authentication.
    std::string password_file;
  };

  int
  running_executable(std::string *path,
                     std::string *error);

  // Require a safe, runnable on-disk path matching the running inode.

  int
  runnable_running_executable(std::string *path,
                              std::string *error);

  // Install a fresh inode atomically; replace only a safe regular destination.

  int
  stage_executable(const std::string &source,
                   const std::string &destination,
                   bool              *created,
                   std::string       *error);

  // Atomically create or replace only a private, singly linked managed password.

  int
  create_password(const std::string &directory,
                  const std::string &secret,
                  bool              *created,
                  std::string       *error);

  // Validate unit arguments without requiring root or accessing the filesystem.

  int
  validate_arguments(const Spec &spec,
                     std::string *error);

  int
  validate(const Spec  &spec,
           std::string *error);

  // Read only an installer-owned, canonical generated unit; reject collisions.

  int
  inspect(const std::string &directory,
          Spec              *spec,
          bool              *installed,
          std::string       *error);

  // Returns EEXIST for a unit with different content, including a symlink.

  int
  existing(const Spec        &spec,
           const std::string &directory,
           bool              *installed,
           std::string       *error);

  // Never replaces an existing unit. An identical unit is accepted unchanged.

  int
  write_unit(const Spec        &spec,
             const std::string &directory,
             bool              *created,
             std::string       *error);

  // Remove only an identical unit owned by this process; leave staged files untouched.

  int
  remove_unit(const Spec        &spec,
              const std::string &directory,
              std::string       *error);

  // Atomically replace the installed unit while systemd observes its old inode.
  int
  replace_unit(const Spec        &current,
               const Spec        &spec,
               const std::string &directory,
               bool              *created,
               std::string       *error);

  // Atomically replace only a managed password set by create_password.
  int
  replace_password(const std::string &directory,
                   const std::string &secret,
                   std::string       *error);
}
