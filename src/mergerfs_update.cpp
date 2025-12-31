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

#include "mergerfs_update.hpp"
#include "json.hpp"
#include "update_io.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <set>
#include <sstream>
#include <string_view>
#include <utility>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace MergerfsUpdate
{
  namespace
  {
    constexpr uint64_t MAX_ARCHIVE = 64 * 1024 * 1024;
    constexpr char API_URL[] = "https://api.github.com/repos/trapexit/mergerfs/releases/latest";
    constexpr char STATIC_BINARY[]     = "/usr/local/bin/mergerfs";
    constexpr size_t MAX_METADATA_SIZE = 1024 * 1024;
    constexpr size_t MAX_PACKAGE_ID_LENGTH = 256;
    constexpr size_t MAX_MEMBER_SIZE = 32 * 1024 * 1024;
    constexpr mode_t TRUSTED_DIRECTORY_MODE = 0755;
    constexpr mode_t EXECUTE_BITS  = 0111;
    constexpr char SHA256_PREFIX[] = "sha256:";
    constexpr size_t SHA256_PREFIX_LENGTH = sizeof(SHA256_PREFIX) - 1;
    constexpr char NIX_STORE_PREFIX[]     = "/nix/store/";
    constexpr size_t NIX_STORE_PREFIX_LENGTH = sizeof(NIX_STORE_PREFIX) - 1;
    constexpr char USR_LOCAL_PREFIX[] = "/usr/local/";
    constexpr size_t USR_LOCAL_PREFIX_LENGTH = sizeof(USR_LOCAL_PREFIX) - 1;
    std::mutex install_mutex;

    struct Environment
    {
      std::string root, path_env;
#ifdef MERGERFS_UPDATE_TEST
      OwnerLookup lookup = nullptr;
      void *context = nullptr;
#endif
      bool fixture = false;
      std::string physical(const std::string &path_) const { return root + path_; }
      uid_t trusted_uid() const { return fixture ? ::geteuid() : 0; }
    };


    Environment
    production()
    {
      Environment  env;
      const char  *path = ::getenv("PATH");
      env.path_env =
        ((((path) && (*path))) ?
         path :
         "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
      return env;
    }


    bool
    safe_file(const struct stat &s_)
    {
      return ((S_ISREG(s_.st_mode)) &&
              (s_.st_nlink == 1) &&
              (!(s_.st_mode & (S_ISUID|S_ISGID|S_IWGRP|S_IWOTH))) &&
              (s_.st_mode & EXECUTE_BITS));
    }


    bool
    same_file(const struct stat &a_,
              const struct stat &b_)
    {
      return ((a_.st_dev == b_.st_dev) &&
              (a_.st_ino == b_.st_ino) &&
              (a_.st_nlink == b_.st_nlink) &&
              (a_.st_size == b_.st_size) &&
              (a_.st_mtim.tv_sec == b_.st_mtim.tv_sec) &&
              (a_.st_mtim.tv_nsec == b_.st_mtim.tv_nsec) &&
              (a_.st_ctim.tv_sec == b_.st_ctim.tv_sec) &&
              (a_.st_ctim.tv_nsec == b_.st_ctim.tv_nsec) &&
              (a_.st_mode == b_.st_mode) &&
              (a_.st_uid == b_.st_uid) &&
              (a_.st_gid == b_.st_gid));
    }


    struct Ownership
    {
      enum Kind
      {
        PACKAGE,
        UNOWNED,
        UNKNOWN
      } kind = UNKNOWN;
      std::string manager, name, reason;
    };


    bool
    package_id(const std::string &id_)
    {
      if((id_.empty()) || (id_.size() > MAX_PACKAGE_ID_LENGTH))
        return false;
      for(unsigned char c : id_)
        {
          if(!(((c >= 'a') &&
                (c <= 'z')) ||
               ((c >= 'A') &&
                (c <= 'Z')) ||
               ((c >= '0') &&
                (c <= '9')) ||
               (c == '-') ||
               (c == '_') ||
               (c == '.') ||
               (c == '+') ||
               (c == ':') ||
               (c == '~')))
            return false;
        }

      return true;
    }


    struct Manager
    {
      const char  *name, *db1, *db2, *tool1, *tool2;
    };

    constexpr Manager MANAGERS[] =
      {
        {"dpkg","/var/lib/dpkg/status",nullptr,"/usr/bin/dpkg-query",nullptr},
        {"rpm","/var/lib/rpm","/usr/lib/sysimage/rpm","/usr/bin/rpm",nullptr},
        {"pacman","/var/lib/pacman/local",nullptr,"/usr/bin/pacman",nullptr},
        {"apk","/lib/apk/db/installed",nullptr,"/sbin/apk","/usr/sbin/apk"}
      };


    std::string
    single_line(const std::string &text_)
    {
      const size_t end = text_.find('\n');
      if((end == std::string::npos) || (end + 1 != text_.size()))
        return {};
      return text_.substr(0,end);
    }


    Ownership
    query_owner(const Environment &env,
                const std::string &path)
    {
#ifdef MERGERFS_UPDATE_TEST
      if((env.fixture) && (env.lookup))
        {
          const Owner answer = env.lookup(path,env.context);
          if(answer == Owner::PACKAGE)
            return {Ownership::PACKAGE,"fixture","fixture-package",{}};
          if(answer == Owner::UNOWNED)
            return {Ownership::UNOWNED,{},{},{}};
          return {Ownership::UNKNOWN,{},{},"ownership cannot be established for " + path};
        }
#endif
      bool applicable = false;
      Ownership uncertainty;
      for(const Manager &manager : MANAGERS)
        {
          if((::access(env.physical(manager.db1).c_str(),F_OK) != 0) &&
             ((!manager.db2) ||
              (::access(env.physical(manager.db2).c_str(),F_OK) != 0)))
            continue;
          applicable = true;
          std::string tool = manager.tool1;
          if((::access(tool.c_str(),X_OK) != 0) && (manager.tool2))
            tool = manager.tool2;
          if(::access(tool.c_str(),X_OK) != 0)
            {
              uncertainty.reason =
              std::string(manager.name) + " database exists without a usable query tool";
              continue;
            }

          std::vector<std::string> args{tool};
          if(std::strcmp(manager.name,"dpkg") == 0)
            {
              args.push_back("-S");
              args.push_back(path);
            }

          if(std::strcmp(manager.name,"rpm") == 0)
            {
              args.push_back("-qf");
              args.push_back(path);
            }

          if(std::strcmp(manager.name,"pacman") == 0)
            {
              args.push_back("-Qo");
              args.push_back(path);
            }

          if(std::strcmp(manager.name,"apk") == 0)
            {
              args.push_back("info");
              args.push_back("-vW");
              args.push_back(path);
            }

          std::string output, command_error;
          int exit_status = -1;
          if(UpdateIO::run(args,-1,&output,4096,&command_error,&exit_status,true,5))
            {
              uncertainty.reason =
              std::string(manager.name) + " ownership query failed: " + command_error;
              continue;
            }

          if(exit_status == 0)
            {
              std::string line = single_line(output), id;
              if(std::strcmp(manager.name,"dpkg") == 0)
                {
                  const size_t sep = line.find(": " + path);
                  if((sep != std::string::npos) && (sep + 2 + path.size() == line.size()))
                    id = line.substr(0,sep);
                }
              else if(std::strcmp(manager.name,"rpm") == 0)
                {
                  id = line;
                }
              else if(std::strcmp(manager.name,"pacman") == 0)
                {
                  const std::string prefix = path + " is owned by ";
                  if(line.compare(0,prefix.size(),prefix) == 0)
                    {
                      const size_t end = line.find(' ',prefix.size());
                      if((end != std::string::npos) && (end + 1 < line.size()))
                        id = line.substr(prefix.size(),end - prefix.size());
                    }
                }
              else
                {
                  const std::string prefix = path + " is owned by ";
                  if(line.compare(0,prefix.size(),prefix) == 0)
                    id = line.substr(prefix.size());
                }

              if(!package_id(id))
                {
                  uncertainty.reason =
                  std::string(manager.name) + " returned malformed ownership for " + path;
                  continue;
                }

              return {Ownership::PACKAGE,manager.name,id,{}};
            }

          const bool no_owner =
            ((exit_status == 1) &&
             (((std::strcmp(manager.name,"dpkg") == 0) &&
               (output.find("dpkg-query: no path found matching pattern") != std::string::npos)) ||
              ((std::strcmp(manager.name,"rpm") == 0) &&
               (output.find("is not owned by any package") != std::string::npos)) ||
              ((std::strcmp(manager.name,"pacman") == 0) &&
               (output.find("No package owns") != std::string::npos)) ||
              ((std::strcmp(manager.name,"apk") == 0) &&
               (output.find("Could not find owner package") != std::string::npos))));
          if(!no_owner)
            {
              uncertainty.reason =
              std::string(manager.name) + " returned an unrecognized ownership answer for " + path;
            }
        }

      if(!applicable)
        return {Ownership::UNKNOWN,{},{},"no installed package database can classify " + path};
      if(!uncertainty.reason.empty())
        return uncertainty;
      return {Ownership::UNOWNED,{},{},{}};
    }


    Ownership
    ownership(const Environment &env_,
              const std::string &path_)
    {
      Ownership lexical = query_owner(env_,path_);
      std::array<char,PATH_MAX> resolved{};
      if(!::realpath(env_.physical(path_).c_str(),resolved.data()))
        return {Ownership::UNKNOWN,{},{},"cannot resolve " + path_};
      std::string actual = resolved.data();
      if(env_.fixture)
        {
          if((actual.compare(0,env_.root.size(),env_.root) != 0) ||
             ((actual.size() > env_.root.size()) &&
              (actual[env_.root.size()] != '/')))
            return {Ownership::UNKNOWN,{},{},"path resolves outside the fixture root"};
          actual.erase(0,env_.root.size());
        }

      if(actual == path_)
        return lexical;
      Ownership target = query_owner(env_,actual);
      if(lexical.kind == Ownership::PACKAGE)
        return lexical;
      if(target.kind == Ownership::PACKAGE)
        return target;
      if(lexical.kind == Ownership::UNKNOWN)
        return lexical;
      return target;
    }


    bool
    selected_executable(const Environment &env_,
                        const std::string &path_)
    {
      struct stat s{};
      return ((::stat(env_.physical(path_).c_str(),&s) == 0) &&
              (S_ISREG(s.st_mode)) &&
              (s.st_mode & EXECUTE_BITS) &&
              (::access(env_.physical(path_).c_str(),X_OK) == 0));
    }


    int
    parent_directory(const Environment        &,
                     const std::string        &,
                     bool,
                     bool,
                     std::vector<std::string> *,
                     int                      *,
                     std::string              *);


    std::string
    version(const Environment &env_,
            const std::string &path_)
    {
      struct stat s{}, link{};
      const std::string file = env_.physical(path_);
      if((::lstat(file.c_str(),&link) < 0) ||
         (!S_ISREG(link.st_mode)) ||
         (::stat(file.c_str(),&s) < 0) ||
         (s.st_uid != env_.trusted_uid()) ||
         (s.st_mode & (S_IWGRP|S_IWOTH)))
        return {};
      int parent = -1;
      std::string ignored;
      if(parent_directory(env_,path_,false,false,nullptr,&parent,&ignored))
        return {};
      ::close(parent);
      std::string output, command_error;
      int code = -1;
      if((UpdateIO::run({file,"--version"},-1,&output,4096,&command_error,&code,true,5)) || (code))
        return {};
      const std::string line   = output.substr(0,output.find('\n'));
      const std::string prefix = "mergerfs v";
      if(line.compare(0,prefix.size(),prefix) != 0)
        return {};
      const std::string tag = line.substr(prefix.size());
      return UpdateIO::safe_tag(tag) ? tag : std::string{};
    }


    int
    local_status(const Environment &env,
                 Status            *result,
                 std::string       *error)
    {
      if(!result)
        return UpdateIO::fail(error,EINVAL,"missing mergerfs status destination");
      Status out;
      out.state = "missing";
      for(size_t start = 0; start < env.path_env.size();)
        {
          size_t end = env.path_env.find(':',start);
          if(end == std::string::npos)
            end = env.path_env.size();
          const std::string dir = env.path_env.substr(start,end - start);
          if((!dir.empty()) && (dir[0] == '/') && (selected_executable(env,dir + "/mergerfs")))
            {
              out.path = dir + "/mergerfs";
              break;
            }

          start = end + 1;
        }

      if(!out.path.empty())
        {
          Ownership owner = ownership(env,out.path);
          out.state =
            ((owner.kind == Ownership::PACKAGE) ?
             "package" :
             (owner.kind == Ownership::UNOWNED) ?
             "unmanaged" :
             "unknown");
          out.manager = owner.manager;
          out.package = owner.name;
          if(!owner.reason.empty())
            out.warnings.push_back(owner.reason);
          struct stat s{}, link{};
          const bool metadata =
            ((::lstat(env.physical(out.path).c_str(),&link) == 0) &&
             (::stat(env.physical(out.path).c_str(),&s) == 0));
          int parent = -1;
          std::string ignored;
          const bool safe_parent =
            parent_directory(env,out.path,false,false,nullptr,&parent,&ignored) == 0;
          if(parent >= 0)
            ::close(parent);
          out.in_place_allowed =
            ((owner.kind == Ownership::UNOWNED) &&
             (metadata) &&
             (S_ISREG(link.st_mode)) &&
             (safe_file(s)) &&
             (s.st_uid == env.trusted_uid()) &&
             (safe_parent) &&
             (out.path.compare(0,NIX_STORE_PREFIX_LENGTH,NIX_STORE_PREFIX) != 0));
          if(owner.kind == Ownership::PACKAGE)
            out.warnings.push_back("Package-owned mergerfs is preserved; use the separate /usr/local static installation.");
          if((!out.in_place_allowed) && (owner.kind == Ownership::UNOWNED))
            out.warnings.push_back("In-place update requires a root-owned, singly linked, non-setuid regular executable without writable group/other bits or symlinks.");
          if(out.path.compare(0,NIX_STORE_PREFIX_LENGTH,NIX_STORE_PREFIX) == 0)
            out.warnings.push_back("Nix store paths cannot be updated in place.");
          out.version = version(env,out.path);
        }

      for(const char *candidate : {
          "/usr/bin/mergerfs",
          "/bin/mergerfs",
          "/usr/sbin/mergerfs",
          "/sbin/mergerfs"
        })
        {
          if((selected_executable(env,candidate)) && (candidate != out.path))
            {
              Ownership owner = ownership(env,candidate);
              if(owner.kind == Ownership::PACKAGE)
                {
                  out.warnings.push_back(std::string("A packaged ") + candidate +
                                         " remains installed; absolute-path services may continue using it after a /usr/local install.");
                }
            }
        }

      struct stat local{};
      if(::lstat(env.physical(STATIC_BINARY).c_str(),&local) == 0)
        {
          Ownership owner = ownership(env,STATIC_BINARY);
          out.static_version =
            ((out.path == STATIC_BINARY) ? out.version : version(env,STATIC_BINARY));
          if((owner.kind == Ownership::UNOWNED) &&
             (safe_file(local)) &&
             (local.st_uid == env.trusted_uid()))
            {
              out.static_install_allowed = true;
            }
          else
            {
              out.warnings.push_back(std::string("Cannot replace /usr/local/bin/mergerfs: ") +
                                     ((owner.kind == Ownership::PACKAGE) ?
                                      "package-owned" :
                                      (owner.kind == Ownership::UNKNOWN) ?
                                      owner.reason :
                                      "unsafe file metadata or symlink"));
            }
        }
      else if(errno == ENOENT)
        {
          out.static_install_allowed = true;
        }
      else
        {
          out.warnings.push_back("Cannot inspect /usr/local/bin/mergerfs");
        }

      int static_parent = -1;
      std::string parent_error;
      if(parent_directory(env,STATIC_BINARY,false,true,nullptr,&static_parent,&parent_error))
        {
          out.static_install_allowed = false;
          out.warnings.push_back("Cannot use /usr/local/bin: " + parent_error);
        }

      if(static_parent >= 0)
        ::close(static_parent);
      if((::geteuid() != 0) && (!env.fixture))
        {
          out.static_install_allowed = false;
          out.warnings.push_back("Installing the static release requires root privileges.");
        }

      if((!out.path.empty()) && (out.path != STATIC_BINARY))
        out.warnings.push_back("PATH selection and services configured with absolute mergerfs paths may differ; a static overlay does not change those services.");
      *result = std::move(out);
      return 0;
    }


    const
    char*
    architecture()
    {
#if defined(__x86_64__)
      return "amd64";
#elif defined(__aarch64__)
      return "arm64";
#elif defined(__arm__)
      return "armhf";
#elif defined(__riscv) && __riscv_xlen == 64
      return "riscv64";
#else
      return nullptr;
#endif
    }


    struct Member
    {
      const char *name;
      const char *mode;
      bool elf;
      uint64_t size = 0;
    };

    constexpr const char *DIRECTORIES[] =
      {
        "usr/",
        "usr/local/",
        "usr/local/bin/",
        "usr/local/lib/",
        "usr/local/lib/mergerfs/",
        "usr/local/share/",
        "usr/local/share/man/",
        "usr/local/share/man/man1/",
        "sbin/"
      };
    constexpr Member EXPECTED[] =
      {
        {"usr/local/bin/mergerfs","-rwxr-xr-x",true,0},
        {"usr/local/bin/mergerfs-fusermount","-rwsr-xr-x",true,0},
        {"usr/local/bin/fsck.mergerfs","lrwxrwxrwx",false,0},
        {"usr/local/bin/mergerfs.collect-info","lrwxrwxrwx",false,0},
        {"usr/local/lib/mergerfs/preload.so","-r--r--r--",true,0},
        {"usr/local/share/man/man1/mergerfs.1","-rw-r--r--",false,0},
        {"sbin/mount.mergerfs","-rwxr-xr-x",true,0}
      };


    const
    char*
    tar_program()
    {
      if(::access("/usr/bin/tar",X_OK) == 0)
        return "/usr/bin/tar";
      if(::access("/bin/tar",X_OK) == 0)
        return "/bin/tar";
      return nullptr;
    }


    int
    inspect_archive(const std::string    &archive,
                    std::array<Member,7> *members,
                    std::string          *error)
    {
      const char *tar = tar_program();
      if(!tar)
        return UpdateIO::fail(error,ENOTSUP,"no supported tar program is available");
      std::string listing;
      int exit_code = 0;
      int rc = UpdateIO::run({
            tar,
            "--list",
            "--gzip",
            "--verbose",
            "--numeric-owner",
            "--full-time",
            "--quoting-style=literal",
            "--file",
            archive
          },
        -1,
        &listing,
        65536,
        error,
        &exit_code,
        true,
        30);
      if((rc) || (exit_code))
        return UpdateIO::fail(error,ENOTSUP,"tar cannot safely list the static release");
      *members = {};
      for(size_t i = 0; i < members->size(); ++i)
        (*members)[i] = EXPECTED[i];
      std::set<std::string> seen;
      std::istringstream lines(listing);
      std::string line;
      while(std::getline(lines,line))
        {
          std::istringstream fields(line);
          std::string mode, owner, count, day, time, name;
          if(!(fields >> mode >> owner >> count >> day >> time))
            return UpdateIO::fail(error,EBADMSG,"unparseable static archive listing");
          std::getline(fields,name);
          if((name.empty()) || (name[0] != ' ') || (owner != "0/0"))
            return UpdateIO::fail(error,EBADMSG,"unsafe archive name or ownership");
          name.erase(0,1);
          if(!seen.insert(name).second)
            return UpdateIO::fail(error,EBADMSG,"duplicate static archive member");
          bool directory = false;
          for(const char *expected : DIRECTORIES)
            {
              if(name == expected)
                {
                  directory = true;
                  break;
                }
            }

          if(directory)
            {
              if((mode != "drwxr-xr-x") || (count != "0"))
                return UpdateIO::fail(error,EBADMSG,"unsafe archive directory");
              continue;
            }

          Member *member = nullptr;
          for(Member &candidate : *members)
            {
              if((name == candidate.name) ||
                 ((candidate.mode[0] == 'l') &&
                  (name == std::string(candidate.name) + " -> mergerfs")))
                {
                  member = &candidate;
                  break;
                }
            }

          if((!member) ||
             (mode != member->mode) ||
             (count.empty()) ||
             (!std::all_of(count.begin(),
                           count.end(),
                           [](char c_){ return c_ >= '0' && c_ <= '9'; })))
            return UpdateIO::fail(error,EBADMSG,"unexpected archive member, type, mode or link");
          try
            {
              member->size = std::stoull(count);
            }
          catch(const std::exception &)
            {
              return UpdateIO::fail(error,EBADMSG,"invalid archive member size");
            }

          if((member->size > MAX_MEMBER_SIZE) ||
             ((member->mode[0] == 'l') &&
              (member->size != 0)) ||
             ((member->mode[0] != 'l') &&
              (member->size == 0)))
            return UpdateIO::fail(error,EBADMSG,"archive member exceeds size or type limit");
        }

      if(seen.size() != std::size(DIRECTORIES) + members->size())
        return UpdateIO::fail(error,EBADMSG,"static archive is missing required members");
      return 0;
    }


    int
    verified_archive(int            fd_,
                     const Release &release_,
                     std::string   *error_)
    {
      struct stat metadata{};
      if((::fstat(fd_,&metadata) < 0) ||
         (!S_ISREG(metadata.st_mode)) ||
         (metadata.st_size != static_cast<off_t>(release_.size)) ||
         (!release_.size) ||
         (release_.size > MAX_ARCHIVE))
        return UpdateIO::fail(error_,EBADMSG,"static release size does not match metadata");
      std::string digest;
      int rc = UpdateIO::hash_file(fd_,&digest,error_);
      if(rc)
        return rc;
      if(digest != release_.digest)
        return UpdateIO::fail(error_,EBADMSG,"static release SHA-256 does not match metadata");
      return 0;
    }


    bool
    trusted_directory(const Environment &env_,
                      int                fd_)
    {
      struct stat s{};
      return ((::fstat(fd_,&s) == 0) &&
              (S_ISDIR(s.st_mode)) &&
              (s.st_uid == env_.trusted_uid()) &&
              (!(s.st_mode & (S_IWGRP|S_IWOTH))));
    }


    int
    parent_directory(const Environment        &env,
                     const std::string        &path,
                     bool                      create,
                     bool                      allow_missing,
                     std::vector<std::string> *made,
                     int                      *descriptor,
                     std::string              *error)
    {
      if((path.size() < 2) || (path[0] != '/') || (path.back() == '/'))
        return UpdateIO::fail(error,EINVAL,"invalid destination path");
      UpdateIO::FD dir(::open(env.root.empty() ? "/" : env.root.c_str(),
                              O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
      if((dir.value < 0) || (!trusted_directory(env,dir.value)))
        return UpdateIO::fail(error,EACCES,"untrusted destination root");
      size_t start      = 1;
      const size_t last = path.rfind('/');
      std::string prefix;
      while(start < last)
        {
          const size_t end = path.find('/',start);
          if((end == std::string::npos) || (end > last))
            break;
          const std::string component = path.substr(start,end - start);
          if((component.empty()) || (component == ".") || (component == ".."))
            return UpdateIO::fail(error,EACCES,"unsafe destination directory component");
          prefix += "/" + component;
          int child =
            ::openat(dir.value,component.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
          if((child < 0) &&
             (errno == ENOENT) &&
             ((prefix == "/usr/local") ||
              (prefix.compare(0,USR_LOCAL_PREFIX_LENGTH,USR_LOCAL_PREFIX) == 0)))
            {
              if((allow_missing) && (!create))
                {
                  *descriptor = -1;
                  return 0;
                }

              if((create) && (::mkdirat(dir.value,component.c_str(),TRUSTED_DIRECTORY_MODE) == 0))
                {
                  made->push_back(prefix);
                  child = ::openat(dir.value,
                                   component.c_str(),
                                   O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
                  if((child >= 0) && (::fchmod(child,TRUSTED_DIRECTORY_MODE) < 0))
                    {
                      ::close(child);
                      return UpdateIO::fail(error,errno,"cannot set trusted directory mode");
                    }
                }
            }

          if(child < 0)
            return UpdateIO::fail(error,errno,"cannot open trusted destination parent " + prefix);
          ::close(dir.value);
          dir.value = child;
          if(!trusted_directory(env,dir.value))
            return UpdateIO::fail(error,EACCES,"untrusted destination parent " + prefix);
          start = end + 1;
        }

      *descriptor = dir.value;
      dir.value   = -1;
      return 0;
    }


    struct Destination
    {
      std::string path, lexical, member, name, temporary, backup;
      const Member *spec = nullptr;
      int parent = -1;
      bool exists = false, committed = false;
      struct stat original{};
      ~Destination() { if(parent >= 0) ::close(parent); }
      Destination() = default;
      Destination(const Destination &) = delete;
      Destination &operator=(const Destination &) = delete;
    };


    bool
    valid_destination(const Environment &env,
                      const Destination &item,
                      const struct stat &s)
    {
      if((s.st_uid != env.trusted_uid()) || (s.st_nlink != 1))
        return false;
      if((item.spec) && (item.spec->mode[0] == 'l'))
        {
          if(!S_ISLNK(s.st_mode))
            return false;
          char link[64];
          ssize_t n =
            ((item.parent >= 0) ?
             ::readlinkat(item.parent,item.name.c_str(),link,sizeof(link)) :
             ::readlink(env.physical(item.path).c_str(),link,sizeof(link)));
          return ((n == 8) && (std::string(link,static_cast<size_t>(n)) == "mergerfs"));
        }

      return ((S_ISREG(s.st_mode)) &&
              (!(s.st_mode & (S_IWGRP|S_IWOTH|S_ISGID))) &&
              ((!(s.st_mode & S_ISUID)) ||
               ((item.spec) &&
                (item.member == "usr/local/bin/mergerfs-fusermount") &&
                ((s.st_mode & 07777) == 04755))));
    }


    int
    destination_check(const Environment &env,
                      Destination       *item,
                      bool               before_commit,
                      std::string       *error)
    {
      struct stat now{};
      const int inspected =
        ((item->parent >= 0) ?
         ::fstatat(item->parent,item->name.c_str(),&now,AT_SYMLINK_NOFOLLOW) :
         ::lstat(env.physical(item->path).c_str(),&now));
      if((inspected < 0) && (errno != ENOENT))
        return UpdateIO::fail(error,EAGAIN,"cannot inspect destination " + item->lexical);
      const bool exists = inspected == 0;
      if((before_commit) &&
         ((exists != item->exists) ||
          ((exists) &&
           (!same_file(now,item->original)))))
        return UpdateIO::fail(error,EAGAIN,"destination changed before commit: " + item->lexical);
      if(!exists)
        {
          if(!before_commit)
            item->exists = false;
          return 0;
        }

      if(!valid_destination(env,*item,now))
        return UpdateIO::fail(error,EAGAIN,"unsafe destination file or alias: " + item->lexical);
      Ownership owner =
        ((((item->spec) && (item->spec->mode[0] == 'l'))) ?
         query_owner(env,item->path) :
         ownership(env,item->path));
      if(item->lexical != item->path)
        {
          Ownership lexical = query_owner(env,item->lexical);
          if(lexical.kind != Ownership::UNOWNED)
            owner = lexical;
        }

      if(owner.kind != Ownership::UNOWNED)
        {
          return UpdateIO::fail(error,
                                EAGAIN,
                                "destination ownership is package-owned or unknown: " +
                                item->lexical);
        }

      if(!before_commit)
        {
          item->exists   = true;
          item->original = now;
        }

      return 0;
    }


    std::string
    unique_name(int         fd_,
                const char *purpose_)
    {
      static unsigned counter = 0;
      for(unsigned tries = 0; tries < 100; ++tries)
        {
          const std::string name = std::string(".mergerfs-") + purpose_ + "-" +
                                   std::to_string(::getpid()) + "-" + std::to_string(++counter);
          struct stat s{};
          if((::fstatat(fd_,name.c_str(),&s,AT_SYMLINK_NOFOLLOW) < 0) && (errno == ENOENT))
            return name;
        }

      return {};
    }


    int
    stage(const Environment &env,
          const std::string &archive,
          Destination       *item,
          std::string       *error)
    {
      item->temporary = unique_name(item->parent,"stage");
      if(item->temporary.empty())
        return UpdateIO::fail(error,EEXIST,"no safe staging name");
      if(item->spec->mode[0] == 'l')
        {
          if(::symlinkat("mergerfs",item->parent,item->temporary.c_str()) < 0)
            {
              item->temporary.clear();
              return UpdateIO::fail(error,errno,"cannot stage archive alias");
            }

          return 0;
        }

      UpdateIO::FD staged(::openat(item->parent,
                                   item->temporary.c_str(),
                                   O_CREAT|O_EXCL|O_RDWR|O_NOFOLLOW|O_CLOEXEC,
                                   0600));
      if(staged.value < 0)
        {
          item->temporary.clear();
          return UpdateIO::fail(error,errno,"cannot stage archive member");
        }

      const char *tar = tar_program();
      int rc = UpdateIO::run({
            tar,
            "--extract",
            "--gzip",
            "--to-stdout",
            "--file",
            archive,
            "--",
            item->member
          },
        staged.value,
        nullptr,
        static_cast<size_t>(item->spec->size),
        error,
        nullptr,
        false,
        30);
      if(rc)
        return UpdateIO::fail(error,EBADMSG,"cannot safely extract " + item->member);
      struct stat s{};
      if((::fstat(staged.value,&s) < 0) ||
         (s.st_size != static_cast<off_t>(item->spec->size)) ||
         ((item->spec->elf) &&
          (!UpdateIO::compatible_elf(staged.value))))
        {
          return UpdateIO::fail(error,
                                EBADMSG,
                                "archive member size or ELF architecture differs: " + item->member);
        }

      const mode_t mode =
        ((item->member == "usr/local/bin/mergerfs-fusermount") ?
         04755 :
         (item->member == "usr/local/lib/mergerfs/preload.so") ?
         0444 :
         (item->member == "usr/local/share/man/man1/mergerfs.1") ?
         0644 :
         0755);
      const uid_t uid = (item->exists) ? item->original.st_uid : env.trusted_uid();
      const gid_t gid = (item->exists) ? item->original.st_gid : (env.fixture ? ::getegid() : 0);
      const mode_t effective_mode =
        ((((item->lexical == item->path) &&
           (item->member == "usr/local/bin/mergerfs") &&
           (item->path != STATIC_BINARY) &&
           (item->exists))) ?
         item->original.st_mode & 0777 :
         mode);
      if((::fchown(staged.value,uid,gid) < 0) ||
         (::fchmod(staged.value,effective_mode) < 0) ||
         (::fsync(staged.value) < 0))
        return UpdateIO::fail(error,errno,"cannot prepare archive replacement");
      return 0;
    }


    bool
    clean_install(const Environment              &env,
                  std::array<Destination,8>      &items,
                  size_t                          count,
                  const std::vector<std::string> &made,
                  bool                            rollback,
                  std::string                    *error)
    {
      bool incomplete = false;
      for(size_t i = count; i-- > 0;)
        {
          Destination &item = items[i];
          if(item.parent < 0)
            continue;
          if((rollback) && (item.committed))
            {
              const int rc =
                ((item.exists) ?
                 ::renameat(item.parent,item.backup.c_str(),item.parent,item.name.c_str()) :
                 ::unlinkat(item.parent,item.name.c_str(),0));
              if((rc < 0) || (::fsync(item.parent) < 0))
                incomplete = true;
              if((item.exists) && (rc == 0))
                item.backup.clear();
            }

          if((!item.temporary.empty()) &&
             (::unlinkat(item.parent,item.temporary.c_str(),0) < 0) &&
             (errno != ENOENT))
            incomplete = true;
          if((!item.backup.empty()) &&
             ((!rollback) ||
              (!item.committed)) &&
             (::unlinkat(item.parent,item.backup.c_str(),0) < 0) &&
             (errno != ENOENT))
            incomplete = true;
        }

      for(auto it = made.rbegin(); it != made.rend(); ++it)
        {
          if((::rmdir(env.physical(*it).c_str()) < 0) && (errno != ENOTEMPTY))
            incomplete = true;
        }

      if((incomplete) && (error))
        *error += "; rollback or temporary directory cleanup incomplete; inspect destinations";
      return !incomplete;
    }


    int
    manual_destination(const Environment &env,
                       std::string       *path,
                       struct stat       *alias,
                       bool              *linked,
                       std::string       *error)
    {
      *path   = "/usr/local/share/man/man1/mergerfs.1";
      *linked = false;
      int parent = -1;
      int rc     = parent_directory(env,"/usr/local/share/man",false,true,nullptr,&parent,error);
      if((rc) || (parent < 0))
        return rc;
      UpdateIO::FD directory(parent);
      struct stat metadata{};
      if(::fstatat(directory.value,"man",&metadata,AT_SYMLINK_NOFOLLOW) < 0)
        {
          return (errno == ENOENT) ?
                 0 :
                 UpdateIO::fail(error,errno,"cannot inspect /usr/local/share/man");
        }

      if(!S_ISLNK(metadata.st_mode))
        return 0;
      char target[64];
      const ssize_t length = ::readlinkat(directory.value,"man",target,sizeof(target));
      if((metadata.st_uid != env.trusted_uid()) ||
         (length != 6) ||
         (std::string_view(target,static_cast<size_t>(length)) != "../man"))
        {
          return UpdateIO::fail(error,
                                EACCES,
                                "/usr/local/share/man is not a trusted symlink to ../man");
        }

      int target_directory = -1;
      rc = parent_directory(env,
                            "/usr/local/man/.mergerfs-directory-check",
                            false,
                            false,
                            nullptr,
                            &target_directory,
                            error);
      if(rc)
        {
          return UpdateIO::fail(error,
                                EACCES,
                                "/usr/local/share/man points to an absent or untrusted /usr/local/man directory");
        }

      ::close(target_directory);
      *path   = "/usr/local/man/man1/mergerfs.1";
      *alias  = metadata;
      *linked = true;
      return 0;
    }


    int
    archive_install(const Environment &env,
                    const Release     &release,
                    int                fd,
                    const std::string &target,
                    Result            *result,
                    std::string       *error)
    {
      if((!result) || ((target != "existing") && (target != "static")))
        return UpdateIO::fail(error,EINVAL,"invalid mergerfs installation target");
      Status current;
      int    rc = local_status(env,&current,error);
      if(rc)
        return rc;
      if((target == "static") && (!env.fixture) && (::geteuid() != 0))
        return UpdateIO::fail(error,EACCES,"static installation requires root");
      if((target == "existing") && (!current.in_place_allowed))
        return UpdateIO::fail(error,EAGAIN,"selected mergerfs binary is not safely unmanaged");
      if((target == "static") && (!current.static_install_allowed))
        return UpdateIO::fail(error,EAGAIN,"local static binary cannot be replaced safely");
      rc = verified_archive(fd,release,error);
      if(rc)
        return rc;
      const std::string archive =
        "/proc/" + std::to_string(::getpid()) + "/fd/" + std::to_string(fd);
      std::array<Member,7> members{};
      rc = inspect_archive(archive,&members,error);
      if(rc)
        return rc;
      std::array<Destination,8> items{};
      size_t count = 0;
      const auto add = [&](const std::string &path,
                           const std::string &lexical,
                           size_t index)
      {
        Destination &item = items[count++];
        item.path    = path;
        item.lexical = lexical;
        item.name    = path.substr(path.rfind('/') + 1);
        item.member  = members[index].name;
        item.spec    = &members[index];
      };
      std::vector<std::string> warnings;
      std::string manual_path;
      struct stat manual_alias{};
      bool manual_linked = false;
      if(target == "existing")
        {
          add(current.path,current.path,0);
        }
      else
        {
          add("/usr/local/bin/mergerfs-fusermount","/usr/local/bin/mergerfs-fusermount",1);
          add("/usr/local/bin/fsck.mergerfs","/usr/local/bin/fsck.mergerfs",2);
          add("/usr/local/bin/mergerfs.collect-info","/usr/local/bin/mergerfs.collect-info",3);
          add("/usr/local/lib/mergerfs/preload.so","/usr/local/lib/mergerfs/preload.so",4);
          rc = manual_destination(env,&manual_path,&manual_alias,&manual_linked,error);
          if(rc)
            return rc;
          add(manual_path,"/usr/local/share/man/man1/mergerfs.1",5);
          add("/usr/local/sbin/mount.mergerfs","/usr/local/sbin/mount.mergerfs",6);
          bool helper_available = true;
          struct stat s{};
          const std::string sbin = env.physical("/sbin");
          if(::lstat(sbin.c_str(),&s) < 0)
            {
              helper_available = false;
            }
          else if(S_ISLNK(s.st_mode))
            {
              char link[64];
              const ssize_t n = ::readlink(sbin.c_str(),link,sizeof(link));
              const std::string destination =
                ((n > 0) ?
                 std::string(link,static_cast<size_t>(n)) :
                 "");
              if((s.st_uid != env.trusted_uid()) ||
                 ((destination != "usr/sbin") &&
                  (destination != "/usr/sbin")))
                {
                  helper_available = false;
                }
              else
                {
                  int parent = -1;
                  if(parent_directory(env,
                                      "/usr/sbin/mount.mergerfs",
                                      false,
                                      false,
                                      nullptr,
                                      &parent,
                                      error))
                    helper_available = false;
                  if(parent >= 0)
                    ::close(parent);
                }
            }
          else if(!S_ISDIR(s.st_mode))
            {
              helper_available = false;
            }

          if(helper_available)
            {
              const std::string effective =
                ((S_ISLNK(s.st_mode)) ?
                 "/usr/sbin/mount.mergerfs" :
                 "/sbin/mount.mergerfs");
              add(effective,"/sbin/mount.mergerfs",6);
              Destination &helper = items[count - 1];
              int parent = -1;
              rc = parent_directory(env,effective,false,false,nullptr,&parent,error);
              if(rc)
                {
                  --count;
                  helper_available = false;
                }
              else
                {
                  helper.parent = parent;
                  rc            = destination_check(env,&helper,false,error);
                  ::close(helper.parent);
                  helper.parent = -1;
                  if(rc)
                    {
                      --count;
                      helper_available = false;
                    }
                }
            }

          if(!helper_available)
            {
              warnings.push_back("Preserved /sbin/mount.mergerfs: package-owned, unknown, or unsafe; mount(8) may continue using it. Use /usr/local/sbin/mount.mergerfs explicitly.");
              if(error)
                error->clear();
            }

          add(STATIC_BINARY,STATIC_BINARY,0);
        }

      std::vector<std::string> made;
      // Validate all destinations before even creating missing /usr/local directories.
      for(size_t i = 0; i < count; ++i)
        {
          Destination &item = items[i];
          rc = parent_directory(env,item.path,false,target == "static",&made,&item.parent,error);
          if(!rc)
            rc = destination_check(env,&item,false,error);
          if(item.parent >= 0)
            {
              ::close(item.parent);
              item.parent = -1;
            }

          if(rc)
            return rc;
        }

      for(size_t i = 0; i < count; ++i)
        {
          Destination &item = items[i];
          rc = parent_directory(env,item.path,true,false,&made,&item.parent,error);
          if(!rc)
            rc = destination_check(env,&item,true,error);
          if(!rc)
            rc = stage(env,archive,&item,error);
          if(rc)
            {
              clean_install(env,items,count,made,false,error);
              return rc;
            }
        }

      for(size_t i = 0; i < count; ++i)
        {
          Destination &item = items[i];
          rc = destination_check(env,&item,true,error);
          if((manual_linked) && (item.member == "usr/local/share/man/man1/mergerfs.1"))
            {
              std::string current_manual;
              struct stat current_alias{};
              bool linked = false;
              rc = manual_destination(env,&current_manual,&current_alias,&linked,error);
              if((rc) ||
                 (!linked) ||
                 (current_manual != item.path) ||
                 (!same_file(manual_alias,current_alias)))
                {
                  if(!rc)
                    {
                      rc = UpdateIO::fail(error,
                                          EAGAIN,
                                          "/usr/local/share/man symlink changed during installation");
                    }
                  break;
                }
            }

          if(rc)
            break;
          if(item.exists)
            {
              item.backup = unique_name(item.parent,"backup");
              if(item.backup.empty())
                {
                  rc = UpdateIO::fail(error,EEXIST,"cannot select backup name");
                  break;
                }

              if(::linkat(item.parent,item.name.c_str(),item.parent,item.backup.c_str(),0) < 0)
                {
                  const int saved = errno;
                  item.backup.clear();
                  rc = UpdateIO::fail(error,saved,"cannot back up existing destination");
                  break;
                }
            }

          if(item.exists)
            {
              struct stat linked{};
              Ownership owner =
                ((item.spec->mode[0] == 'l') ?
                 query_owner(env,item.path) :
                 ownership(env,item.path));
              if(item.lexical != item.path)
                {
                  Ownership lexical = query_owner(env,item.lexical);
                  if(lexical.kind != Ownership::UNOWNED)
                    owner = lexical;
                }

              if((::fstatat(item.parent,item.name.c_str(),&linked,AT_SYMLINK_NOFOLLOW) < 0) ||
                 (linked.st_dev != item.original.st_dev) ||
                 (linked.st_ino != item.original.st_ino) ||
                 (linked.st_nlink != item.original.st_nlink + 1) ||
                 (linked.st_mode != item.original.st_mode) ||
                 (linked.st_uid != item.original.st_uid) ||
                 (linked.st_gid != item.original.st_gid) ||
                 (linked.st_size != item.original.st_size) ||
                 (linked.st_mtim.tv_sec != item.original.st_mtim.tv_sec) ||
                 (linked.st_mtim.tv_nsec != item.original.st_mtim.tv_nsec) ||
                 (owner.kind != Ownership::UNOWNED))
                {
                  rc = UpdateIO::fail(error,
                                      EAGAIN,
                                      "destination changed after backup: " + item.lexical);
                  break;
                }
            }

          if(item.exists)
            {
              rc = ::renameat(item.parent,item.temporary.c_str(),item.parent,item.name.c_str());
            }
          else
            {
              rc = static_cast<int>(::syscall(SYS_renameat2,
                                              item.parent,
                                              item.temporary.c_str(),
                                              item.parent,
                                              item.name.c_str(),
                                              RENAME_NOREPLACE));
            }

          if(rc < 0)
            {
              rc = UpdateIO::fail(error,errno,"destination changed during commit");
              break;
            }

          item.committed = true;
          item.temporary.clear();
          if(::fsync(item.parent) < 0)
            {
              rc = UpdateIO::fail(error,errno,"destination directory sync failed");
              break;
            }

          rc = 0;
        }

      if(rc)
        {
          clean_install(env,items,count,made,true,error);
          return rc;
        }

      if(!clean_install(env,items,count,{},false,error))
        warnings.push_back("Installation committed, but backup cleanup is incomplete; inspect destination directories.");
      result->path = ((target == "existing") ? current.path : STATIC_BINARY);
      warnings.push_back("Existing mergerfs mounts keep the old binary until remounted; mergerfs-webui was not restarted.");
      if((target == "static") && (current.path != STATIC_BINARY) && (!current.path.empty()))
        warnings.push_back("Services using an absolute mergerfs path may still use the previous binary.");
      result->warnings = std::move(warnings);
      return 0;
    }
  }


  int
  status(Status      *result_,
         std::string *error_)
  {
    if(error_)
      error_->clear();
    return local_status(production(),result_,error_);
  }


  int
  latest(Release     *release,
         std::string *error)
  {
    if(error)
      error->clear();
    if(!release)
      return UpdateIO::fail(error,EINVAL,"missing release destination");
    if(!architecture())
      return UpdateIO::fail(error,ENOTSUP,"no static release for this architecture");
    std::string response;
    int rc = UpdateIO::curl(API_URL,MAX_METADATA_SIZE,-1,&response,error);
    if(rc)
      return rc;
    try
      {
        const auto body = nlohmann::json::parse(response);
        const std::string tag = body.at("tag_name").get<std::string>();
        if((!UpdateIO::safe_tag(tag)) ||
           (body.at("draft").get<bool>()) ||
           (body.at("prerelease").get<bool>()))
          {
            return UpdateIO::fail(error,
                                  ENOTSUP,
                                  "latest mergerfs release is not a supported stable tag");
          }

        Release selected;
        selected.tag   = tag;
        selected.asset = "mergerfs-" + tag + "-static-linux_" + architecture() + ".tar.gz";
        const std::string expected =
          "https://github.com/trapexit/mergerfs/releases/download/" + tag + "/" + selected.asset;
        unsigned matches = 0;
        for(const auto &asset : body.at("assets"))
          {
            if(asset.at("name").get<std::string>() != selected.asset)
              continue;
            ++matches;
            if((asset.at("state").get<std::string>() != "uploaded") ||
               (asset.at("browser_download_url").get<std::string>() != expected))
              {
                return UpdateIO::fail(error,
                                      ENOTSUP,
                                      "static release asset has an unexpected URL or state");
              }

            const std::string digest = asset.at("digest").get<std::string>();
            if((digest.compare(0,SHA256_PREFIX_LENGTH,SHA256_PREFIX) != 0) ||
               (!UpdateIO::hex_digest(std::string_view(digest).substr(SHA256_PREFIX_LENGTH))))
              {
                return UpdateIO::fail(error,
                                      ENOTSUP,
                                      "static release asset lacks a verified SHA-256 digest");
              }

            selected.digest = digest.substr(SHA256_PREFIX_LENGTH);
            selected.size   = asset.at("size").get<uint64_t>();
            if((!selected.size) || (selected.size > MAX_ARCHIVE))
              return UpdateIO::fail(error,ENOTSUP,"static release asset exceeds 64 MiB limit");
          }

        if(matches != 1)
          {
            return UpdateIO::fail(error,
                                  ENOTSUP,
                                  "latest release has no unique static asset for this architecture");
          }

        *release = std::move(selected);
        return 0;
      }
    catch(const nlohmann::json::exception &)
      {
        return UpdateIO::fail(error,ENOTSUP,"invalid static release metadata");
      }
  }


  int
  install(const std::string &tag,
          const std::string &digest,
          const std::string &target,
          Result            *result,
          std::string       *error)
  {
    if(error)
      error->clear();
    if((!result) ||
       (!UpdateIO::safe_tag(tag)) ||
       (!UpdateIO::hex_digest(digest)) ||
       ((target != "existing") &&
        (target != "static")))
      return UpdateIO::fail(error,EINVAL,"invalid selected mergerfs release");
    if((target == "static") && (::geteuid() != 0))
      return UpdateIO::fail(error,EACCES,"static installation requires root");
    std::lock_guard<std::mutex> lock(install_mutex);
    Status current;
    int    rc = status(&current,error);
    if(rc)
      return rc;
    if((target == "existing") && (!current.in_place_allowed))
      return UpdateIO::fail(error,EAGAIN,"selected mergerfs binary is not safely unmanaged");
    if((target == "static") && (!current.static_install_allowed))
      return UpdateIO::fail(error,EAGAIN,"local static binary cannot be replaced safely");
    Release selected;
    rc = latest(&selected,error);
    if(rc)
      return rc;
    if((selected.tag != tag) || (selected.digest != digest))
      return UpdateIO::fail(error,EAGAIN,"mergerfs release changed; check again");
    char filename[] = "/tmp/.mergerfs-download-XXXXXX";
    UpdateIO::FD download(::mkstemp(filename));
    if(download.value < 0)
      return UpdateIO::fail(error,errno,"cannot create static download file");
    const std::string url = "https://github.com/trapexit/mergerfs/releases/download/" +
                            selected.tag + "/" + selected.asset;
    rc = UpdateIO::curl(url,MAX_ARCHIVE,download.value,nullptr,error);
    if(!rc)
      rc = archive_install(production(),selected,download.value,target,result,error);
    ::unlink(filename);
    return rc;
  }


#ifdef MERGERFS_UPDATE_TEST
  namespace
  {
    int
    fixture_environment(const Fixture &fixture_,
                        Environment   *env_,
                        std::string   *error_)
    {
      if((fixture_.root.empty()) ||
         (fixture_.root[0] != '/') ||
         (fixture_.root == "/") ||
         (!fixture_.lookup))
        return UpdateIO::fail(error_,EINVAL,"unsafe fixture root or ownership lookup");
      struct stat s{};
      std::array<char,PATH_MAX> resolved{};
      if((::lstat(fixture_.root.c_str(),&s) < 0) ||
         (!S_ISDIR(s.st_mode)) ||
         (!::realpath(fixture_.root.c_str(),resolved.data())) ||
         (fixture_.root != resolved.data()))
        return UpdateIO::fail(error_,EINVAL,"fixture root must be a real absolute directory");
      env_->root = fixture_.root;
      env_->path_env =
        ((fixture_.path_env.empty()) ? "/usr/local/bin:/usr/bin:/bin" : fixture_.path_env);
      env_->lookup  = fixture_.lookup;
      env_->context = fixture_.context;
      env_->fixture = true;
      return 0;
    }
  }


  int
  test_status(const Fixture &fixture_,
              Status        *result_,
              std::string   *error_)
  {
    Environment env;
    int rc = fixture_environment(fixture_,&env,error_);
    return rc ? rc : local_status(env,result_,error_);
  }


  int
  test_install_archive(const Fixture     &fixture_,
                       const Release     &release_,
                       const std::string &archive_,
                       const std::string &target_,
                       Result            *result_,
                       std::string       *error_)
  {
    if(error_)
      error_->clear();
    if((!UpdateIO::safe_tag(release_.tag)) ||
       (!UpdateIO::hex_digest(release_.digest)) ||
       ((target_ != "existing") &&
        (target_ != "static")))
      return UpdateIO::fail(error_,EINVAL,"invalid fixture release selection");
    Environment env;
    int rc = fixture_environment(fixture_,&env,error_);
    if(rc)
      return rc;
    UpdateIO::FD file(::open(archive_.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC));
    if(file.value < 0)
      return UpdateIO::fail(error_,errno,"cannot open fixture archive");
    std::lock_guard<std::mutex> lock(install_mutex);
    return archive_install(env,release_,file.value,target_,result_,error_);
  }
#endif
}
