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

#include "service_install.hpp"
#include "update_io.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <utility>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace ServiceInstall
{
  namespace
  {
    constexpr size_t MAX_ARGUMENT_LENGTH = 2048;
    constexpr int MAX_SERVICE_PORT    = 65535;
    constexpr size_t COPY_BUFFER_SIZE = 16384;
    constexpr size_t UNIT_TEXT_RESERVE_OVERHEAD = 256;
    constexpr size_t MAX_SECRET_LENGTH  = 128;
    constexpr off_t MAX_EXECUTABLE_SIZE = 128 * 1024 * 1024;
    constexpr const char *MANAGED_PASSWORD_NAME = "password";
    constexpr const char *INVALID_MANAGED_DIRECTORY_PATH = "invalid managed directory path";
    constexpr mode_t UNTRUSTED_WRITE_BITS  = 022;
    constexpr mode_t NON_OWNER_ACCESS_BITS = 077;
    constexpr mode_t EXECUTE_BITS = 0111;
    constexpr mode_t SETID_BITS   = 06000;
    constexpr mode_t PRIVATE_MODE = 0600;
    constexpr mode_t PASSWORD_DIRECTORY_MODE = 0700;
    constexpr mode_t EXECUTABLE_MODE   = 0755;
    constexpr mode_t SERVICE_UNIT_MODE = 0644;


    bool
    safe_argument(const std::string &value_,
                  bool               path_)
    {
      if((value_.empty()) ||
         (value_.size() > MAX_ARGUMENT_LENGTH) ||
         ((path_) &&
          (value_.front() != '/')))
        return false;
      for(unsigned char c : value_)
        {
          if(!(((c >= 'a') &&
                (c <= 'z')) ||
               ((c >= 'A') &&
                (c <= 'Z')) ||
               ((c >= '0') &&
                (c <= '9')) ||
               (c == '_') ||
               (c == '-') ||
               (c == '.') ||
               ((path_) &&
                ((c == '/') ||
                 (c == '+'))) ||
               ((!path_) &&
                (c == ':'))))
            return false;
        }

      if(path_)
        {
          size_t start = 1;
          while(start < value_.size())
            {
              size_t end;
              std::string_view component;
              end = value_.find('/',start);
              if(end == std::string::npos)
                end = value_.size();
              component = std::string_view(value_.data() + start,end - start);
              if((component.empty()) || (component == ".") || (component == ".."))
                return false;
              start = end + 1;
            }

          if(value_.back() == '/')
            return false;
        }

      return true;
    }


    int
    check_spec(const Spec  &spec_,
               std::string *error_)
    {
      if((!safe_argument(spec_.executable,true)) ||
         ((!spec_.password_file.empty()) &&
          (!safe_argument(spec_.password_file,true))) ||
         (!safe_argument(spec_.host,false)) ||
         (spec_.port < 1) ||
         (spec_.port > MAX_SERVICE_PORT))
        {
          return UpdateIO::fail(error_,
                                EINVAL,
                                "service arguments require safe absolute paths, host and port");
        }

      return 0;
    }


    std::string
    unit_text(const Spec &spec_)
    {
      const std::string port = std::to_string(spec_.port);
      std::string text;
      text.reserve(UNIT_TEXT_RESERVE_OVERHEAD + spec_.executable.size() + spec_.host.size() +
                   port.size() + spec_.password_file.size());
      text +=
      "[Unit]\nDescription=mergerfs-webui\nWants=network-online.target\nAfter=network-online.target\n\n"
      "[Service]\nType=exec\nExecStart=";
      text += spec_.executable;
      text += " --host ";
      text += spec_.host;
      text += " --port ";
      text += port;
      if(!spec_.password_file.empty())
        {
          text += " --password-file ";
          text += spec_.password_file;
        }

      text += "\nRestart=on-failure\nRestartSec=2s\n\n"
              "[Install]\nWantedBy=multi-user.target\n";
      return text;
    }


    bool
    parse_unit(const std::string &text_,
               Spec              *spec_)
    {
      constexpr std::string_view marker = "\nExecStart=";
      const size_t start = text_.find(marker);
      if(start == std::string::npos)
        return false;
      const size_t line = start + marker.size();
      const size_t end = text_.find('\n',line);
      if(end == std::string::npos)
        return false;
      const std::string_view command(text_.data() + line,end - line);
      const size_t host = command.find(" --host ");
      const size_t port = command.find(" --port ");
      if((host == std::string_view::npos) ||
         (port == std::string_view::npos) ||
         (port <= host + 8))
        return false;
      const size_t password = command.find(" --password-file ",port + 8);
      const size_t port_end = password == std::string_view::npos ? command.size() : password;
      Spec parsed;
      parsed.executable.assign(command.substr(0,host));
      parsed.host.assign(command.substr(host + 8,port - host - 8));
      const auto converted = std::from_chars(command.data() + port + 8,
                                              command.data() + port_end,
                                              parsed.port);
      if((converted.ec != std::errc()) ||
         (converted.ptr != command.data() + port_end))
        return false;
      if(password != std::string_view::npos)
        parsed.password_file.assign(command.substr(password + 17));
      std::string error;
      if((check_spec(parsed,&error) != 0) || (unit_text(parsed) != text_))
        return false;
      *spec_ = std::move(parsed);
      return true;
    }


    int
    open_unit_directory(const std::string &directory_,
                        UpdateIO::FD      *fd_,
                        std::string       *error_)
    {
      struct stat st;
      fd_->value = ::open(directory_.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
      if(fd_->value < 0)
        return UpdateIO::fail(error_,errno,"cannot open service directory: " + directory_);
      if(::fstat(fd_->value,&st) < 0)
        return UpdateIO::fail(error_,errno,"cannot inspect service directory: " + directory_);
      if((st.st_uid != ::geteuid()) || (st.st_mode & UNTRUSTED_WRITE_BITS))
        {
          return UpdateIO::fail(error_,
                                EACCES,
                                "service directory must be owned by the service installer and not writable by others: " +
                                directory_);
        }

      return 0;
    }


    int
    read_existing(int                dir_,
                  const std::string &expected_,
                  bool              *installed_,
                  std::string       *error_,
                  UpdateIO::FD      *held_ = nullptr,
                  struct stat       *metadata_ = nullptr,
                  Spec              *parsed_ = nullptr)
    {
      struct stat st;
      size_t      offset;
      UpdateIO::FD unit;
      std::string  contents;
      *installed_ = false;
      unit.value  = ::openat(dir_,UNIT_NAME,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
      if(unit.value < 0)
        {
          if(errno == ENOENT)
            return 0;
          if(errno == ELOOP)
            {
              return UpdateIO::fail(error_,
                                    EEXIST,
                                    "a symlink already occupies the mergerfs-webui service unit path");
            }

          return UpdateIO::fail(error_,errno,"cannot open existing mergerfs-webui service unit");
        }

      if(::fstat(unit.value,&st) < 0)
        return UpdateIO::fail(error_,errno,"cannot inspect existing mergerfs-webui service unit");
      if((!S_ISREG(st.st_mode)) ||
         (st.st_uid != ::geteuid()) ||
         (st.st_mode & UNTRUSTED_WRITE_BITS) ||
         (st.st_nlink != 1) ||
         (st.st_size <= 0) ||
         (st.st_size > static_cast<off_t>((MAX_ARGUMENT_LENGTH * 3) + UNIT_TEXT_RESERVE_OVERHEAD)) ||
         ((!parsed_) && (st.st_size != static_cast<off_t>(expected_.size()))))
        {
          return UpdateIO::fail(error_,
                                EEXIST,
                                "existing mergerfs-webui service unit is not the requested unit");
        }

      contents.assign(static_cast<size_t>(st.st_size),'\0');
      offset = 0;
      while(offset < contents.size())
        {
          ssize_t count;
          count = ::read(unit.value,&contents[offset],contents.size() - offset);
          if((count < 0) && (errno == EINTR))
            continue;
          if(count <= 0)
            {
              return UpdateIO::fail(error_,
                                    count < 0 ? errno : EIO,
                                    "cannot read existing mergerfs-webui service unit");
            }

          offset += static_cast<size_t>(count);
        }

      if(parsed_ ? !parse_unit(contents,parsed_) : contents != expected_)
        {
          return UpdateIO::fail(error_,
                                EEXIST,
                                "existing mergerfs-webui service unit differs; refusing to replace it");
        }

      if(held_)
        {
          held_->value = unit.value;
          unit.value   = UpdateIO::FD::invalid_fd;
        }

      if(metadata_)
        *metadata_ = st;
      *installed_ = true;
      return 0;
    }


    int
    regular_file(const std::string &path_,
                 bool               executable_,
                 std::string       *error_)
    {
      UpdateIO::FD file(::open(path_.c_str(),O_RDONLY|O_NONBLOCK|O_CLOEXEC));
      if(file.value < 0)
        return UpdateIO::fail(error_,errno,"cannot open service path: " + path_);
      struct stat st;
      if(::fstat(file.value,&st) < 0)
        return UpdateIO::fail(error_,errno,"cannot inspect service path: " + path_);
      if((!S_ISREG(st.st_mode)) ||
         ((executable_) &&
          ((!(st.st_mode & EXECUTE_BITS)) ||
           (::faccessat(AT_FDCWD,path_.c_str(),X_OK,AT_EACCESS) < 0))))
        {
          return UpdateIO::fail(error_,
                                EACCES,
                                "service path must be a regular readable file and executables must be runnable: " +
                                path_);
        }

      return 0;
    }


    int
    managed_directory(const std::string &path_,
                      mode_t             mode_,
                      bool               create_,
                      UpdateIO::FD      *directory_,
                      std::string       *error_)
    {
      size_t slash;
      int    rc;
      struct stat  st;
      std::string  parent;
      std::string  name;
      UpdateIO::FD parent_fd;
      if(!safe_argument(path_,true))
        return UpdateIO::fail(error_,EINVAL,INVALID_MANAGED_DIRECTORY_PATH);
      slash = path_.rfind('/');
      if((slash == std::string::npos) || (slash + 1 == path_.size()))
        return UpdateIO::fail(error_,EINVAL,INVALID_MANAGED_DIRECTORY_PATH);
      parent = ((slash) ? path_.substr(0,slash) : "/");
      name   = path_.substr(slash + 1);
      rc     = open_unit_directory(parent,&parent_fd,error_);
      if(rc)
        return rc;
      directory_->value =
      ::openat(parent_fd.value,name.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
      if((directory_->value < 0) && (errno == ENOENT) && (create_))
        {
          if((::mkdirat(parent_fd.value,name.c_str(),mode_) < 0) && (errno != EEXIST))
            return UpdateIO::fail(error_,errno,"cannot create managed directory: " + path_);
          directory_->value =
          ::openat(parent_fd.value,name.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
          if((directory_->value >= 0) && (::fsync(parent_fd.value) < 0))
            return UpdateIO::fail(error_,errno,"cannot sync managed parent directory");
        }

      if(directory_->value < 0)
        return UpdateIO::fail(error_,errno,"cannot open managed directory: " + path_);
      if(::fstat(directory_->value,&st) < 0)
        return UpdateIO::fail(error_,errno,"cannot inspect managed directory");
      if((st.st_uid != ::geteuid()) ||
         (st.st_mode & UNTRUSTED_WRITE_BITS) ||
         ((mode_ == PASSWORD_DIRECTORY_MODE) &&
          (st.st_mode & NON_OWNER_ACCESS_BITS)))
        return UpdateIO::fail(error_,EACCES,"managed directory permissions are unsafe: " + path_);
      return 0;
    }


    int
    identical_file(int          source_,
                   int          target_,
                   off_t        size_,
                   bool        *same_,
                   std::string *error_)
    {
      std::array<char,COPY_BUFFER_SIZE> first;
      std::array<char,COPY_BUFFER_SIZE> second;
      *same_ = false;
      for(off_t offset = 0; offset < size_;)
        {
          size_t  length;
          ssize_t a;
          ssize_t b;
          length = std::min(first.size(),static_cast<size_t>(size_ - offset));
          a      = ::pread(source_,first.data(),length,offset);
          if((a < 0) && (errno == EINTR))
            continue;
          b = ::pread(target_,second.data(),length,offset);
          if((b < 0) && (errno == EINTR))
            continue;
          if((a <= 0) || (b <= 0))
            {
              return UpdateIO::fail(error_,
                                    ((a < 0) || (b < 0)) ? errno : EIO,
                                    "cannot compare managed executable");
            }

          if((a != b) || (std::memcmp(first.data(),second.data(),static_cast<size_t>(a)) != 0))
            return 0;
          offset += a;
        }

      *same_ = true;
      return 0;
    }
  }

  namespace
  {
    constexpr size_t RUNNING_EXECUTABLE_PATH_LIMIT = 4096;
    constexpr size_t STAGING_NAME_BUFFER_SIZE      = 64;
    constexpr const char *RUNNING_EXECUTABLE_PROC_PATH = "/proc/self/exe";
    constexpr const char *EXECUTABLE_DESTINATION_CHANGED =
      "managed executable destination changed during staging";
    constexpr const char *PASSWORD_DESTINATION_CHANGED =
      "managed password destination changed during staging";
    constexpr const char *SERVICE_UNIT_CHANGED_BEFORE_REMOVAL =
      "mergerfs-webui service unit changed before removal";
  }


  int
  running_executable(std::string *path_,
                     std::string *error_)
  {
    char    buffer[RUNNING_EXECUTABLE_PATH_LIMIT];
    ssize_t size;
    size = ::readlink(RUNNING_EXECUTABLE_PROC_PATH,buffer,sizeof(buffer));
    if(size < 0)
      return UpdateIO::fail(error_,errno,"cannot locate running executable");
    if(size == static_cast<ssize_t>(sizeof(buffer)))
      return UpdateIO::fail(error_,ENAMETOOLONG,"running executable path exceeds limit");
    path_->assign(buffer,static_cast<size_t>(size));
    return 0;
  }


  int
  runnable_running_executable(std::string *path_,
                              std::string *error_)
  {
    int rc;
    struct stat  current_stat;
    struct stat  running_stat;
    UpdateIO::FD current;
    UpdateIO::FD running;
    rc = running_executable(path_,error_);
    if(rc)
      return rc;
    if(!safe_argument(*path_,true))
      {
        return UpdateIO::fail(error_,
                              EACCES,
                              "running executable has no safe on-disk path; restart it before using it for a service");
      }

    rc = regular_file(*path_,true,error_);
    if(rc)
      return rc;
    current.value = ::open(path_->c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    running.value = ::open(RUNNING_EXECUTABLE_PROC_PATH,O_RDONLY|O_CLOEXEC);
    if((current.value < 0) ||
       (running.value < 0) ||
       (::fstat(current.value,&current_stat) < 0) ||
       (::fstat(running.value,&running_stat) < 0))
      return UpdateIO::fail(error_,errno,"cannot compare running service executable");
    if((current_stat.st_dev != running_stat.st_dev) || (current_stat.st_ino != running_stat.st_ino))
      {
        return UpdateIO::fail(error_,
                              EAGAIN,
                              "running executable no longer matches its on-disk path; restart it before using it for a service");
      }

    return 0;
  }


  int
  stage_executable(const std::string &source_,
                   const std::string &destination_,
                   bool              *created_,
                   std::string       *error_)
  {
    size_t      slash;
    struct stat original;
    struct stat previous;
    struct stat after;
    unsigned long long random;
    char temporary[STAGING_NAME_BUFFER_SIZE];
    std::array<char,COPY_BUFFER_SIZE> buffer;
    off_t offset;
    int   rc;
    bool  replacing;
    std::string  parent;
    std::string  name;
    UpdateIO::FD input;
    UpdateIO::FD dir;
    UpdateIO::FD existing;
    UpdateIO::FD output;
    const auto abort = [&](int code_,const char *message_)
    {
      ::unlinkat(dir.value,temporary,0);
      return UpdateIO::fail(error_,code_,message_);
    };
    *created_ = false;
    if(!safe_argument(destination_,true))
      return UpdateIO::fail(error_,EINVAL,"invalid managed executable path");
    slash  = destination_.rfind('/');
    parent = destination_.substr(0,slash);
    name   = destination_.substr(slash + 1);
    input.value = ::open(source_.c_str(),
                         O_RDONLY | O_CLOEXEC |
                         (source_ == RUNNING_EXECUTABLE_PROC_PATH ? 0 : O_NOFOLLOW));
    if(input.value < 0)
      return UpdateIO::fail(error_,errno,"cannot open running executable for service");
    if(::fstat(input.value,&original) < 0)
      return UpdateIO::fail(error_,errno,"cannot inspect running executable");
    if((!S_ISREG(original.st_mode)) ||
       (!(original.st_mode & EXECUTE_BITS)) ||
       (original.st_size <= 0) ||
       (original.st_size > MAX_EXECUTABLE_SIZE))
      return UpdateIO::fail(error_,EINVAL,"running executable is not a bounded regular executable");
    rc = managed_directory(parent,EXECUTABLE_MODE,true,&dir,error_);
    if(rc)
      return rc;
    existing.value = ::openat(dir.value,name.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    replacing      = existing.value >= 0;
    if(replacing)
      {
        if(::fstat(existing.value,&previous) < 0)
          return UpdateIO::fail(error_,errno,"cannot inspect managed executable");
        if((!S_ISREG(previous.st_mode)) ||
           (previous.st_uid != ::geteuid()) ||
           (previous.st_mode & (UNTRUSTED_WRITE_BITS | SETID_BITS)) ||
           (!(previous.st_mode & EXECUTE_BITS)) ||
           (previous.st_nlink != 1))
          return UpdateIO::fail(error_,EEXIST,"an unsafe managed executable already exists");
        if(previous.st_size == original.st_size)
          {
            bool same = false;
            rc = identical_file(input.value,existing.value,original.st_size,&same,error_);
            if((rc) || (same))
              return rc;
          }
      }
    else
      {
        if(errno != ENOENT)
          {
            return UpdateIO::fail(error_,
                                  errno == ELOOP ? EEXIST : errno,
                                  "managed executable destination is occupied or unsafe");
          }
      }

    if(::getrandom(&random,sizeof(random),0) != static_cast<ssize_t>(sizeof(random)))
      return UpdateIO::fail(error_,EIO,"cannot reserve random executable staging name");
    std::snprintf(temporary,sizeof(temporary),".mergerfs-webui-%016llx",random);
    output.value =
        ::openat(dir.value,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,PRIVATE_MODE);
    if(output.value < 0)
      return UpdateIO::fail(error_,errno,"cannot stage managed executable");
    offset = 0;
    while(offset < original.st_size)
      {
        size_t  size;
        ssize_t count;
        size_t  written;
        size  = std::min(buffer.size(),static_cast<size_t>(original.st_size - offset));
        count = ::pread(input.value,buffer.data(),size,offset);
        if((count < 0) && (errno == EINTR))
          continue;
        if(count <= 0)
          return abort(count < 0 ? errno : EIO,"cannot read running executable");
        written = 0;
        while(written < static_cast<size_t>(count))
          {
            ssize_t n;
            n = ::write(output.value,buffer.data() + written,static_cast<size_t>(count) - written);
            if((n < 0) && (errno == EINTR))
              continue;
            if(n <= 0)
              return abort(n < 0 ? errno : EIO,"cannot write managed executable");
            written += static_cast<size_t>(n);
          }

        offset += count;
      }

    if((::fstat(input.value,&after) < 0) ||
       (after.st_dev != original.st_dev) ||
       (after.st_ino != original.st_ino) ||
       (after.st_size != original.st_size) ||
       (after.st_mtim.tv_sec != original.st_mtim.tv_sec) ||
       (after.st_mtim.tv_nsec != original.st_mtim.tv_nsec) ||
       (after.st_ctim.tv_sec != original.st_ctim.tv_sec) ||
       (after.st_ctim.tv_nsec != original.st_ctim.tv_nsec))
      return abort(EAGAIN,"running executable changed during staging");
    if((::fchmod(output.value,EXECUTABLE_MODE) < 0) || (::fsync(output.value) < 0))
      return abort(errno,"cannot sync managed executable");
    if(replacing)
      {
        struct stat current;
        if((::fstatat(dir.value,name.c_str(),&current,AT_SYMLINK_NOFOLLOW) < 0) ||
           (current.st_dev != previous.st_dev) ||
           (current.st_ino != previous.st_ino) ||
           (current.st_size != previous.st_size) ||
           (current.st_mode != previous.st_mode) ||
           (current.st_uid != previous.st_uid) ||
           (current.st_nlink != previous.st_nlink) ||
           (current.st_mtim.tv_sec != previous.st_mtim.tv_sec) ||
           (current.st_mtim.tv_nsec != previous.st_mtim.tv_nsec) ||
           (current.st_ctim.tv_sec != previous.st_ctim.tv_sec) ||
           (current.st_ctim.tv_nsec != previous.st_ctim.tv_nsec))
          return abort(EAGAIN,EXECUTABLE_DESTINATION_CHANGED);
        if(::renameat(dir.value,temporary,dir.value,name.c_str()) < 0)
          return abort(errno,"cannot replace managed executable");
      }
    else
      {
        if(::syscall(SYS_renameat2,dir.value,temporary,dir.value,name.c_str(),RENAME_NOREPLACE) < 0)
          {
            return abort(errno == EEXIST ? EEXIST : errno,EXECUTABLE_DESTINATION_CHANGED);
          }
      }

    if(::fsync(dir.value) < 0)
      return UpdateIO::fail(error_,errno,"managed executable installed but directory sync failed");
    *created_ = true;
    return 0;
  }


  int
  create_password(const std::string &directory_,
                  const std::string &secret_,
                  bool              *created_,
                  std::string       *error_)
  {
    struct stat previous;
    unsigned long long random;
    char temporary[STAGING_NAME_BUFFER_SIZE];
    std::array<char,MAX_SECRET_LENGTH + 1> text;
    std::array<char,MAX_SECRET_LENGTH + 1> current_password;
    size_t offset;
    int    rc;
    bool   replacing;
    UpdateIO::FD dir;
    UpdateIO::FD existing;
    UpdateIO::FD file;
    const auto printable = [](unsigned char c_)
    {
      return ((c_ >= 33) && (c_ <= 126));
    };
    const auto abort = [&](int code_,const char *message_)
    {
      ::unlinkat(dir.value,temporary,0);
      return UpdateIO::fail(error_,code_,message_);
    };
    *created_ = false;
    if((secret_.empty()) ||
       (secret_.size() > MAX_SECRET_LENGTH) ||
       (!std::all_of(secret_.begin(),secret_.end(),printable)))
      {
        return UpdateIO::fail(error_,
                              EINVAL,
                              "managed password must be printable without spaces or controls");
      }

    rc = managed_directory(directory_,PASSWORD_DIRECTORY_MODE,true,&dir,error_);
    if(rc)
      return rc;
    existing.value =
        ::openat(dir.value,MANAGED_PASSWORD_NAME,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    replacing = existing.value >= 0;
    if(replacing)
      {
        if(::fstat(existing.value,&previous) < 0)
          return UpdateIO::fail(error_,errno,"cannot inspect managed password");
        if((!S_ISREG(previous.st_mode)) ||
           (previous.st_uid != ::geteuid()) ||
           (previous.st_mode & NON_OWNER_ACCESS_BITS) ||
           (previous.st_nlink != 1))
          return UpdateIO::fail(error_,EEXIST,"an unsafe managed password already exists");
        if(previous.st_size == static_cast<off_t>(secret_.size() + 1))
          {
            ssize_t length;
            length = ::pread(existing.value,current_password.data(),secret_.size() + 1,0);
            if(length < 0)
              return UpdateIO::fail(error_,errno,"cannot inspect managed password contents");
            if((length == static_cast<ssize_t>(secret_.size() + 1)) &&
               (std::memcmp(current_password.data(),secret_.data(),secret_.size()) == 0) &&
               (current_password[secret_.size()] == '\n'))
              return 0;
          }
      }
    else
      {
        if(errno != ENOENT)
          {
            return UpdateIO::fail(error_,
                                  errno == ELOOP ? EEXIST : errno,
                                  "managed password destination is occupied or unsafe");
          }
      }

    if(::getrandom(&random,sizeof(random),0) != static_cast<ssize_t>(sizeof(random)))
      return UpdateIO::fail(error_,EIO,"cannot reserve random password staging name");
    std::snprintf(temporary,sizeof(temporary),".password-%016llx",random);
    file.value = ::openat(dir.value,
                          temporary,
                          O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,
                          PRIVATE_MODE);
    if(file.value < 0)
      return UpdateIO::fail(error_,errno,"cannot stage managed password");
    std::memcpy(text.data(),secret_.data(),secret_.size());
    text[secret_.size()] = '\n';
    offset               = 0;
    while(offset < secret_.size() + 1)
      {
        ssize_t n;
        n = ::write(file.value,text.data() + offset,secret_.size() + 1 - offset);
        if((n < 0) && (errno == EINTR))
          continue;
        if(n <= 0)
          return abort(n < 0 ? errno : EIO,"cannot write managed password");
        offset += static_cast<size_t>(n);
      }

    if(::fsync(file.value) < 0)
      return abort(errno,"cannot sync managed password");
    if(replacing)
      {
        struct stat current;
        if((::fstatat(dir.value,MANAGED_PASSWORD_NAME,&current,AT_SYMLINK_NOFOLLOW) < 0) ||
           (current.st_dev != previous.st_dev) ||
           (current.st_ino != previous.st_ino) ||
           (current.st_size != previous.st_size) ||
           (current.st_mode != previous.st_mode) ||
           (current.st_uid != previous.st_uid) ||
           (current.st_nlink != previous.st_nlink) ||
           (current.st_mtim.tv_sec != previous.st_mtim.tv_sec) ||
           (current.st_mtim.tv_nsec != previous.st_mtim.tv_nsec) ||
           (current.st_ctim.tv_sec != previous.st_ctim.tv_sec) ||
           (current.st_ctim.tv_nsec != previous.st_ctim.tv_nsec))
          return abort(EAGAIN,PASSWORD_DESTINATION_CHANGED);
        if(::renameat(dir.value,temporary,dir.value,MANAGED_PASSWORD_NAME) < 0)
          return abort(errno,"cannot replace managed password");
      }
    else
      {
        if(::syscall(SYS_renameat2,
                     dir.value,
                     temporary,
                     dir.value,
                     MANAGED_PASSWORD_NAME,
                     RENAME_NOREPLACE) < 0)
          {
            return abort(errno == EEXIST ? EEXIST : errno,PASSWORD_DESTINATION_CHANGED);
          }
      }

    if(::fsync(dir.value) < 0)
      return UpdateIO::fail(error_,errno,"managed password installed but directory sync failed");
    *created_ = true;
    return 0;
  }


  int
  replace_password(const std::string &directory_,
                   const std::string &secret_,
                   std::string       *error_)
  {
    struct stat previous;
    unsigned long long random;
    char temporary[STAGING_NAME_BUFFER_SIZE];
    std::array<char,MAX_SECRET_LENGTH + 1> text;
    size_t offset;
    int rc;
    UpdateIO::FD dir;
    UpdateIO::FD existing;
    UpdateIO::FD file;
    const auto printable = [](unsigned char c_)
    {
      return ((c_ >= 33) && (c_ <= 126));
    };
    const auto abort = [&](int code_,const char *message_)
    {
      ::unlinkat(dir.value,temporary,0);
      return UpdateIO::fail(error_,code_,message_);
    };
    if((secret_.empty()) ||
       (secret_.size() > MAX_SECRET_LENGTH) ||
       (!std::all_of(secret_.begin(),secret_.end(),printable)))
      {
        return UpdateIO::fail(error_,
                              EINVAL,
                              "managed password must be printable without spaces or controls");
      }

    rc = managed_directory(directory_,PASSWORD_DIRECTORY_MODE,true,&dir,error_);
    if(rc)
      return rc;

    existing.value =
        ::openat(dir.value,MANAGED_PASSWORD_NAME,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(existing.value < 0)
      {
        return UpdateIO::fail(error_,
                              errno == ENOENT ? ENOENT :
                                errno == ELOOP ? EEXIST : errno,
                              "no managed password exists to replace");
      }
    if(::fstat(existing.value,&previous) < 0)
      return UpdateIO::fail(error_,errno,"cannot inspect managed password");
    if((!S_ISREG(previous.st_mode)) ||
       (previous.st_uid != ::geteuid()) ||
       (previous.st_mode & NON_OWNER_ACCESS_BITS) ||
       (previous.st_nlink != 1))
      return UpdateIO::fail(error_,EEXIST,"an unsafe managed password already exists");

    if(::getrandom(&random,sizeof(random),0) != static_cast<ssize_t>(sizeof(random)))
      return UpdateIO::fail(error_,EIO,"cannot reserve random password staging name");
    std::snprintf(temporary,sizeof(temporary),".password-%016llx",random);
    file.value = ::openat(dir.value,
                          temporary,
                          O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,
                          PRIVATE_MODE);
    if(file.value < 0)
      return UpdateIO::fail(error_,errno,"cannot stage managed password");
    std::memcpy(text.data(),secret_.data(),secret_.size());
    text[secret_.size()] = '\n';
    offset               = 0;
    while(offset < secret_.size() + 1)
      {
        ssize_t n;
        n = ::write(file.value,text.data() + offset,secret_.size() + 1 - offset);
        if((n < 0) && (errno == EINTR))
          continue;
        if(n <= 0)
          return abort(n < 0 ? errno : EIO,"cannot write managed password");
        offset += static_cast<size_t>(n);
      }

    if(::fsync(file.value) < 0)
      return abort(errno,"cannot sync managed password");
    struct stat current;
    if((::fstatat(dir.value,MANAGED_PASSWORD_NAME,&current,AT_SYMLINK_NOFOLLOW) < 0) ||
       (current.st_dev != previous.st_dev) ||
       (current.st_ino != previous.st_ino) ||
       (current.st_mode != previous.st_mode) ||
       (current.st_uid != previous.st_uid) ||
       (current.st_nlink != previous.st_nlink) ||
       (current.st_size != previous.st_size) ||
       (current.st_mtim.tv_sec != previous.st_mtim.tv_sec) ||
       (current.st_mtim.tv_nsec != previous.st_mtim.tv_nsec) ||
       (current.st_ctim.tv_sec != previous.st_ctim.tv_sec) ||
       (current.st_ctim.tv_nsec != previous.st_ctim.tv_nsec))
      return abort(EAGAIN,PASSWORD_DESTINATION_CHANGED);
    if(::renameat(dir.value,temporary,dir.value,MANAGED_PASSWORD_NAME) < 0)
      return abort(errno,"cannot replace managed password");

    if(::fsync(dir.value) < 0)
      return UpdateIO::fail(error_,errno,"managed password replaced but directory sync failed");
    return 0;
  }


  int
  validate_arguments(const Spec &spec_,
                     std::string *error_)
  {
    return check_spec(spec_,error_);
  }


  int
  validate(const Spec  &spec_,
           std::string *error_)
  {
    int rc;
    if(::geteuid() != 0)
      {
        return UpdateIO::fail(error_,
                              EACCES,
                              "installing a system service requires running mergerfs-webui as root");
      }

    rc = check_spec(spec_,error_);
    if(rc)
      return rc;
    rc = regular_file(spec_.executable,true,error_);
    if(rc)
      return rc;
    return spec_.password_file.empty() ? 0 : regular_file(spec_.password_file,false,error_);
  }


  int
  inspect(const std::string &directory_,
          Spec              *spec_,
          bool              *installed_,
          std::string       *error_)
  {
    UpdateIO::FD dir;
    *installed_ = false;
    const int rc = open_unit_directory(directory_,&dir,error_);
    if(rc)
      return rc;
    return read_existing(dir.value,"",installed_,error_,nullptr,nullptr,spec_);
  }


  int
  existing(const Spec        &spec_,
           const std::string &directory_,
           bool              *installed_,
           std::string       *error_)
  {
    int rc;
    UpdateIO::FD dir;
    rc = check_spec(spec_,error_);
    if(rc)
      return rc;
    rc = open_unit_directory(directory_,&dir,error_);
    if(rc)
      return rc;
    return read_existing(dir.value,unit_text(spec_),installed_,error_);
  }


  int
  write_unit(const Spec        &spec_,
             const std::string &directory_,
             bool              *created_,
             std::string       *error_)
  {
    int    rc;
    int    code;
    size_t offset;
    bool   installed;
    UpdateIO::FD dir;
    std::string  text;
    UpdateIO::FD unit;
    *created_ = false;
    rc        = check_spec(spec_,error_);
    if(rc)
      return rc;
    rc = open_unit_directory(directory_,&dir,error_);
    if(rc)
      return rc;
    text      = unit_text(spec_);
    installed = false;
    rc        = read_existing(dir.value,text,&installed,error_);
    if((rc) || (installed))
      return rc;

    unit.value = ::openat(dir.value,
                          UNIT_NAME,
                          O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,
                          PRIVATE_MODE);
    if(unit.value < 0)
      return UpdateIO::fail(error_,errno,"cannot create mergerfs-webui service unit");
    code   = 0;
    offset = 0;
    while(offset < text.size())
      {
        ssize_t count;
        count = ::write(unit.value,text.data() + offset,text.size() - offset);
        if((count < 0) && (errno == EINTR))
          continue;
        if(count <= 0)
          {
            code = ((count < 0) ? errno : EIO);
            break;
          }

        offset += static_cast<size_t>(count);
      }

    if((!code) && (::fchmod(unit.value,SERVICE_UNIT_MODE) < 0))
      code = errno;
    if((!code) && (::fsync(unit.value) < 0))
      code = errno;
    if((!code) && (::fsync(dir.value) < 0))
      code = errno;
    if(code)
      {
        struct stat written;
        struct stat current;
        if((::fstat(unit.value,&written) == 0) &&
           (::fstatat(dir.value,UNIT_NAME,&current,AT_SYMLINK_NOFOLLOW) == 0) &&
           (written.st_dev == current.st_dev) &&
           (written.st_ino == current.st_ino) &&
           (current.st_nlink == 1))
          ::unlinkat(dir.value,UNIT_NAME,0);
        return UpdateIO::fail(error_,code,"cannot write mergerfs-webui service unit");
      }

    *created_ = true;
    return 0;
  }


  int
  remove_unit(const Spec        &spec_,
              const std::string &directory_,
              std::string       *error_)
  {
    int rc;
    struct stat original;
    struct stat current;
    bool installed;
    UpdateIO::FD dir;
    UpdateIO::FD unit;
    rc = check_spec(spec_,error_);
    if(rc)
      return rc;
    rc = open_unit_directory(directory_,&dir,error_);
    if(rc)
      return rc;
    installed = false;
    rc        = read_existing(dir.value,unit_text(spec_),&installed,error_,&unit,&original);
    if(rc)
      return rc;
    if(!installed)
      return UpdateIO::fail(error_,ENOENT,"mergerfs-webui service unit is not installed");

    if(::fstatat(dir.value,UNIT_NAME,&current,AT_SYMLINK_NOFOLLOW) < 0)
      {
        return UpdateIO::fail(error_,
                              errno == ENOENT ? EAGAIN : errno,
                              SERVICE_UNIT_CHANGED_BEFORE_REMOVAL);
      }

    if((current.st_dev != original.st_dev) || (current.st_ino != original.st_ino))
      return UpdateIO::fail(error_,EAGAIN,SERVICE_UNIT_CHANGED_BEFORE_REMOVAL);
    if((!S_ISREG(current.st_mode)) ||
       (current.st_uid != original.st_uid) ||
       (current.st_nlink != 1) ||
       (current.st_mode & UNTRUSTED_WRITE_BITS) ||
       (current.st_size != original.st_size) ||
       (current.st_mtim.tv_sec != original.st_mtim.tv_sec) ||
       (current.st_mtim.tv_nsec != original.st_mtim.tv_nsec) ||
       (current.st_ctim.tv_sec != original.st_ctim.tv_sec) ||
       (current.st_ctim.tv_nsec != original.st_ctim.tv_nsec))
      return UpdateIO::fail(error_,EEXIST,SERVICE_UNIT_CHANGED_BEFORE_REMOVAL);
    if(::unlinkat(dir.value,UNIT_NAME,0) < 0)
      return UpdateIO::fail(error_,errno,"cannot remove mergerfs-webui service unit");
    if(::fsync(dir.value) < 0)
      return UpdateIO::fail(error_,errno,"cannot sync systemd unit directory after removal");
    return 0;
  }


  int
  replace_unit(const Spec        &current_,
               const Spec        &spec_,
               const std::string &directory_,
               bool              *created_,
               std::string       *error_)
  {
    int rc;
    struct stat original;
    struct stat current;
    bool installed;
    UpdateIO::FD dir;
    UpdateIO::FD unit;
    rc = check_spec(current_,error_);
    if(rc)
      return rc;
    rc = check_spec(spec_,error_);
    if(rc)
      return rc;
    rc = open_unit_directory(directory_,&dir,error_);
    if(rc)
      return rc;
    // Confirm the current unit text first; reject anything we did not install.
    installed = false;
    rc        = read_existing(dir.value,unit_text(current_),&installed,error_,nullptr,&original);
    if(rc)
      return rc;
    if(!installed)
      {
        return UpdateIO::fail(error_,
                              ENOENT,
                              "mergerfs-webui service unit is not installed for this change");
      }

    const std::string text = unit_text(spec_);
    if(text == unit_text(current_))
      {
        // Nothing to replace; leave the installed unit and its inode alone.
        return UpdateIO::fail(error_,
                              EALREADY,
                              "the requested service unit is already installed");
      }

    // Write the proposed unit to a private staging name; keep the existing
    // unit loaded until the very last renameat.
    char temporary[STAGING_NAME_BUFFER_SIZE];
    current = {};
    unsigned long long random = 0;
    if(::getrandom(&random,sizeof(random),0) != static_cast<ssize_t>(sizeof(random)))
      {
        return UpdateIO::fail(error_,
                              EIO,
                              "cannot reserve random service unit staging name");
      }
    std::snprintf(temporary,sizeof(temporary),".%016llx.service",random);
    unit.value = ::openat(dir.value,
                          temporary,
                          O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,
                          PRIVATE_MODE);
    if(unit.value < 0)
      return UpdateIO::fail(error_,errno,"cannot stage proposed mergerfs-webui service unit");

    int code = 0;
    size_t offset = 0;
    while(offset < text.size())
      {
        ssize_t count;
        count = ::write(unit.value,text.data() + offset,text.size() - offset);
        if((count < 0) && (errno == EINTR))
          continue;
        if(count <= 0)
          {
            code = ((count < 0) ? errno : EIO);
            break;
          }

        offset += static_cast<size_t>(count);
      }

    if((!code) && (::fchmod(unit.value,SERVICE_UNIT_MODE) < 0))
      code = errno;
    if((!code) && (::fsync(unit.value) < 0))
      code = errno;
    if(code)
      {
        struct stat written;
        struct stat changed;
        if((::fstat(unit.value,&written) == 0) &&
           (::fstatat(dir.value,temporary,&changed,AT_SYMLINK_NOFOLLOW) == 0) &&
           (written.st_dev == changed.st_dev) &&
           (written.st_ino == changed.st_ino) &&
           (changed.st_nlink == 1))
          ::unlinkat(dir.value,temporary,0);
        return UpdateIO::fail(error_,code,"cannot write proposed mergerfs-webui service unit");
      }

    // Nothing changed on disk until this point; systemd keeps running its
    // current unit until we swap the name below.
    if(::fstatat(dir.value,UNIT_NAME,&current,AT_SYMLINK_NOFOLLOW) < 0)
      {
        ::unlinkat(dir.value,temporary,0);
        return UpdateIO::fail(error_,
                              errno == ENOENT ? EAGAIN : errno,
                              SERVICE_UNIT_CHANGED_BEFORE_REMOVAL);
      }
    if((current.st_dev != original.st_dev) || (current.st_ino != original.st_ino))
      {
        ::unlinkat(dir.value,temporary,0);
        return UpdateIO::fail(error_,EAGAIN,SERVICE_UNIT_CHANGED_BEFORE_REMOVAL);
      }
    if(::renameat(dir.value,temporary,dir.value,UNIT_NAME) < 0)
      {
        int saved = errno;
        ::unlinkat(dir.value,temporary,0);
        return UpdateIO::fail(error_,saved,"cannot replace mergerfs-webui service unit");
      }
    if(::fsync(dir.value) < 0)
      {
        return UpdateIO::fail(error_,
                              errno,
                              "mergerfs-webui service unit replaced but directory sync failed");
      }

    *created_ = true;
    return 0;
  }
}
