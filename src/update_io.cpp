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

#include "update_io.hpp"

#include <array>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

namespace UpdateIO
{
  namespace
  {
    constexpr size_t MAX_METADATA_SIZE = 1024 * 1024;
    constexpr size_t SHA256_HEX_LENGTH = 64;
    constexpr size_t MAX_TAG_LENGTH    = 100;
  }


  FD::~FD()
  {
    if(value >= 0)
      ::close(value);
  }


  int
  fail(std::string       *error_,
       int                code_,
       const std::string &message_)
  {
    if(error_)
      *error_ = message_;
    return -code_;
  }


  bool
  hex_digest(std::string_view digest_)
  {
    if(digest_.size() != SHA256_HEX_LENGTH)
      return false;
    for(char c : digest_)
      {
        if(!(((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f'))))
          return false;
      }

    return true;
  }


  bool
  safe_tag(std::string_view tag_)
  {
    if((tag_.empty()) || (tag_.size() > MAX_TAG_LENGTH) || (tag_ == ".") || (tag_ == ".."))
      return false;
    for(unsigned char c : tag_)
      {
        if(!(((c >= 'a') &&
              (c <= 'z')) ||
             ((c >= 'A') &&
              (c <= 'Z')) ||
             ((c >= '0') &&
              (c <= '9')) ||
             (c == '.') ||
             (c == '_') ||
             (c == '-')))
          return false;
      }

    return true;
  }


  int
  run(const std::vector<std::string> &args,
      int                             destination,
      std::string                    *output,
      size_t                          limit,
      std::string                    *error,
      int                            *exit_status,
      bool                            capture_stderr,
      int                             timeout_seconds)
  {
    if((args.empty()) || (args[0].empty()))
      return fail(error,EINVAL,"empty update command");
    int pipefd[2] = {-1,-1};
    if((output) && (::pipe2(pipefd,O_CLOEXEC) < 0))
      return fail(error,errno,"cannot create update command pipe");
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for(const std::string &arg : args)
      argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);
    pid_t pid = ::fork();
    if(pid == 0)
      {
        if(timeout_seconds > 0)
          ::setpgid(0,0);
        if(output)
          ::close(pipefd[0]);
        const int target = (output) ? pipefd[1] : destination;
        if(::dup2(target,STDOUT_FILENO) < 0)
          ::_exit(127);
        if((!output) && (limit))
          {
            const rlimit cap{static_cast<rlim_t>(limit),static_cast<rlim_t>(limit)};
            if(::setrlimit(RLIMIT_FSIZE,&cap) < 0)
              ::_exit(127);
          }

        if(output)
          ::close(pipefd[1]);
        if((capture_stderr) && (output))
          {
            if(::dup2(STDOUT_FILENO,STDERR_FILENO) < 0)
              ::_exit(127);
            if((::setenv("LC_ALL","C",1) < 0) || (::setenv("LANGUAGE","C",1) < 0))
              ::_exit(127);
          }
        else
          {
            const int nullfd = ::open("/dev/null",O_WRONLY);
            if((nullfd < 0) || (::dup2(nullfd,STDERR_FILENO) < 0))
              ::_exit(127);
            ::close(nullfd);
          }

        ::execv(args[0].c_str(),argv.data());
        ::_exit(127);
      }

    const int fork_error = errno;
    if(output)
      ::close(pipefd[1]);
    if(pid < 0)
      {
        if(output)
          ::close(pipefd[0]);
        return fail(error,fork_error,"cannot start update command");
      }

    if(timeout_seconds > 0)
      ::setpgid(pid,pid);
    bool overflow  = false;
    int read_error = 0;
    bool timed_out = false;
    int status     = 0;
    bool exited    = false;
    bool eof = !output;
    if(output)
      output->clear();
    const auto deadline = (timeout_seconds > 0) ? ::time(nullptr) + timeout_seconds : 0;
    while((!exited) || (!eof))
      {
        if(!exited)
          {
            pid_t waited = ::waitpid(pid,&status,WNOHANG);
            if(waited == pid)
              {
                exited = true;
              }
            else if((waited < 0) && (errno != EINTR))
              {
                read_error = errno;
                break;
              }
          }

        if((exited) && (eof))
          break;
        if((timeout_seconds > 0) && (::time(nullptr) >= deadline))
          {
            timed_out = true;
            break;
          }

        if(!eof)
          {
            pollfd watch{pipefd[0],POLLIN | POLLHUP,0};
            int ready = ::poll(&watch,1,100);
            if((ready < 0) && (errno == EINTR))
              continue;
            if(ready < 0)
              {
                read_error = errno;
                break;
              }

            if(ready > 0)
              {
                char    buffer[8192];
                ssize_t n = ::read(pipefd[0],buffer,sizeof(buffer));
                if((n < 0) && (errno == EINTR))
                  continue;
                if(n < 0)
                  {
                    read_error = errno;
                    break;
                  }

                if(n == 0)
                  {
                    eof = true;
                  }
                else if(static_cast<size_t>(n) > limit - output->size())
                  {
                    overflow = true;
                    break;
                  }
                else
                  {
                    output->append(buffer,static_cast<size_t>(n));
                  }
              }
          }
        else
          {
            ::poll(nullptr,0,100);
          }
      }

    if(output)
      ::close(pipefd[0]);
    if((overflow) || (read_error) || (timed_out))
      {
        if(timeout_seconds > 0)
          ::kill(-pid,SIGKILL);
        ::kill(pid,SIGKILL);
      }

    if(!exited)
      {
        while(::waitpid(pid,&status,0) < 0)
          {
            if(errno == EINTR)
              continue;
            return fail(error,errno,"cannot wait for update command");
          }
      }

    if(timed_out)
      return fail(error,ETIMEDOUT,"update command timed out");
    if(overflow)
      return fail(error,EFBIG,"release response exceeds size limit");
    if(read_error)
      return fail(error,read_error,"cannot read update command output");
    if(!WIFEXITED(status))
      return fail(error,EIO,"update command terminated unexpectedly");
    if(exit_status)
      {
        *exit_status = WEXITSTATUS(status);
        return 0;
      }

    if(WEXITSTATUS(status) != 0)
      {
        return fail(error,
                    EIO,
                    "update command failed (exit status " + std::to_string(WEXITSTATUS(status)) +
                    ")");
      }

    return 0;
  }


  int
  curl(const std::string &url_,
       uint64_t           limit_,
       int                destination_,
       std::string       *output_,
       std::string       *error_)
  {
    std::vector<std::string> args =
      {
        "/usr/bin/curl",
        "--disable",
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--connect-timeout",
        "10",
        "--max-time",
        "60",
        "--max-filesize",
        std::to_string(limit_),
        "--user-agent",
        "mergerfs-webui-updater",
        "--output",
        "-",
        url_
      };
    return run(args,destination_,output_,output_ ? MAX_METADATA_SIZE : 0,error_);
  }


  int
  hash_file(int          fd_,
            std::string *digest_,
            std::string *error_)
  {
    const std::string descriptor =
      "/proc/" + std::to_string(::getpid()) + "/fd/" + std::to_string(fd_);
    std::string output;
    int rc = run({"/usr/bin/sha256sum","--",descriptor},-1,&output,SHA256_HEX_LENGTH * 4,error_);
    if(rc)
      return rc;
    if((output.size() < SHA256_HEX_LENGTH + 1) ||
       (output[SHA256_HEX_LENGTH] != ' ') ||
       (!hex_digest(std::string_view(output).substr(0,SHA256_HEX_LENGTH))))
      return fail(error_,EBADMSG,"invalid SHA-256 command output");
    *digest_ = output.substr(0,SHA256_HEX_LENGTH);
    return 0;
  }


  bool
  compatible_elf(int fd_)
  {
    std::array<unsigned char,20> header{};
    if((::pread(fd_,header.data(),header.size(),0) != static_cast<ssize_t>(header.size())) ||
       (header[0] != 0x7f) ||
       (header[1] != 'E') ||
       (header[2] != 'L') ||
       (header[3] != 'F') ||
       (header[5] != 1))
      return false;
#if defined(__x86_64__)
    return ((header[4] == 2) && (header[18] == 62) && (header[19] == 0));
#elif defined(__aarch64__)
    return ((header[4] == 2) && (header[18] == 183) && (header[19] == 0));
#elif defined(__arm__)
    return ((header[4] == 1) && (header[18] == 40) && (header[19] == 0));
#elif defined(__riscv) && __riscv_xlen == 64
    return ((header[4] == 2) && (header[18] == 243) && (header[19] == 0));
#else
    return false;
#endif
  }
}
