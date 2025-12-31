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

#include "update.hpp"
#include "json.hpp"
#include "update_io.hpp"

#include <array>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace Update
{
  namespace
  {
    constexpr uint64_t MAX_ASSET_SIZE  = 32 * 1024 * 1024;
    constexpr size_t MAX_METADATA_SIZE = 1024 * 1024;
    constexpr char API_URL[] =
      "https://api.github.com/repos/trapexit/mergerfs-webui/releases/latest";
    constexpr char DELETED_SUFFIX[] = " (deleted)";
    constexpr size_t DELETED_SUFFIX_LENGTH = sizeof(DELETED_SUFFIX) - 1;
    constexpr char SHA256_PREFIX[] = "sha256:";
    constexpr size_t SHA256_PREFIX_LENGTH   = sizeof(SHA256_PREFIX) - 1;
    constexpr mode_t EXECUTABLE_PERMISSIONS = 0777;
    constexpr mode_t EXECUTE_BITS = 0111;
    constexpr char RUNNING_EXECUTABLE[] = "/proc/self/exe";
    constexpr char RUNNING_INSPECTION_ERROR[] = "cannot inspect running executable";
    bool               initialized = false;
    std::mutex         install_mutex;


    const
    char*
    asset_name()
    {
#if defined(__x86_64__)
      return "mergerfs-webui_x86_64-linux-musl";
#elif defined(__aarch64__)
      return "mergerfs-webui_aarch64-linux-musl";
#elif defined(__arm__)
      return "mergerfs-webui_arm-linux-musleabihf";
#elif defined(__riscv) && __riscv_xlen == 64
      return "mergerfs-webui_riscv64-linux-musl";
#else
      return nullptr;
#endif
    }


    int
    locate_executable(std::string *path_,
                      std::string *error_,
                      bool        *deleted_ = nullptr)
    {
      std::array<char,PATH_MAX> path{};
      const ssize_t length = ::readlink(RUNNING_EXECUTABLE,path.data(),path.size());
      if((length <= 0) || (static_cast<size_t>(length) == path.size()))
        {
          return UpdateIO::fail(error_,
                                length < 0 ? errno : ENAMETOOLONG,
                                "cannot locate running executable");
        }

      struct stat running{};
      if(::stat(RUNNING_EXECUTABLE,&running) < 0)
        return UpdateIO::fail(error_,errno,RUNNING_INSPECTION_ERROR);
      const bool deleted = running.st_nlink == 0;
      path_->assign(path.data(),static_cast<size_t>(length));
      if((deleted) &&
         (path_->size() >= DELETED_SUFFIX_LENGTH) &&
         (path_->compare(path_->size() - DELETED_SUFFIX_LENGTH,
                         DELETED_SUFFIX_LENGTH,
                         DELETED_SUFFIX) == 0))
        path_->resize(path_->size() - DELETED_SUFFIX_LENGTH);
      if(deleted_)
        *deleted_ = deleted;
      return 0;
    }


    int
    open_installed(const std::string &path_,
                   UpdateIO::FD      *file_,
                   UpdateIO::FD      *directory_,
                   std::string       *name_,
                   struct stat       *metadata_,
                   std::string       *error_)
    {
      const size_t slash = path_.rfind('/');
      if((slash == std::string::npos) || (slash + 1 == path_.size()))
        return UpdateIO::fail(error_,EINVAL,"invalid executable location");
      *name_ = path_.substr(slash + 1);
      const std::string parent = (slash) ? path_.substr(0,slash) : "/";
      directory_->value = ::open(parent.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
      if(directory_->value < 0)
        {
          const int saved = errno;
          return UpdateIO::fail(error_,
                                saved,
                                "cannot open executable directory '" + parent + "': " +
                                std::strerror(saved));
        }
      file_->value = ::openat(directory_->value,name_->c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
      if((file_->value < 0) || (::fstat(file_->value,metadata_) < 0))
        {
          const int saved = errno;
          return UpdateIO::fail(error_,
                                saved,
                                "cannot open installed executable '" + path_ + "': " +
                                std::strerror(saved));
        }
      if((!S_ISREG(metadata_->st_mode)) ||
         (metadata_->st_nlink != 1) ||
         ((metadata_->st_mode & (S_ISUID|S_ISGID)) != 0))
        {
          return UpdateIO::fail(error_,
                                EINVAL,
                                "installed executable must be a regular, singly linked, non-setuid file");
        }

      return 0;
    }


    int
    restart_path(std::string *path_,
                 std::string *error_)
    {
      int rc = locate_executable(path_,error_);
      if(rc)
        return rc;
      UpdateIO::FD installed(::open(path_->c_str(),O_PATH|O_CLOEXEC));
      if(installed.value < 0)
        {
          const int saved = errno;
          return UpdateIO::fail(error_,
                                saved,
                                "cannot open installed executable '" + *path_ + "': " +
                                std::strerror(saved));
        }
      struct stat metadata{};
      if(::fstat(installed.value,&metadata) < 0)
        return UpdateIO::fail(error_,errno,"cannot inspect installed executable");
      if(!S_ISREG(metadata.st_mode))
        return UpdateIO::fail(error_,EINVAL,"installed executable is not a regular file");
      if((!(metadata.st_mode & EXECUTE_BITS)) ||
         (::faccessat(AT_FDCWD,path_->c_str(),X_OK,AT_EACCESS) < 0))
        return UpdateIO::fail(error_,EACCES,"installed executable is not runnable");
      return 0;
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
  }


  int
  initialize(std::string *error_)
  {
    std::string path;
    bool deleted;
    int rc = locate_executable(&path,error_,&deleted);
    if(rc)
      return rc;
    if(deleted)
      {
        return UpdateIO::fail(error_,
                              ESTALE,
                              "running executable has already been replaced; restart before updating");
      }

    if(!asset_name())
      return UpdateIO::fail(error_,ENOTSUP,"no release asset supports this architecture");
    UpdateIO::FD file;
    UpdateIO::FD directory;
    std::string  name;
    struct stat metadata{};
    rc = open_installed(path,&file,&directory,&name,&metadata,error_);
    initialized = rc == 0;
    return rc;
  }


  int
  latest(Release     *release,
         std::string *error)
  {
    if(error)
      error->clear();
    if((!release) || (!initialized))
      return UpdateIO::fail(error,EINVAL,"updater is not initialized");
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
          return UpdateIO::fail(error,EBADMSG,"unsupported latest release metadata");
        const std::string asset = asset_name();
        const std::string url =
          "https://github.com/trapexit/mergerfs-webui/releases/download/" + tag + "/" + asset;
        Release selected;
        selected.tag   = tag;
        selected.asset = asset;
        for(const auto &candidate : body.at("assets"))
          {
            if(candidate.at("name").get<std::string>() != asset)
              continue;
            if((candidate.at("state").get<std::string>() != "uploaded") ||
               (candidate.at("browser_download_url").get<std::string>() != url))
              return UpdateIO::fail(error,EBADMSG,"unexpected release asset URL");
            const std::string full_digest = candidate.at("digest").get<std::string>();
            if((full_digest.compare(0,SHA256_PREFIX_LENGTH,SHA256_PREFIX) != 0) ||
               (!UpdateIO::hex_digest(std::string_view(full_digest).substr(SHA256_PREFIX_LENGTH))))
              return UpdateIO::fail(error,EBADMSG,"release asset has no SHA-256 digest");
            selected.digest = full_digest.substr(SHA256_PREFIX_LENGTH);
            selected.size   = candidate.at("size").get<uint64_t>();
            if((selected.size == 0) || (selected.size > MAX_ASSET_SIZE))
              return UpdateIO::fail(error,EFBIG,"release asset exceeds size limit");
            UpdateIO::FD installed;
            UpdateIO::FD directory;
            std::string  name;
            struct stat metadata{};
            std::string path;
            rc = locate_executable(&path,error);
            if(rc)
              return rc;
            rc = open_installed(path,&installed,&directory,&name,&metadata,error);
            if(rc)
              return rc;
            std::string local_hash;
            rc = UpdateIO::hash_file(installed.value,&local_hash,error);
            if(rc)
              return rc;
            selected.installed = local_hash == selected.digest;
            UpdateIO::FD running(::open(RUNNING_EXECUTABLE,O_RDONLY|O_CLOEXEC));
            if(running.value < 0)
              return UpdateIO::fail(error,errno,RUNNING_INSPECTION_ERROR);
            struct stat running_metadata{};
            if(::fstat(running.value,&running_metadata) < 0)
              return UpdateIO::fail(error,errno,RUNNING_INSPECTION_ERROR);
            if((metadata.st_dev == running_metadata.st_dev) &&
               (metadata.st_ino == running_metadata.st_ino))
              {
                selected.running = selected.installed;
              }
            else
              {
                rc = UpdateIO::hash_file(running.value,&local_hash,error);
                if(rc)
                  return rc;
                selected.running = local_hash == selected.digest;
              }

            *release = std::move(selected);
            return 0;
          }

        return UpdateIO::fail(error,ENOTSUP,"latest release has no asset for this architecture");
      }
    catch(const nlohmann::json::exception &)
      {
        return UpdateIO::fail(error,EBADMSG,"invalid GitHub release metadata");
      }
  }


  int
  install(const std::string &tag,
          const std::string &digest,
          Release           *release,
          std::string       *error)
  {
    if(error)
      error->clear();
    if((!release) || (!UpdateIO::safe_tag(tag)) || (!UpdateIO::hex_digest(digest)))
      return UpdateIO::fail(error,EINVAL,"invalid selected release");
    std::lock_guard<std::mutex> lock(install_mutex);
    Release selected;
    int     rc = latest(&selected,error);
    if(rc)
      return rc;
    if((tag != selected.tag) || (digest != selected.digest))
      return UpdateIO::fail(error,EAGAIN,"latest release changed; check for updates again");
    if(selected.installed)
      return UpdateIO::fail(error,EALREADY,"latest release is already installed");

    UpdateIO::FD installed;
    UpdateIO::FD directory;
    std::string  name;
    struct stat original{};
    std::string path;
    rc = locate_executable(&path,error);
    if(rc)
      return rc;
    rc = open_installed(path,&installed,&directory,&name,&original,error);
    if(rc)
      return rc;
    std::string temporary =
      path.substr(0,path.rfind('/') + 1) + ".mergerfs-webui-update-XXXXXX";
    UpdateIO::FD replacement(::mkstemp(temporary.data()));
    if(replacement.value < 0)
      return UpdateIO::fail(error,errno,"cannot create update alongside executable");
    const auto discard = [&]() { ::unlink(temporary.c_str()); };
    const std::string url = "https://github.com/trapexit/mergerfs-webui/releases/download/" +
                            selected.tag + "/" + selected.asset;
    rc = UpdateIO::curl(url,MAX_ASSET_SIZE,replacement.value,nullptr,error);
    if(rc)
      {
        discard();
        return rc;
      }

    struct stat downloaded{};
    if((::fstat(replacement.value,&downloaded) < 0) ||
       (downloaded.st_size != static_cast<off_t>(selected.size)))
      {
        discard();
        return UpdateIO::fail(error,EBADMSG,"release asset size does not match metadata");
      }

    std::string actual;
    rc = UpdateIO::hash_file(replacement.value,&actual,error);
    if(rc)
      {
        discard();
        return rc;
      }

    if((actual != selected.digest) || (!UpdateIO::compatible_elf(replacement.value)))
      {
        discard();
        return UpdateIO::fail(error,
                              EBADMSG,
                              "release asset checksum or architecture does not match");
      }

    if((::fchown(replacement.value,original.st_uid,original.st_gid) < 0) ||
       (::fchmod(replacement.value,original.st_mode & EXECUTABLE_PERMISSIONS) < 0) ||
       (::fsync(replacement.value) < 0))
      {
        const int saved = errno;
        discard();
        return UpdateIO::fail(error,saved,"cannot prepare replacement executable");
      }

    struct stat current{};
    if((::fstat(installed.value,&current) < 0) ||
       (!same_file(original,current)) ||
       (::fstatat(directory.value,name.c_str(),&current,AT_SYMLINK_NOFOLLOW) < 0) ||
       (!same_file(original,current)))
      {
        discard();
        return UpdateIO::fail(error,EAGAIN,"installed executable changed during update");
      }

    if(::renameat(AT_FDCWD,temporary.c_str(),directory.value,name.c_str()) < 0)
      {
        const int saved = errno;
        discard();
        return UpdateIO::fail(error,saved,"cannot replace installed executable");
      }

    if(::fsync(directory.value) < 0)
      {
        return UpdateIO::fail(error,
                              errno,
                              "executable replaced, but directory sync failed; restart and check installation");
      }

    selected.installed = true;
    *release           = std::move(selected);
    return 0;
  }


  int
  restart_ready(std::string *error_)
  {
    std::lock_guard<std::mutex> lock(install_mutex);
    std::string path;
    return restart_path(&path,error_);
  }


  int
  reexec(int           argc_,
         char        **argv_,
         std::string  *error_)
  {
    std::lock_guard<std::mutex> lock(install_mutex);
    std::string path;
    int rc;
    int saved;
    rc = restart_path(&path,error_);
    if(rc)
      return rc;
    std::vector<char*> arguments;
    arguments.reserve(static_cast<size_t>(argc_) + 1);
    arguments.push_back(const_cast<char*>(path.c_str()));
    for(int i = 1; i < argc_; ++i)
      arguments.push_back(argv_[i]);
    arguments.push_back(nullptr);
    ::execv(path.c_str(),arguments.data());
    saved = errno;
    return UpdateIO::fail(error_,
                          saved,
                          "cannot re-execute installed executable: " +
                          std::string(::strerror(saved)));
  }
}
