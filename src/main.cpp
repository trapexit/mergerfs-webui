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

#include "favicon_ico.h"
#include "httplib.h"
#include "index_html_gz.h"
#include "json.hpp"
#include "mergerfs_update.hpp"
#include "persistence.hpp"
#include "service_install.hpp"
#include "update.hpp"
#include "update_io.hpp"
#include "version.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <limits.h>
#include <mntent.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

using json = nlohmann::json;

static constexpr char SYSTEMCTL_PATH[]      = "/usr/bin/systemctl";
static constexpr size_t XATTR_GROWTH_FACTOR = 2;

static std::string g_password;
static std::string g_index_html;
static std::mutex  g_mounts_mutex;
static bool g_update_enabled = false;
static const std::string g_instance_id =
  std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
static Persistence::Roots g_persistence_roots =
  {
    "/etc/fstab",
    {"/etc/systemd/system","/usr/lib/systemd/system"}
  };

static
int
_running_mount_type(const std::string &mount_,
                    std::string       *type_);


static
std::string
_config_file(const std::string &mount_)
{
  return mount_ + "/.mergerfs";
}


static
int
_get_xattr(const std::string &path_,
           const char        *attr_,
           std::string       *value_)
{
  constexpr size_t initial_size = 64;
  constexpr size_t max_size     = 65536;
  std::vector<char> buffer(initial_size);

  ssize_t rv;
  while(true)
    {
      rv = ::lgetxattr(path_.c_str(),attr_,buffer.data(),buffer.size());
      if(rv >= 0)
        {
          value_->assign(buffer.data(),static_cast<size_t>(rv));
          return 0;
        }

      if(errno != ERANGE)
        return -errno;
      if(buffer.size() == max_size)
        return -E2BIG;
      buffer.resize(std::min(buffer.size() * XATTR_GROWTH_FACTOR,max_size));
    }
}


static
int
_list_xattrs(const std::string &path_,
             std::vector<char> *attrs_)
{
  constexpr size_t initial_size = 4096;
  constexpr size_t max_size     = 65536;
  ssize_t rv;
  attrs_->resize(initial_size);
  while(true)
    {
      rv = ::llistxattr(path_.c_str(),attrs_->data(),attrs_->size());
      if(rv >= 0)
        {
          attrs_->resize(static_cast<size_t>(rv));
          return 0;
        }

      if(errno != ERANGE)
        return -errno;
      if(attrs_->size() == max_size)
        return -E2BIG;
      attrs_->resize(std::min(attrs_->size() * XATTR_GROWTH_FACTOR,max_size));
    }
}


static
int
_get_kv(const std::string &mount_,
        const std::string &key_,
        std::string       *value_)
{
  return _get_xattr(_config_file(mount_),("user.mergerfs." + key_).c_str(),value_);
}


static
int
_set_kv(const std::string &mount_,
        const std::string &key_,
        const std::string &value_)
{
  std::string path = _config_file(mount_);
  std::string attr = "user.mergerfs." + key_;

  if(::lsetxattr(path.c_str(),attr.c_str(),value_.data(),value_.size(),0) < 0)
    return -errno;
  return 0;
}


static
int
_get_kvs(const std::string                 &mount_,
         std::map<std::string,std::string> *kvs_)
{
  constexpr std::string_view prefix = "user.mergerfs.";
  std::string path = _config_file(mount_);
  std::vector<char> attrs;
  int rv;
  rv = _list_xattrs(path,&attrs);
  if(rv < 0)
    return rv;

  for(size_t pos = 0; pos < attrs.size();)
    {
      const char *name = attrs.data() + pos;
      size_t length;
      length = std::strlen(name);
      std::string_view attr(name, length);
      if(attr.compare(0,prefix.size(),prefix) == 0)
        {
          std::string value;
          rv = _get_xattr(path,name,&value);
          if(rv < 0)
            return rv;
          kvs_->emplace(std::string(attr.substr(prefix.size())),std::move(value));
        }

      pos += length + 1;
    }

  return 0;
}


static
bool
_validate_password(const std::string &password_)
{
  return ((g_password.empty()) || (password_ == g_password));
}


static
json
_generate_error(const std::string &mount_,
                const std::string &key_,
                const std::string &value_,
                int                err_)
{
  json error = {{"mount",mount_},{"key",key_},{"value",value_}};

  switch(err_)
    {
    case -EROFS:
      error["msg"] = "'" + key_ + "' is read only.";
      break;
    case -EINVAL:
      error["msg"] = "value '" + value_ + "' is invalid for '" + key_ + "'";
      break;
    case -EACCES:
      error["msg"] = "mergerfs-webui (pid " +
        std::to_string(::getpid()) +
        ") is running as uid " +
        std::to_string(::getuid()) +
        " which appears not to have access to modify the mount's config.";
      break;
    case -ENOTCONN:
      error["msg"] = "It appears the mergerfs mount '" +
        mount_ +
        "' is in a bad state. mergerfs may have crashed.";
      break;
    default:
      error["msg"] = std::strerror(-err_);
      break;
    }

  return error;
}


static
void
_get_root(const httplib::Request &req_,
          httplib::Response      &res_)
{
  struct stat st;
  if((!g_index_html.empty()) && (::stat(g_index_html.c_str(),&st) == 0) && (S_ISREG(st.st_mode)))
    {
      res_.set_file_content(g_index_html,"text/html");
      return;
    }

  if(req_.get_header_value("Accept-Encoding").find("gzip") != std::string::npos)
    {
      res_.set_header("Content-Encoding","gzip");
      res_.set_content(reinterpret_cast<const char*>(index_html_gz),index_html_gz_len,"text/html");
      return;
    }

  res_.set_content("browser needs to support gzip","text/plain");
}


static
void
_get_favicon(const httplib::Request &,
             httplib::Response      &res_)
{
  res_.set_content(reinterpret_cast<const char*>(favicon_ico),favicon_ico_len,"image/png");
}


static
bool
_valid_fs_type(const std::string &path_,
               const std::string &type_)
{
  constexpr std::array<std::string_view,5> paths = {"/mnt/","/media/","/opt/","/tmp/","/srv/"};
  constexpr std::array<std::string_view,13> types =
    {
      "bcachefs",
      "btrfs",
      "exfat",
      "ext2",
      "ext3",
      "ext4",
      "f2fs",
      "jfs",
      "ntfs",
      "reiserfs",
      "vfat",
      "xfs",
      "zfs"
    };
  constexpr std::string_view fuse_prefix = "fuse.";
  bool under_allowed_path = false;
  for(std::string_view prefix : paths)
    {
      if(path_.compare(0,prefix.size(),prefix) == 0)
        under_allowed_path = true;
    }

  if(!under_allowed_path)
    return false;

  for(std::string_view type : types)
    {
      if(type_ == type)
        return true;
    }

  return ((type_ != "fuse.gvfsd-fuse") &&
          (type_ != "fuse.kio-fuse") &&
          (type_.compare(0,fuse_prefix.size(),fuse_prefix) == 0));
}


static
json
_mounts(bool mergerfs_only_)
{
  json mounts = json::array();
  struct mntent *entry;
  std::lock_guard<std::mutex> lock(g_mounts_mutex);
  FILE *file = ::setmntent("/proc/mounts","r");
  if(file == nullptr)
    return mounts;

  while((entry = ::getmntent(file)) != nullptr)
    {
      if(mergerfs_only_)
        {
          if(std::strcmp(entry->mnt_type,"fuse.mergerfs") == 0)
            mounts.push_back(entry->mnt_dir);
        }
      else if(_valid_fs_type(entry->mnt_dir,entry->mnt_type))
        {
          mounts.push_back({{"path",entry->mnt_dir},{"type",entry->mnt_type}});
        }
    }

  ::endmntent(file);
  return mounts;
}


static
void
_get_mounts(const httplib::Request &,
            httplib::Response      &res_)
{
  res_.set_content(_mounts(false).dump(),"application/json");
}


static
void
_get_mounts_mergerfs(const httplib::Request &,
                     httplib::Response      &res_)
{
  res_.set_content(_mounts(true).dump(),"application/json");
}


static
void
_config_error(httplib::Response &res_,
              int                err_)
{
  res_.status =
    (((err_ == -ENOENT) || (err_ == -ENODATA)) ?
     404 :
     ((err_ == -EACCES) || (err_ == -EPERM)) ?
     403 :
     (err_ == -ENOTCONN) ?
     503 :
     (err_ == -E2BIG) ?
     413 :
     500);
  res_.set_content(json({{"error",{{"msg",std::strerror(-err_)}}}}).dump(),"application/json");
}


static
bool
_require_mergerfs_mount(const std::string &mount_,
                        httplib::Response &res_)
{
  std::string type;
  int rv;
  rv = _running_mount_type(mount_,&type);
  if(rv < 0)
    {
      _config_error(res_,rv);
      return false;
    }

  if(type != "fuse.mergerfs")
    {
      res_.status = httplib::StatusCode::NotFound_404;
      res_.set_content(json({
            {"error",{{"msg","mountpoint is not a running mergerfs mount"}}}
          }).dump(),
        "application/json");
      return false;
    }

  return true;
}


static
void
_get_kvs_route(const httplib::Request &req_,
               httplib::Response      &res_)
{
  if(!req_.has_param("mount"))
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content("mount param not set","text/plain");
      return;
    }

  const std::string &mount = req_.get_param_value("mount");
  if(!_require_mergerfs_mount(mount,res_))
    return;
  std::map<std::string,std::string> kvs;
  int rv;
  rv = _get_kvs(mount,&kvs);
  if(rv < 0)
    _config_error(res_,rv);
  else
    res_.set_content(json(kvs).dump(),"application/json");
}


static
void
_get_kvs_key(const httplib::Request &req_,
             httplib::Response      &res_)
{
  if(!req_.has_param("mount"))
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content("mount param not set","text/plain");
      return;
    }

  const std::string &mount = req_.get_param_value("mount");
  if(!_require_mergerfs_mount(mount,res_))
    return;
  std::string value;
  int rv;
  rv = _get_kv(mount,req_.path_params.at("key"),&value);
  if(rv < 0)
    _config_error(res_,rv);
  else
    res_.set_content(json(value).dump(),"application/json");
}


static
bool
_check_auth(const httplib::Request &req_)
{
  constexpr std::string_view bearer_prefix = "Bearer ";
  if(g_password.empty())
    return true;
  const std::string header = req_.get_header_value("Authorization");
  return ((header.compare(0,bearer_prefix.size(),bearer_prefix) == 0) &&
          (_validate_password(header.substr(bearer_prefix.size()))));
}


static
bool
_ascii_iequal(std::string_view left_,
              std::string_view right_)
{
  const auto equal_char = [](unsigned char left_,unsigned char right_)
  {
    if((left_ >= 'A') && (left_ <= 'Z'))
      left_ += 'a' - 'A';
    if((right_ >= 'A') && (right_ <= 'Z'))
      right_ += 'a' - 'A';
    return left_ == right_;
  };
  return ((left_.size() == right_.size()) &&
          (std::equal(left_.begin(),left_.end(),right_.begin(),equal_char)));
}


static
httplib::Server::HandlerResponse
_check_write_request(const httplib::Request &req_,
                     httplib::Response      &res_)
{
  using Result = httplib::Server::HandlerResponse;
  if((req_.method == "GET") || (req_.method == "HEAD") || (req_.method == "OPTIONS"))
    return Result::Unhandled;

  const auto site   = req_.headers.find("Sec-Fetch-Site");
  const auto origin = req_.headers.find("Origin");
  const auto host   = req_.headers.find("Host");
  bool allowed =
    ((req_.headers.count("Sec-Fetch-Site") <= 1) &&
     ((site == req_.headers.end()) ||
      (site->second == "same-origin") ||
      (site->second == "none")));
  if(origin != req_.headers.end())
    {
      std::string_view authority(origin->second);
      std::string_view default_port;
      constexpr std::string_view http_prefix  = "http://";
      constexpr std::string_view https_prefix = "https://";
      if(authority.substr(0,http_prefix.size()) == http_prefix)
        {
          authority.remove_prefix(http_prefix.size());
          default_port = ":80";
        }
      else if(authority.substr(0,https_prefix.size()) == https_prefix)
        {
          authority.remove_prefix(https_prefix.size());
          default_port = ":443";
        }
      else
        {
          allowed = false;
        }

      std::string_view expected =
        ((host == req_.headers.end()) ?
         std::string_view{} :
         std::string_view(host->second));
      if((!default_port.empty()) &&
         (expected.size() > default_port.size()) &&
         (expected.substr(expected.size() - default_port.size()) == default_port))
        expected.remove_suffix(default_port.size());
      // TLS proxies must preserve the browser's Host; never trust forwarded headers.
      allowed =
        ((allowed) &&
         (req_.headers.count("Origin") == 1) &&
         (req_.headers.count("Host") == 1) &&
         (!expected.empty()) &&
         (_ascii_iequal(authority,expected)));
    }

  if(!allowed)
    {
      res_.status = httplib::StatusCode::Forbidden_403;
      res_.set_content(json({{"error",{{"msg","cross-origin writes are not allowed"}}}}).dump(),
                       "application/json");
      return Result::Handled;
    }

  // This hook runs before the body is read. Empty commands need no media type.
  const auto length = req_.headers.find("Content-Length");
  if((req_.has_header("Transfer-Encoding")) ||
     ((length != req_.headers.end()) &&
      (length->second != "0")))
    {
      const auto content_type = req_.headers.find("Content-Type");
      std::string_view media_type =
        ((content_type == req_.headers.end()) ?
         std::string_view{} :
         std::string_view(content_type->second));
      media_type = media_type.substr(0,media_type.find(';'));
      while((!media_type.empty()) && ((media_type.back() == ' ') || (media_type.back() == '\t')))
        media_type.remove_suffix(1);
      if((req_.headers.count("Content-Type") != 1) ||
         (!_ascii_iequal(media_type,"application/json")))
        {
          res_.status = httplib::StatusCode::UnsupportedMediaType_415;
          res_.set_content(json({
                {"error",{{"msg","request body must use application/json"}}}
              }).dump(),
            "application/json");
          return Result::Handled;
        }
    }

  return Result::Unhandled;
}


static
bool
_local_service_request(const httplib::Request &req_);


static
void
_persistence_error(httplib::Response &res_,
                   int                err_,
                   const std::string &message_)
{
  res_.status =
    (((err_ == -EACCES) || (err_ == -EPERM)) ?
     403 :
     (err_ == -ENOENT) ?
     404 :
     (((err_ == -EEXIST) || (err_ == -ESTALE) || (err_ == -EAGAIN))) ?
     409 :
     (((err_ == -E2BIG) || (err_ == -EFBIG))) ?
     413 :
     (((err_ == -EINVAL) ||
       (err_ == -EOPNOTSUPP) ||
       (err_ == -ENAMETOOLONG) ||
       (err_ == -ENOTDIR) ||
       (err_ == -ELOOP))) ?
     422 :
     500);
  res_.set_content(json({{"error",{{"msg",message_}}}}).dump(),"application/json");
}


static
void
_get_persistence(const httplib::Request &req_,
                 httplib::Response      &res_)
{
  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  if(!req_.has_param("mount"))
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content(json({{"error",{{"msg","mount param not set"}}}}).dump(),"application/json");
      return;
    }

  std::vector<Persistence::Source> sources;
  std::string error;
  int rv;
  rv = Persistence::discover(req_.get_param_value("mount"),g_persistence_roots,&sources,&error);
  if(rv < 0)
    {
      _persistence_error(res_,rv,error);
      return;
    }

  json result = {{"enabled",true},{"sources",json::array()}};
  for(const auto &source : sources)
    {
      result["sources"].push_back({{"type",source.type},
                                   {"path",source.path},
                                   {"options",source.options}});
    }

  res_.set_content(result.dump(),"application/json");
}


static
void
_raw_persistence_request(const httplib::Request &req_,
                         httplib::Response      &res_,
                         bool                    save_)
{
  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  if((g_password.empty()) && (!_local_service_request(req_)))
    {
      _persistence_error(res_,
                         -EACCES,
                         "open this page directly at 127.0.0.1 to edit raw files without a password");
      return;
    }

  if(!req_.has_param("mount"))
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content(json({{"error",{{"msg","mount param not set"}}}}).dump(),"application/json");
      return;
    }

  const std::string &mount = req_.get_param_value("mount");
  std::string error;
  if(!save_)
    {
      if((!req_.has_param("type")) || (!req_.has_param("path")))
        {
          res_.status = httplib::StatusCode::BadRequest_400;
          res_.set_content(json({{"error",{{"msg","choose a configuration source"}}}}).dump(),
                           "application/json");
          return;
        }

      Persistence::Raw raw;
      int rv;
      rv = Persistence::raw_read(mount,
                                 g_persistence_roots,
                                 req_.get_param_value("type"),
                                 req_.get_param_value("path"),
                                 &raw,
                                 &error);
      if(rv < 0)
        {
          _persistence_error(res_,rv,error);
        }
      else
        {
          res_.set_header("Cache-Control","no-store");
          res_.set_content(json({{"type",raw.type},
                                 {"path",raw.path},
                                 {"text",raw.text},
                                 {"revision",raw.revision},
                                 {"scope",raw.scope}}).dump(),
            "application/json");
        }

      return;
    }

  try
    {
      const json body = json::parse(req_.body);
      if((!body.is_object()) ||
         (body.size() != 3) ||
         (!body.contains("source")) ||
         (!body["source"].is_object()) ||
         (body["source"].size() != 2))
        {
          res_.status = httplib::StatusCode::BadRequest_400;
          res_.set_content(json({{"error",{{"msg","invalid raw source request"}}}}).dump(),
                           "application/json");
          return;
        }

      const std::string type     = body["source"].at("type").get<std::string>();
      const std::string path     = body["source"].at("path").get<std::string>();
      const std::string text     = body.at("text").get<std::string>();
      const std::string revision = body.at("expected_revision").get<std::string>();
      if(revision.empty())
        {
          res_.status = httplib::StatusCode::BadRequest_400;
          res_.set_content(json({{"error",{{"msg","load this source before saving"}}}}).dump(),
                           "application/json");
          return;
        }

      int rv;
      rv = Persistence::raw_save(mount,g_persistence_roots,type,path,text,revision,&error);
      if(rv < 0)
        _persistence_error(res_,rv,error);
      else
        res_.set_content(json({{"result","success"}}).dump(),"application/json");
    }
  catch(const json::exception &)
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content(json({{"error",{{"msg","invalid raw source request"}}}}).dump(),
                       "application/json");
    }
}


static
void
_get_mount_definitions(const httplib::Request &req_,
                       httplib::Response      &res_)
{
  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  std::vector<std::string> mounts;
  std::string error;
  int rv;
  rv = Persistence::list_mountpoints(g_persistence_roots,&mounts,&error);
  if(rv < 0)
    {
      _persistence_error(res_,rv,error);
      return;
    }

  res_.set_content(json({{"enabled",true},{"mounts",mounts}}).dump(),"application/json");
}


static
void
_warn_inaccessible(json              &warnings_,
                   const std::string &path_,
                   int                mode_,
                   const char        *action_)
{
  if(::faccessat(AT_FDCWD,path_.c_str(),mode_,AT_EACCESS) == 0)
    return;
  warnings_.push_back(std::string("Cannot ") + action_ + " " + path_ + ": " +
                      std::strerror(errno) + ".");
}


static
void
_warn_uncreatable_directory(json        &warnings_,
                            std::string  path_)
{
  while((::faccessat(AT_FDCWD,path_.c_str(),F_OK,AT_EACCESS) < 0) &&
        (errno == ENOENT) &&
        (path_ != "/"))
    {
      const size_t slash = path_.rfind('/');
      path_ = ((slash == 0) ? "/" : (slash == std::string::npos) ? "." : path_.substr(0,slash));
    }

  _warn_inaccessible(warnings_,path_,W_OK | X_OK,"create systemd unit directory under");
}


static
void
_get_mount_definition_capabilities(const httplib::Request &req_,
                                   httplib::Response      &res_)
{
  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  json warnings = json::array();
  const std::string &fstab = g_persistence_roots.fstab;
  if(!fstab.empty())
    {
      _warn_inaccessible(warnings,fstab,R_OK,"read fstab");
      const size_t slash = fstab.rfind('/');
      const std::string directory =
        ((slash == 0) ?
         "/" :
         (slash == std::string::npos) ?
         "." :
         fstab.substr(0,slash));
      _warn_inaccessible(warnings,directory,W_OK | X_OK,"write fstab directory");
    }

  if(!g_persistence_roots.systemd_dirs.empty())
    _warn_uncreatable_directory(warnings,g_persistence_roots.systemd_dirs.front());
  res_.set_content(json({{"enabled",true},
                         {"fstab",g_persistence_roots.fstab},
                         {
                           "systemd_dir",
                           (g_persistence_roots.systemd_dirs.empty()) ?
                           "" :
                           g_persistence_roots.systemd_dirs.front()
                         },
                         {"warnings",std::move(warnings)}}).dump(),
    "application/json");
}


static
void
_get_directories(const httplib::Request &req_,
                 httplib::Response      &res_)
{
  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  if(!req_.has_param("path"))
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content(json({{"error",{{"msg","path param not set"}}}}).dump(),"application/json");
      return;
    }

  Persistence::DirectoryListing listing;
  std::string error;
  int rv;
  rv = Persistence::list_directories(req_.get_param_value("path"),&listing,&error);
  if(rv < 0)
    {
      _persistence_error(res_,rv,error);
      return;
    }

  json result =
    {
      {"path",listing.path},
      {"parent",listing.parent.empty() ? json(nullptr) : json(listing.parent)},
      {"directories",json::array()}
    };
  for(const auto &directory : listing.directories)
    result["directories"].push_back({{"name",directory.name},{"path",directory.path}});
  res_.set_content(result.dump(),"application/json");
}


static
void
_post_mount_definition(const httplib::Request &req_,
                       httplib::Response      &res_)
{
  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  try
    {
      const nlohmann::ordered_json body = nlohmann::ordered_json::parse(req_.body);
      Persistence::Definition definition;
      definition.type       = body.at("type").get<std::string>();
      definition.mountpoint = body.at("mountpoint").get<std::string>();
      definition.branches   = body.at("branches").get<std::string>();
      definition.ini_path   = body.at("ini_path").get<std::string>();
      const auto &options = body.at("options");
      if(!options.is_object())
        {
          res_.status = httplib::StatusCode::BadRequest_400;
          res_.set_content(json({{"error",{{"msg","invalid mount definition request"}}}}).dump(),
                           "application/json");
          return;
        }

      for(auto it = options.begin(); it != options.end(); ++it)
        definition.options.emplace_back(it.key(),it.value().get<std::string>());
      Persistence::Created created;
      std::string error;
      int rv;
      rv = Persistence::create(definition,g_persistence_roots,&created,&error);
      if(rv < 0)
        {
          _persistence_error(res_,rv,error);
        }
      else
        {
          res_.status = httplib::StatusCode::Created_201;
          res_.set_content(json({{"type",created.type},
                                 {"path",created.path},
                                 {"mountpoint",created.mountpoint},
                                 {"ini_path",created.ini_path}}).dump(),
            "application/json");
        }
    }
  catch(const nlohmann::ordered_json::exception &)
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content(json({{"error",{{"msg","invalid mount definition request"}}}}).dump(),
                       "application/json");
    }
}


static
void
_delete_mount_definition(const httplib::Request &req_,
                         httplib::Response      &res_)
{
  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  try
    {
      const json body = json::parse(req_.body);
      const std::string mount = body.at("mountpoint").get<std::string>();
      const std::string type  = body.at("source").at("type").get<std::string>();
      const std::string path  = body.at("source").at("path").get<std::string>();
      const std::string confirmation = body.at("confirmation").get<std::string>();
      if(confirmation != mount)
        {
          _persistence_error(res_,-EINVAL,"mountpoint confirmation does not match");
          return;
        }

      std::string retained_ini_path;
      std::string error;
      int rv;
      rv = Persistence::remove(mount,g_persistence_roots,type,path,&retained_ini_path,&error);
      if(rv < 0)
        {
          _persistence_error(res_,rv,error);
        }
      else
        {
          res_.set_content(json({{"result","success"},
                                 {"mountpoint",mount},
                                 {"type",type},
                                 {"path",path},
                                 {"retained_ini_path",retained_ini_path}}).dump(),
            "application/json");
        }
    }
  catch(const json::exception &)
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content(json({{"error",{{"msg","invalid mount definition request"}}}}).dump(),
                       "application/json");
    }
}


static
void
_post_persistence_request(const httplib::Request &req_,
                          httplib::Response      &res_,
                          bool                    preview_)
{
  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  if(!req_.has_param("mount"))
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content(json({{"error",{{"msg","mount param not set"}}}}).dump(),"application/json");
      return;
    }

  try
    {
      const json body = json::parse(req_.body);
      const std::string &mount = req_.get_param_value("mount");
      const std::string type   = body.at("source").at("type").get<std::string>();
      const std::string path   = body.at("source").at("path").get<std::string>();
      const std::string key    = body.at("key").get<std::string>();
      const std::string value  = body.at("value").get<std::string>();
      const bool remove = (body.contains("remove")) ? body.at("remove").get<bool>() : false;
      if((remove) && (!value.empty()))
        {
          res_.status = httplib::StatusCode::BadRequest_400;
          res_.set_content(json({
                {"error",{{"msg","option removal requires an empty value"}}}
              }).dump(),
            "application/json");
          return;
        }

      std::string error;
      if(preview_)
        {
          Persistence::Preview result;
          int rv;
          rv = Persistence::preview(mount,
                                    g_persistence_roots,
                                    type,
                                    path,
                                    key,
                                    value,
                                    &result,
                                    &error,
                                    remove);
          if(rv < 0)
            {
              _persistence_error(res_,rv,error);
            }
          else
            {
              res_.set_content(json({{"path",result.path},
                                     {"before",result.before},
                                     {"after",result.after},
                                     {"before_line",result.before_line},
                                     {"after_line",result.after_line},
                                     {"config_before",result.config_before},
                                     {"config_after",result.config_after},
                                     {"revision",result.revision},
                                     {"changed",result.changed}}).dump(),
                "application/json");
            }
        }
      else
        {
          std::string revision;
          const std::string *expected = nullptr;
          if(body.contains("expected_revision"))
            {
              revision = body.at("expected_revision").get<std::string>();
              expected = &revision;
            }

          int rv;
          rv = Persistence::save(mount,
                                 g_persistence_roots,
                                 type,
                                 path,
                                 key,
                                 value,
                                 &error,
                                 expected,
                                 remove);
          if(rv < 0)
            _persistence_error(res_,rv,error);
          else
            res_.set_content(json({{"result","success"}}).dump(),"application/json");
        }
    }
  catch(const json::exception &)
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content(json({{"error",{{"msg","invalid persistence request"}}}}).dump(),
                       "application/json");
    }
}


static
void
_post_persistence(const httplib::Request &req_,
                  httplib::Response      &res_)
{
  _post_persistence_request(req_,res_,false);
}


static
void
_post_persistence_preview(const httplib::Request &req_,
                          httplib::Response      &res_)
{
  _post_persistence_request(req_,res_,true);
}


static
void
_post_kvs_key(const httplib::Request &req_,
              httplib::Response      &res_)
{
  if(!req_.has_param("mount"))
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content(json({{"error","mount param not set"}}).dump(),"application/json");
      return;
    }

  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error","authentication required"}}).dump(),"application/json");
      return;
    }

  if(!_require_mergerfs_mount(req_.get_param_value("mount"),res_))
    return;

  try
    {
      int rv;
      std::string mount = req_.get_param_value("mount");
      std::string key   = req_.path_params.at("key");
      std::string value = json::parse(req_.body).get<std::string>();
      rv = _set_kv(mount,key,value);

      if(rv == 0)
        {
          res_.set_content(json({{"result","success"}}).dump(),"application/json");
        }
      else
        {
          res_.status = httplib::StatusCode::BadRequest_400;
          json response = {{"result","error"},{"error",_generate_error(mount,key,value,rv)}};
          res_.set_content(response.dump(),"application/json");
        }
    }
  catch(const std::exception &e_)
    {
      std::fprintf(stderr,"%s\n",e_.what());
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content("invalid json","text/plain");
    }
}


static
int
_running_mount_type(const std::string &mount_,
                    std::string       *type_)
{
  std::lock_guard<std::mutex> lock(g_mounts_mutex);
  FILE *file;
  struct mntent *entry;
  int rv;

  type_->clear();
  file = ::setmntent("/proc/mounts","r");
  if(file == nullptr)
    return -errno;
  while((entry = ::getmntent(file)) != nullptr)
    {
      if(mount_ == entry->mnt_dir)
        *type_ = entry->mnt_type;
    }

  rv = ((::ferror(file)) ? -EIO : 0);
  ::endmntent(file);
  return rv;
}


static
int
_unique_fstab_target(const std::string &fstab_,
                     const std::string &mount_)
{
  FILE   *file;
  size_t  matches = 0;
  struct mntent *entry;
  int rv;

  file = ::setmntent(fstab_.c_str(),"r");
  if(file == nullptr)
    return -errno;
  while((entry = ::getmntent(file)) != nullptr)
    {
      if(mount_ == entry->mnt_dir)
        ++matches;
    }

  rv = ((::ferror(file)) ? -EIO : (matches == 1) ? 0 : -EEXIST);
  ::endmntent(file);
  return rv;
}


static
int
_canonical_mountpoint(const std::string &mount_,
                      std::string       *error_)
{
  if((mount_.empty()) ||
     (mount_[0] != '/') ||
     (mount_.size() >= PATH_MAX) ||
     (mount_.find('\0') != std::string::npos))
    {
      *error_ = "mountpoint must be an absolute existing directory";
      return -EINVAL;
    }

  char canonical[PATH_MAX];
  if(::realpath(mount_.c_str(),canonical) == nullptr)
    {
      *error_ = "cannot resolve mountpoint: " + std::string(::strerror(errno));
      return -errno;
    }

  if(mount_ != canonical)
    {
      *error_ = "mountpoint must use its canonical path (without symlinks)";
      return -EINVAL;
    }

  struct stat metadata;
  if(::stat(canonical,&metadata) < 0)
    {
      *error_ = "cannot inspect mountpoint: " + std::string(::strerror(errno));
      return -errno;
    }

  if(!S_ISDIR(metadata.st_mode))
    {
      *error_ = "mountpoint is not a directory";
      return -ENOTDIR;
    }

  return 0;
}


// Drain both output streams through one pipe, including when a command floods stderr.
// Keep the child as a zombie until the pipe closes so its process-group ID cannot be
// recycled while a descendant still owns the pipe.
static
int
_run_mount_command(const char                     *program_,
                   const std::vector<std::string> &args_,
                   std::string                    *output_)
{
  int    flags;
  int    nullfd;
  int    fork_error;
  int    status = 0;
  int    pipefd[2];
  bool   eof = false;
  pid_t  pid;
  char  *environment[3];
  std::vector<char*> argv;
  std::chrono::steady_clock::time_point deadline;
  static constexpr char path[] =
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
  static constexpr char locale[] = "LC_ALL=C";

  output_->clear();
  if(::pipe2(pipefd,O_CLOEXEC) < 0)
    return -errno;
  flags = ::fcntl(pipefd[0],F_GETFL);
  if((flags < 0) || (::fcntl(pipefd[0],F_SETFL,flags | O_NONBLOCK) < 0))
    {
      int err;
      err = errno;
      ::close(pipefd[0]);
      ::close(pipefd[1]);
      return -err;
    }

  nullfd = ::open("/dev/null",O_RDONLY|O_CLOEXEC);
  if(nullfd < 0)
    {
      int err;
      err = errno;
      ::close(pipefd[0]);
      ::close(pipefd[1]);
      return -err;
    }

  argv.reserve(args_.size() + 2);
  argv.push_back(const_cast<char*>(program_));
  for(const std::string &arg : args_)
    argv.push_back(const_cast<char*>(arg.c_str()));
  argv.push_back(nullptr);
  environment[0] = const_cast<char*>(path);
  environment[1] = const_cast<char*>(locale);
  environment[2] = nullptr;
  pid            = ::fork();
  if(pid == 0)
    {
      static constexpr char message[] = "failed to execute command\n";
      ::close(pipefd[0]);
      if((::setpgid(0,0) < 0) ||
         (::dup2(nullfd,STDIN_FILENO) < 0) ||
         (::dup2(pipefd[1],STDOUT_FILENO) < 0) ||
         (::dup2(pipefd[1],STDERR_FILENO) < 0))
        ::_exit(127);
      ::close(nullfd);
      ::close(pipefd[1]);
      ::execve(program_,argv.data(),environment);
      (void)::write(STDERR_FILENO,message,sizeof(message) - 1);
      ::_exit(127);
    }

  fork_error = errno;
  ::close(nullfd);
  ::close(pipefd[1]);
  if(pid < 0)
    {
      ::close(pipefd[0]);
      return -fork_error;
    }

  (void)::setpgid(pid,pid);

  deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
  for(;;)
    {
      int remaining;
      struct pollfd descriptor;
      std::chrono::steady_clock::time_point now;

      if(!eof)
        {
          char buffer[2048];
          for(int reads = 0; reads < 32; ++reads)
            {
              ssize_t n;
              n = ::read(pipefd[0],buffer,sizeof(buffer));
              if(n > 0)
                {
                  if(output_->size() < 8192)
                    {
                      output_->append(buffer,
                                      std::min(static_cast<size_t>(n),
                                               size_t(8192) - output_->size()));
                    }

                  continue;
                }

              if((n == 0) || ((errno != EAGAIN) && (errno != EINTR)))
                eof = true;
              break;
            }
        }

      // WNOHANG only after EOF; an unreaped leader pins the group ID while
      // descendants with inherited descriptors are still being drained.
      if(eof)
        {
          pid_t rv;
          rv = ::waitpid(pid,&status,WNOHANG);
          if(rv == pid)
            {
              ::close(pipefd[0]);
              if(WIFEXITED(status))
                return WEXITSTATUS(status);
              return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : -EIO;
            }

          if((rv < 0) && (errno != EINTR))
            {
              ::close(pipefd[0]);
              return -errno;
            }
        }

      now = std::chrono::steady_clock::now();
      if(now >= deadline)
        break;
      remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline -
                                                                                         now).count());
      descriptor = {pipefd[0],POLLIN | POLLHUP,0};
      (void)::poll(eof ? nullptr : &descriptor,eof ? 0 : 1,std::min(remaining,200));
    }

  ::close(pipefd[0]);
  (void)::kill(-pid,SIGKILL);
  (void)::kill(pid,SIGKILL);
  if(::waitpid(pid,&status,WNOHANG) == 0)
    {
      std::thread([pid]()
      {
        int child_status;
        while((::waitpid(pid,&child_status,0) < 0) && (errno == EINTR))
          {
          }
      }).detach();
    }

  return -ETIMEDOUT;
}


static
void
_mount_command_error(httplib::Response &res_,
                     const std::string &operation_,
                     int                rv_,
                     std::string        output_)
{
  res_.status = ((rv_ == -ETIMEDOUT) ? 504 : 502);
  while((!output_.empty()) && ((output_.back() == '\n') || (output_.back() == '\r')))
    output_.pop_back();
  if(output_.empty())
    output_ = ((rv_ < 0) ? ::strerror(-rv_) : "exit status " + std::to_string(rv_));
  res_.set_content(json({{"error",{{"msg",operation_ + " failed: " + output_}}}}).dump(),
                   "application/json");
}


static
bool
_is_valid_systemd_unit_name(const std::string &unit_)
{
  static constexpr char mount_suffix[]   = ".mount";
  static constexpr char service_suffix[] = ".service";
  constexpr size_t mount_length   = sizeof(mount_suffix) - 1;
  constexpr size_t service_length = sizeof(service_suffix) - 1;
  const bool valid_suffix =
    (((unit_.size() > mount_length) &&
      (unit_.compare(unit_.size() - mount_length,mount_length,mount_suffix) == 0)) ||
     ((unit_.size() > service_length) &&
      (unit_.compare(unit_.size() - service_length,service_length,service_suffix) == 0)));
  return ((valid_suffix) &&
          (unit_.find_first_not_of("abcdefghijklmnopqrstuvwxyz"
                                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                                   "_.@:\\x-") == std::string::npos));
}


static
bool
_invalid_configured_fstab_path(const std::string &path_,
                               const std::string &fstab_)
{
  return ((path_ != fstab_) ||
          (path_.empty()) ||
          (path_.front() != '/') ||
          (path_.find('\0') != std::string::npos));
}


static
void
_post_mount_action(const httplib::Request &req_,
                   httplib::Response      &res_)
{
  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  try
    {
      int rv;
      std::string error;
      std::string running_type;

      const json body = json::parse(req_.body);
      const std::string action = body.at("action").get<std::string>();
      const std::string mount  = body.at("mountpoint").get<std::string>();
      if((action != "mount") && (action != "umount"))
        {
          _persistence_error(res_,-EINVAL,"unknown mount action");
          return;
        }

      rv = _canonical_mountpoint(mount,&error);
      if(rv < 0)
        {
          _persistence_error(res_,rv,error);
          return;
        }

      // Serialize lifecycle operations, including their fresh /proc/mounts check.
      static std::mutex action_mutex;
      std::lock_guard<std::mutex> lock(action_mutex);
      rv = _running_mount_type(mount,&running_type);
      if(rv < 0)
        {
          _persistence_error(res_,rv,"cannot inspect running mounts");
          return;
        }

      if(action == "umount")
        {
          if(running_type != "fuse.mergerfs")
            {
              _persistence_error(res_,-ENOENT,"mountpoint is not a running mergerfs mount");
              return;
            }

          std::string output;
          rv = _run_mount_command("/usr/bin/umount",{"--",mount},&output);
          if(rv != 0)
            {
              _mount_command_error(res_,"umount",rv,std::move(output));
              return;
            }
        }
      else
        {
          std::vector<Persistence::Source> sources;
          std::string output;
          size_t      matches = 0;

          const std::string type = body.at("source").at("type").get<std::string>();
          const std::string path = body.at("source").at("path").get<std::string>();
          if((type != "fstab") && (type != "systemd"))
            {
              _persistence_error(res_,-EINVAL,"mount requires a fstab or systemd source");
              return;
            }

          if(!running_type.empty())
            {
              _persistence_error(res_,
                                 -EEXIST,
                                 "mountpoint is already mounted (" + running_type + ")");
              return;
            }

          rv = Persistence::discover(mount,g_persistence_roots,&sources,&error);
          if(rv < 0)
            {
              _persistence_error(res_,rv,error);
              return;
            }

          for(const auto &source : sources)
            {
              if((source.type == type) && (source.path == path))
                ++matches;
            }

          if(matches != 1)
            {
              _persistence_error(res_,-ENOENT,"selected mount source is not configured");
              return;
            }

          if(type == "fstab")
            {
              if(_invalid_configured_fstab_path(path,g_persistence_roots.fstab))
                {
                  _persistence_error(res_,-EINVAL,"invalid configured fstab path");
                  return;
                }

              rv = _unique_fstab_target(path,mount);
              if(rv != 0)
                {
                  _persistence_error(res_,
                                     rv,
                                     "fstab must contain exactly one entry for this mountpoint");
                  return;
                }

              rv = _run_mount_command("/usr/bin/mount",{"-T",path,"--",mount},&output);
            }
          else
            {
              char selected[PATH_MAX];
              char loaded[PATH_MAX];
              bool invalid_fragment;
              bool different_source;

              const size_t slash = path.rfind('/');
              if((slash == std::string::npos) || (slash + 1 == path.size()))
                {
                  _persistence_error(res_,-EINVAL,"invalid systemd unit path");
                  return;
                }

              const std::string unit = path.substr(slash + 1);
              if(!_is_valid_systemd_unit_name(unit))
                {
                  _persistence_error(res_,-EINVAL,"invalid systemd unit name");
                  return;
                }

              rv = _run_mount_command(SYSTEMCTL_PATH,
                                      {"show","--property=FragmentPath","--value","--",unit},
                                      &output);
              if(rv != 0)
                {
                  _mount_command_error(res_,"systemctl show",rv,std::move(output));
                  return;
                }

              while((!output.empty()) && ((output.back() == '\n') || (output.back() == '\r')))
                output.pop_back();
              invalid_fragment =
                ((output.empty()) ||
                 (output.find('\n') != std::string::npos) ||
                 (output.find('\0') != std::string::npos) ||
                 (output.size() >= PATH_MAX));
              different_source =
                ((invalid_fragment) ||
                 (::realpath(path.c_str(),selected) == nullptr) ||
                 (::realpath(output.c_str(),loaded) == nullptr) ||
                 (std::strcmp(selected,loaded) != 0));
              if(different_source)
                {
                  _persistence_error(res_,
                                     -ESTALE,
                                     "systemd loaded unit does not match selected source; reload systemd or check configured unit directory");
                  return;
                }

              output.clear();
              rv = _run_mount_command(SYSTEMCTL_PATH,{"start","--",unit},&output);
            }

          if(rv != 0)
            {
              _mount_command_error(res_,
                                   type == "fstab" ? "mount" : "systemctl start",
                                   rv,
                                   std::move(output));
              return;
            }
        }

      res_.set_content(json({{"result","success"},{"action",action},{"mountpoint",mount}}).dump(),
                       "application/json");
    }
  catch(const json::exception &)
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content(json({{"error",{{"msg","invalid mount action request"}}}}).dump(),
                       "application/json");
    }
}


static
void
_update_error(httplib::Response &res_,
              int                err_,
              const std::string &message_)
{
  res_.status =
    ((((err_ == -EAGAIN) || (err_ == -EALREADY))) ?
     409 :
     (((err_ == -EACCES) || (err_ == -EPERM))) ?
     403 :
     (err_ == -EINVAL) ?
     400 :
     (err_ == -ENOTSUP) ?
     422 :
     502);
  res_.set_content(json({{"error",{{"msg",message_}}}}).dump(),"application/json");
}


static
int
_service_spec(const std::string    &host_,
              int                   port_,
              const std::string    &password_file_,
              ServiceInstall::Spec *spec_,
              std::string          *error_)
{
  struct stat      running;
  constexpr size_t default_systemd_directory_count = 2;
  spec_->host          = host_;
  spec_->port          = port_;
  spec_->password_file = password_file_;
  spec_->executable    = ServiceInstall::MANAGED_EXECUTABLE;

  if(::geteuid() != 0)
    {
      return UpdateIO::fail(error_,
                            EACCES,
                            "managing a system service requires running mergerfs-webui as root");
    }

  if((!g_index_html.empty()) ||
     (g_persistence_roots.fstab != "/etc/fstab") ||
     (g_persistence_roots.systemd_dirs.size() != default_systemd_directory_count) ||
     (g_persistence_roots.systemd_dirs[0] != "/etc/systemd/system") ||
     (g_persistence_roots.systemd_dirs[1] != "/usr/lib/systemd/system"))
    {
      return UpdateIO::fail(error_,
                            ENOTSUP,
                            "service setup or removal requires the embedded UI and default persistence paths");
    }

  if((::stat("/run/systemd/system",&running) < 0) ||
     (!S_ISDIR(running.st_mode)) ||
     (::access(SYSTEMCTL_PATH,X_OK) < 0))
    {
      return UpdateIO::fail(error_,
                            ENOTSUP,
                            "systemd is not running or /usr/bin/systemctl is unavailable");
    }

  for(const char *path : {
      "/usr/lib/systemd/system/mergerfs-webui.service",
      "/lib/systemd/system/mergerfs-webui.service",
      "/run/systemd/system/mergerfs-webui.service"
    })
    {
      struct stat st;
      if(::lstat(path,&st) == 0)
        {
          return UpdateIO::fail(error_,
                                EALREADY,
                                "a packaged or runtime mergerfs-webui unit already exists");
        }

      if(errno != ENOENT)
        return UpdateIO::fail(error_,errno,"cannot check other systemd unit locations");
    }

  return 0;
}


static
bool
_local_service_request(const httplib::Request &req_)
{
  const std::string &peer = req_.remote_addr;
  if((peer != "127.0.0.1") && (peer != "::1") && (peer != "::ffff:127.0.0.1"))
    return false;
  {
    const std::string host = req_.get_header_value("Host");
    const size_t colon     = host.rfind(':');
    if((colon == std::string::npos) ||
       ((host.substr(0,colon) != "127.0.0.1") &&
        (host.substr(0,colon) != "localhost") &&
        (host.substr(0,colon) != "[::1]")) ||
       (req_.has_header("Forwarded")) ||
       (req_.has_header("X-Forwarded-For")) ||
       (req_.has_header("Via")))
      return false;
  }

  return true;
}


static
int
_service_command(const std::vector<std::string> &args_,
                 std::string                    *error_)
{
  std::string output;
  std::string command;
  int rv;

  rv = _run_mount_command(SYSTEMCTL_PATH,args_,&output);
  if(rv == 0)
    return 0;
  while((!output.empty()) && ((output.back() == '\n') || (output.back() == '\r')))
    output.pop_back();
  command = "systemctl " + args_.front();
  return UpdateIO::fail(error_,
                        rv < 0 ? -rv : EIO,
                        command + " failed" + (output.empty() ? "" : ": " + output));
}


static
int
_service_main_pid(const std::string &unit_path_,
                  pid_t             *pid_,
                  std::string       *error_)
{
  std::string fragment;
  std::string output;
  char selected[PATH_MAX];
  char loaded[PATH_MAX];
  int  rv;

  rv = _run_mount_command(SYSTEMCTL_PATH,
                          {
                            "show",
                            "--property=FragmentPath",
                            "--value",
                            "--",
                            ServiceInstall::UNIT_NAME
                          },
                          &fragment);
  if(rv != 0)
    {
      return UpdateIO::fail(error_,
                            rv < 0 ? -rv : EIO,
                            "cannot inspect loaded mergerfs-webui service unit");
    }

  while((!fragment.empty()) && ((fragment.back() == '\n') || (fragment.back() == '\r')))
    fragment.pop_back();
  if((fragment.empty()) ||
     (fragment.size() >= PATH_MAX) ||
     (fragment.find('\n') != std::string::npos) ||
     (::realpath(unit_path_.c_str(),selected) == nullptr) ||
     (::realpath(fragment.c_str(),loaded) == nullptr) ||
     (std::strcmp(selected,loaded) != 0))
    {
      return UpdateIO::fail(error_,
                            EALREADY,
                            "systemd has loaded a different service unit; no files were removed");
    }

  rv = _run_mount_command(SYSTEMCTL_PATH,
                          {"show","--property=MainPID","--value","--",ServiceInstall::UNIT_NAME},
                          &output);
  if(rv != 0)
    {
      return UpdateIO::fail(error_,
                            rv < 0 ? -rv : EIO,
                            "cannot inspect running mergerfs-webui service process");
    }

  while((!output.empty()) && ((output.back() == '\n') || (output.back() == '\r')))
    output.pop_back();
  {
    int main_pid      = 0;
    const auto parsed = std::from_chars(output.data(),output.data() + output.size(),main_pid);
    if((parsed.ec != std::errc{}) ||
       (parsed.ptr != output.data() + output.size()) ||
       (main_pid < 0) ||
       (output.empty()))
      {
        return UpdateIO::fail(error_,EIO,"systemd returned an invalid service process ID");
      }

    *pid_ = static_cast<pid_t>(main_pid);
  }

  return 0;
}


static
void
_get_update(const httplib::Request &req_,
            httplib::Response      &res_)
{
  if(!g_update_enabled)
    {
      res_.set_content(json({{"enabled",false}}).dump(),"application/json");
      return;
    }

  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  Update::Release release;
  std::string     error;
  int rv;
  rv = Update::latest(&release,&error);
  if(rv < 0)
    {
      _update_error(res_,rv,error);
    }
  else
    {
      res_.set_content(json({{"enabled",true},
                             {"tag",release.tag},
                             {"asset",release.asset},
                             {"digest",release.digest},
                             {"installed",release.installed},
                             {"running",release.running}}).dump(),
        "application/json");
    }
}


static
void
_post_update(const httplib::Request &req_,
             httplib::Response      &res_)
{
  if(!g_update_enabled)
    {
      _update_error(res_,-ENOTSUP,"updates unavailable for this executable");
      return;
    }

  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  try
    {
      const json body = json::parse(req_.body);
      const std::string tag    = body.at("tag").get<std::string>();
      const std::string digest = body.at("digest").get<std::string>();
      Update::Release release;
      std::string     error;
      int rv;
      rv = Update::install(tag,digest,&release,&error);
      if(rv < 0)
        {
          _update_error(res_,rv,error);
        }
      else
        {
          res_.set_content(json({{"result","success"},
                                 {"tag",release.tag},
                                 {"restart_required",!release.running}}).dump(),
            "application/json");
        }
    }
  catch(const json::exception &)
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content(json({{"error",{{"msg","invalid update request"}}}}).dump(),
                       "application/json");
    }
}


static
void
_get_mergerfs_status(const httplib::Request &req_,
                     httplib::Response      &res_)
{
  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  MergerfsUpdate::Status status;
  std::string error;
  int rv;
  rv = MergerfsUpdate::status(&status,&error);
  if(rv < 0)
    {
      _update_error(res_,rv,error);
    }
  else
    {
      res_.set_content(json({{"state",status.state},
                             {"path",status.path},
                             {"version",status.version},
                             {"manager",status.manager},
                             {"package",status.package},
                             {"static_version",status.static_version},
                             {"in_place_allowed",status.in_place_allowed},
                             {"static_install_allowed",status.static_install_allowed},
                             {"warnings",status.warnings}}).dump(),
        "application/json");
    }
}


static
void
_get_mergerfs_update(const httplib::Request &req_,
                     httplib::Response      &res_)
{
  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  MergerfsUpdate::Release release;
  std::string error;
  int rv;
  rv = MergerfsUpdate::latest(&release,&error);
  if(rv < 0)
    {
      _update_error(res_,rv,error);
    }
  else
    {
      res_.set_content(json({{"tag",release.tag},
                             {"asset",release.asset},
                             {"digest",release.digest},
                             {"size",release.size}}).dump(),
        "application/json");
    }
}


static
void
_post_mergerfs_update(const httplib::Request &req_,
                      httplib::Response      &res_)
{
  if(!_check_auth(req_))
    {
      res_.status = httplib::StatusCode::Unauthorized_401;
      res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                       "application/json");
      return;
    }

  try
    {
      int    rv;
      size_t key_count = 0;
      const auto count_key = [&key_count](int, json::parse_event_t event_, json &)
      {
        if(event_ == json::parse_event_t::key)
          ++key_count;
        return true;
      };
      const json body = json::parse(req_.body,count_key);
      if((!body.is_object()) ||
         (key_count != 3) ||
         (body.size() != 3) ||
         (!body.contains("tag")) ||
         (!body.at("tag").is_string()) ||
         (!body.contains("digest")) ||
         (!body.at("digest").is_string()) ||
         (!body.contains("target")) ||
         (!body.at("target").is_string()))
        {
          _update_error(res_,-EINVAL,"invalid mergerfs update request");
          return;
        }

      const std::string tag    = body.at("tag").get<std::string>();
      const std::string digest = body.at("digest").get<std::string>();
      const std::string target = body.at("target").get<std::string>();
      if((!UpdateIO::safe_tag(tag)) ||
         (!UpdateIO::hex_digest(digest)) ||
         ((target != "existing") &&
          (target != "static")))
        {
          _update_error(res_,-EINVAL,"invalid mergerfs update request");
          return;
        }

      MergerfsUpdate::Result result;
      std::string error;
      rv = MergerfsUpdate::install(tag,digest,target,&result,&error);
      if(rv < 0)
        {
          _update_error(res_,rv,error);
        }
      else
        {
          res_.set_content(json({{"result","success"},
                                 {"tag",tag},
                                 {"path",result.path},
                                 {"warnings",result.warnings}}).dump(),
            "application/json");
        }
    }
  catch(const json::exception &)
    {
      _update_error(res_,-EINVAL,"invalid mergerfs update request");
    }
}


static
void
_get_auth(const httplib::Request &,
          httplib::Response      &res_)
{
  res_.set_content(json({{"password_required",!g_password.empty()},
                         {"updates_enabled",g_update_enabled},
                         {"instance_id",g_instance_id},
                         {"version",VERSION}}).dump(),
    "application/json");
}


static
void
_post_auth_verify(const httplib::Request &req_,
                  httplib::Response      &res_)
{
  try
    {
      json body = json::parse(req_.body);
      std::string password = body.value("password","");
      if(_validate_password(password))
        {
          res_.set_content(json({{"result","success"},{"valid",true}}).dump(),"application/json");
        }
      else
        {
          res_.status = httplib::StatusCode::Unauthorized_401;
          res_.set_content(json({{"result","error"},
                                 {"valid",false},
                                 {"error","Invalid password"}}).dump(),
            "application/json");
        }
    }
  catch(const std::exception &e_)
    {
      std::fprintf(stderr,"%s\n",e_.what());
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content("invalid json","text/plain");
    }
}


static
void
_get_branches_info(const httplib::Request &req_,
                   httplib::Response      &res_)
{
  if(!req_.has_param("mount"))
    {
      res_.status = httplib::StatusCode::BadRequest_400;
      res_.set_content(json({{"error","mount param not set"}}).dump(),"application/json");
      return;
    }

  const std::string &mount = req_.get_param_value("mount");
  if(!_require_mergerfs_mount(mount,res_))
    return;
  std::string branches;
  int rv = _get_kv(mount,"branches",&branches);
  if(rv < 0)
    {
      _config_error(res_,rv);
      return;
    }

  json result = json::array();
  for(size_t start = 0; start < branches.size();)
    {
      size_t end = branches.find(':',start);
      if(end == std::string::npos)
        end = branches.size();
      std::string_view branch(branches.data() + start,end - start);
      size_t equals = branch.find('=');
      std::string      path(branch.substr(0,equals));
      std::string      mode;
      std::string      minfreespace;
      if(equals != std::string_view::npos)
        {
          std::string_view suffix = branch.substr(equals + 1);
          size_t comma = suffix.find(',');
          mode = suffix.substr(0,comma);
          if(comma != std::string_view::npos)
            minfreespace = suffix.substr(comma + 1);
        }

      json item = {{"path",path},{"mode",mode},{"minfreespace",minfreespace}};
      struct statvfs info;
      if(::statvfs(path.c_str(),&info) == 0)
        {
          uint64_t available = uint64_t{info.f_frsize} * info.f_bavail;
          uint64_t used      = uint64_t{info.f_frsize} * (info.f_blocks - info.f_bavail);
          item["total_space"]     = available + used;
          item["used_space"]      = used;
          item["available_space"] = available;
          item["readonly"]        = (info.f_flag & ST_RDONLY) != 0;
        }
      else
        {
          item["total_space"]     = 0;
          item["used_space"]      = 0;
          item["available_space"] = 0;
          item["readonly"]        = false;
          item["error"]           = "Failed to get disk info";
        }

      result.push_back(std::move(item));
      start = end + 1;
    }

  res_.set_content(result.dump(),"application/json");
}


static
bool
_load_password_file(const std::string &path_)
{
  int fd;
  struct stat st;
  fd = ::open(path_.c_str(),O_RDONLY|O_CLOEXEC|O_NONBLOCK);
  if(fd < 0)
    {
      std::cerr << "Cannot open password file " << path_ << ": " << std::strerror(errno) << '\n';
      return false;
    }

  if(::fstat(fd,&st) < 0)
    {
      int err;
      err = errno;
      ::close(fd);
      std::cerr << "Cannot inspect password file " << path_ << ": " << std::strerror(err) << '\n';
      return false;
    }

  if(!S_ISREG(st.st_mode))
    {
      ::close(fd);
      std::cerr << "Password file must be a regular file: " << path_ << '\n';
      return false;
    }

  constexpr size_t MAX_PASSWORD_FILE_BYTES = 4096;
  std::array<char,MAX_PASSWORD_FILE_BYTES + 1> buffer;
  size_t size = 0;
  for(;;)
    {
      ssize_t n;
      if(size == buffer.size())
        {
          ::close(fd);
          std::cerr << "Password file exceeds " << MAX_PASSWORD_FILE_BYTES << " bytes: " <<
            path_ << '\n';
          return false;
        }

      n = ::read(fd,buffer.data() + size,buffer.size() - size);
      if((n < 0) && (errno == EINTR))
        continue;
      if(n < 0)
        {
          int err;
          err = errno;
          ::close(fd);
          std::cerr << "Cannot read password file " << path_ << ": " << std::strerror(err) << '\n';
          return false;
        }

      if(n == 0)
        break;
      size += static_cast<size_t>(n);
    }

  ::close(fd);
  std::string password(buffer.data(),size);
  if((!password.empty()) && (password.back() == '\n'))
    {
      password.pop_back();
      if((!password.empty()) && (password.back() == '\r'))
        password.pop_back();
    }

  if((password.empty()) ||
     (std::any_of(password.begin(),
                  password.end(),
                  [](unsigned char c_)
                  {
                    constexpr unsigned char ASCII_CONTROL_LIMIT = 32;
                    constexpr unsigned char ASCII_DELETE = 127;
                    return ((c_ < ASCII_CONTROL_LIMIT) || (c_ == ASCII_DELETE));
                  })))
    {
      std::cerr <<
        "Password file must contain one nonempty line without control characters: " << path_ << '\n';
      return false;
    }

  g_password = std::move(password);
  return true;
}


static
void
_print_usage(std::ostream &out_)
{
  out_ <<
    "Usage: mergerfs-webui [options]\n" <<
    "A simple web UI to configure mergerfs instances\n\n" <<
    "  --host <address>      Interface to bind to (default: 127.0.0.1)\n" <<
    "  --port <1..65535>     TCP port to use (default: 8080)\n" <<
    "  --password-file <path> Read password from file (one trailing newline removed)\n" <<
    "  --fstab <path>        fstab path (default: /etc/fstab)\n" <<
    "  --systemd-dir <path>  systemd unit directory (overrides defaults)\n" <<
    "  --index.html <path>   Serve a local page for development\n" <<
    "  --version             Show the application version\n" <<
    "  --help                Show this help\n\n" <<
    "Startup editing, updates, and restart are available by default.\n" <<
    "Use --password-file to require authentication for these operations.\n" <<
    "Updates also require /usr/bin/curl, /usr/bin/sha256sum, and write access\n" <<
    "to the executable directory. Restart re-execs the installed binary.\n" <<
    "Setup can copy the running binary to /usr/local/bin or use it in place,\n" <<
    "and install a systemd system service when running as root.\n" <<
    "Choose localhost (127.0.0.1), all IPv4 interfaces (0.0.0.0), or a custom\n" <<
    "listener address, and any service port from 1 to 65535.\n" <<
    "Choose no password, the current password file, or a new password of\n" <<
    "1-128 printable ASCII characters without spaces or controls. Setup\n" <<
    "generates an editable 32-character default; save it before closing the tab.\n" <<
    "These choices are independent; security warnings do not restrict them.\n" <<
    "With no password, anyone who can reach the listener can change settings.\n" <<
    "Plain HTTP does not encrypt passwords; use SSH, TLS, or a VPN as needed.\n" <<
    "Setup can also remove the exact matching systemd unit and disable\n" <<
    "automatic startup. When run by that service, the web UI then exits;\n" <<
    "the installed executable, password file and mergerfs config remain.\n" <<
    "Configuration can edit raw discovered fstab entries, systemd .mount units\n" <<
    "and referenced ini files. Raw saves do not reload systemd or alter live\n" <<
    "mounts; without a password, raw access is localhost-only.\n";
}


static constexpr int MAX_PORT     = 65535;
static constexpr int DEFAULT_PORT = 8080;
static constexpr std::string_view OPTION_PREFIX = "--";


static
bool
_parse_port(std::string_view  value_,
            int              *port_)
{
  int  port;
  auto parsed = std::from_chars(value_.data(),value_.data() + value_.size(),port);
  if((parsed.ec != std::errc{}) ||
     (parsed.ptr != value_.data() + value_.size()) ||
     (port < 1) ||
     (port > MAX_PORT))
    return false;

  *port_ = port;
  return true;
}


enum class ParseResult
{
  RUN,
  SUCCESS,
  FAILURE
};

enum class ValueOption
{
  HOST,
  PORT,
  PASSWORD_FILE,
  INDEX_HTML,
  FSTAB,
  SYSTEMD_DIR,
  UNKNOWN
};


static
ValueOption
_value_option(std::string_view option_)
{
  if(option_ == "--host")
    return ValueOption::HOST;
  if(option_ == "--port")
    return ValueOption::PORT;
  if(option_ == "--password-file")
    return ValueOption::PASSWORD_FILE;
  if(option_ == "--index.html")
    return ValueOption::INDEX_HTML;
  if(option_ == "--fstab")
    return ValueOption::FSTAB;
  if(option_ == "--systemd-dir")
    return ValueOption::SYSTEMD_DIR;
  return ValueOption::UNKNOWN;
}


static
ParseResult
_parse_options(int           argc_,
               char        **argv_,
               std::string  *host_,
               int          *port_,
               bool         *log_,
               std::string  *password_file_)
{
  for(int i = 1; i < argc_; ++i)
    {
      std::string_view option(argv_[i]);
      if(option == "--help")
        {
          _print_usage(std::cout);
          return ParseResult::SUCCESS;
        }

      if(option == "--version")
        {
          std::cout << "mergerfs-webui v" << VERSION << '\n';
          return ParseResult::SUCCESS;
        }

      if(option == "--log")
        {
          *log_ = true;
          continue;
        }

      const ValueOption value_option = _value_option(option);
      if(value_option == ValueOption::UNKNOWN)
        {
          std::cerr << "Unknown option or positional argument: " << option << '\n';
          _print_usage(std::cerr);
          return ParseResult::FAILURE;
        }

      if((++i == argc_) ||
         (std::string_view(argv_[i]).compare(0,OPTION_PREFIX.size(),OPTION_PREFIX) == 0))
        {
          std::cerr << "Missing value for " << option << '\n';
          return ParseResult::FAILURE;
        }

      std::string value(argv_[i]);
      switch(value_option)
        {
        case ValueOption::HOST:
          *host_ = std::move(value);
          break;
        case ValueOption::PASSWORD_FILE:
          if(value.empty())
            {
              std::cerr << "Password file path must not be empty\n";
              return ParseResult::FAILURE;
            }

          *password_file_ = std::move(value);
          break;
        case ValueOption::INDEX_HTML:
          g_index_html = std::move(value);
          break;
        case ValueOption::FSTAB:
          g_persistence_roots.fstab = std::move(value);
          break;
        case ValueOption::SYSTEMD_DIR:
          g_persistence_roots.systemd_dirs = {std::move(value)};
          break;
        case ValueOption::PORT:
          if(!_parse_port(value,port_))
            {
              std::cerr << "Invalid port: " << value << '\n';
              return ParseResult::FAILURE;
            }
          break;
        case ValueOption::UNKNOWN:
          break;
        }
    }

  return ParseResult::RUN;
}


static
void
_get_persistence_raw(const httplib::Request &req_,
                     httplib::Response      &res_)
{
  _raw_persistence_request(req_,res_,false);
}


static
void
_post_persistence_raw(const httplib::Request &req_,
                      httplib::Response      &res_)
{
  _raw_persistence_request(req_,res_,true);
}


static
void
_log_http_request(const httplib::Request  &req_,
                  const httplib::Response &res_)
{
  auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  struct tm time;
  char      timestamp[sizeof("YYYY-MM-DDTHH:MM:SS")];
  ::localtime_r(&now,&time);
  std::strftime(timestamp,sizeof(timestamp),"%Y-%m-%dT%H:%M:%S",&time);
  std::fprintf(stdout,
               "%s %s %s -> %d\n",
               timestamp,
               req_.method.c_str(),
               req_.path.c_str(),
               res_.status);
}


static constexpr char SERVICE_MODE_FIELD[] = "mode";
static constexpr char SERVICE_HOST_FIELD[] = "host";
static constexpr char SERVICE_PORT_FIELD[] = "port";
static constexpr char SERVICE_EXECUTABLE_FIELD[] = "expected_executable";
static constexpr char SERVICE_PASSWORD_MODE_FIELD[] = "password_mode";
static constexpr char SERVICE_PASSWORD_FIELD[] = "password";


static
bool
_valid_service_install_payload(const json &body_)
{
  return ((body_.is_object()) &&
          (body_.contains(SERVICE_PASSWORD_MODE_FIELD)) &&
          (body_[SERVICE_PASSWORD_MODE_FIELD].is_string()) &&
          (body_.contains(SERVICE_MODE_FIELD)) &&
          (body_[SERVICE_MODE_FIELD].is_string()) &&
          (body_.contains(SERVICE_HOST_FIELD)) &&
          (body_[SERVICE_HOST_FIELD].is_string()) &&
          (body_.contains(SERVICE_PORT_FIELD)) &&
          (body_[SERVICE_PORT_FIELD].is_number_integer()) &&
          (body_[SERVICE_PORT_FIELD] >= 1) &&
          (body_[SERVICE_PORT_FIELD] <= MAX_PORT) &&
          (body_.contains(SERVICE_EXECUTABLE_FIELD)) &&
          (body_[SERVICE_EXECUTABLE_FIELD].is_string()));
}


int
main(int    argc_,
     char **argv_)
{
  std::string host = "127.0.0.1";
  int port = DEFAULT_PORT;
  bool log = false;
  std::string password_file;

  switch(_parse_options(argc_,argv_,&host,&port,&log,&password_file))
    {
    case ParseResult::SUCCESS:
      return EXIT_SUCCESS;
    case ParseResult::FAILURE:
      return EXIT_FAILURE;
    case ParseResult::RUN:
      break;
    }

  if((!password_file.empty()) && (!_load_password_file(password_file)))
    return EXIT_FAILURE;

  std::string update_error;
  if(Update::initialize(&update_error) < 0)
    std::cerr << "Updates unavailable: " << update_error << '\n';
  else
    g_update_enabled = true;

  if(!g_password.empty())
    std::cout << "Password authentication enabled\n";
  else
    std::cout << "No password set. Authentication disabled.\n";

  httplib::Server http_server;
  http_server.set_pre_routing_handler(_check_write_request);
  if(log)
    {
      http_server.set_logger(_log_http_request);
    }

  // Keep-alive sockets occupy workers while idle; do not strand both workers for 5s.
  http_server.set_keep_alive_max_count(1);

  http_server.new_task_queue = []() { return new httplib::ThreadPool(2); };

  http_server.Get("/",_get_root);
  http_server.Get("/favicon.ico",_get_favicon);
  http_server.Get("/auth",_get_auth);
  http_server.Post("/auth/verify",_post_auth_verify);
  http_server.Get("/update",_get_update);
  http_server.Post("/update",_post_update);
  http_server.Get("/mergerfs/status",_get_mergerfs_status);
  http_server.Get("/mergerfs/update",_get_mergerfs_update);
  http_server.Post("/mergerfs/update",_post_mergerfs_update);
  std::atomic<bool> restart_requested{false};
  std::atomic<bool> service_start_requested{false};
  std::atomic<bool> service_remove_requested{false};
  std::atomic<bool> service_stop_requested{false};
  std::mutex service_mutex;
  const std::string service_path =
    std::string(ServiceInstall::UNIT_DIRECTORY) + "/" + ServiceInstall::UNIT_NAME;
  const auto service_status = [&](const httplib::Request &req_,
                                  httplib::Response      &res_)
  {
    if(!_check_auth(req_))
      {
        res_.status = httplib::StatusCode::Unauthorized_401;
        res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                         "application/json");
        return;
      }

    ServiceInstall::Spec spec;
    std::string error;
    int rv = _service_spec(host,port,password_file,&spec,&error);
    std::string running_path;
    std::string running_error;
    const int running_rv = ServiceInstall::runnable_running_executable(&running_path,&running_error);
    bool installed = false;
    bool enabled   = false;
    bool active    = false;
    if(rv == 0)
      rv = ServiceInstall::inspect(ServiceInstall::UNIT_DIRECTORY,&spec,&installed,&error);
    const bool password_retry = installed &&
      spec.password_file == ServiceInstall::MANAGED_PASSWORD &&
      password_file != ServiceInstall::MANAGED_PASSWORD;
    const std::string &credential = installed ? spec.password_file : password_file;
    const std::string password_mode = credential.empty() ? "none" :
      credential == password_file ? "current" : "new";
    const std::string unit_mode = spec.executable == ServiceInstall::MANAGED_EXECUTABLE ?
      "install" : "running";

    if((rv == 0) && (installed))
      {
        std::string output;
        enabled = _run_mount_command(SYSTEMCTL_PATH,
                                     {"is-enabled","--quiet","--",ServiceInstall::UNIT_NAME},
                                     &output) == 0;
        output.clear();
        active = _run_mount_command(SYSTEMCTL_PATH,
                                    {"is-active","--quiet","--",ServiceInstall::UNIT_NAME},
                                    &output) == 0;
      }

    res_.set_content(json({{"installed",installed},
                           {"enabled",enabled},
                           {"active",active},
                           {"available",rv == 0},
                           {"bootstrap",password_file.empty()},
                           {"password_retry",password_retry},
                           {"path",service_path},
                           {"host",installed ? spec.host : host},
                           {"port",installed ? spec.port : port},
                           {"password_file",password_file},
                           {"password_mode",password_mode},
                           {
                             "executable",
                             (installed) ?
                             spec.executable :
                             ServiceInstall::MANAGED_EXECUTABLE
                           },
                           {"unit_mode",installed ? unit_mode : ""},
                           {"running_executable",running_path},
                           {"running_available",running_rv == 0},
                           {"running_reason",running_rv == 0 ? "" : running_error},
                           {"reason",rv == 0 ? "" : error}}).dump(),
      "application/json");
  };
  http_server.Get("/service/status",service_status);
  const auto service_install = [&](const httplib::Request &req_,
                                   httplib::Response      &res_)
  {
    if(!_check_auth(req_))
      {
        res_.status = httplib::StatusCode::Unauthorized_401;
        res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                         "application/json");
        return;
      }

    std::lock_guard<std::mutex> lock(service_mutex);
    if((restart_requested.load()) ||
       (service_start_requested.load()) ||
       (service_remove_requested.load()) ||
       (service_stop_requested.load()))
      {
        _update_error(res_,-EALREADY,"service transition already in progress");
        return;
      }

    json body;
    try
      {
        body = json::parse(req_.body);
      }
    catch(const json::exception &)
      {
        _update_error(res_,-EINVAL,"choose the service binding, executable and password policy");
        return;
      }

    if(!_valid_service_install_payload(body))
      {
        _update_error(res_,
                      -EINVAL,
                      "choose a service executable mode, port from 1 to 65535, and password policy");
        return;
      }

    const std::string mode = body[SERVICE_MODE_FIELD].get<std::string>();
    if((mode != "install") && (mode != "running"))
      {
        _update_error(res_,-EINVAL,"service executable mode must be install or running");
        return;
      }

    const std::string password_mode = body[SERVICE_PASSWORD_MODE_FIELD].get<std::string>();
    if(((password_mode != "none") &&
        (password_mode != "current") &&
        (password_mode != "new")) ||
       ((password_mode == "new") ?
        ((body.size() != 6) ||
         (!body.contains(SERVICE_PASSWORD_FIELD)) ||
         (!body[SERVICE_PASSWORD_FIELD].is_string())) :
        (body.size() != 5)))
      {
        _update_error(res_,-EINVAL,"choose none, current or new authentication; only new accepts a password");
        return;
      }

    const std::string *setup_password = nullptr;
    if(password_mode == "new")
      {
        const std::string &secret = body[SERVICE_PASSWORD_FIELD].get_ref<const std::string&>();
        const auto printable = [](unsigned char c_) { return c_ >= 33 && c_ <= 126; };
        if((secret.empty()) ||
           (secret.size() > 128) ||
           (!std::all_of(secret.begin(),secret.end(),printable)))
          {
            _update_error(res_,-EINVAL,"password must be 1 to 128 printable ASCII characters without spaces");
            return;
          }

        setup_password = &secret;
      }

    ServiceInstall::Spec spec;
    std::string error;
    spec.host = body[SERVICE_HOST_FIELD].get<std::string>();
    spec.port = body[SERVICE_PORT_FIELD].get<int>();
    spec.executable = body[SERVICE_EXECUTABLE_FIELD].get<std::string>();
    spec.password_file = password_mode == "none" ? "" :
      password_mode == "current" ? password_file : ServiceInstall::MANAGED_PASSWORD;
    int rv = ServiceInstall::validate_arguments(spec,&error);
    ServiceInstall::Spec installed_spec;
    bool installed = false;
    int inspect_rv = 0;
    if(rv == 0)
      inspect_rv = ServiceInstall::inspect(ServiceInstall::UNIT_DIRECTORY,
                                           &installed_spec,&installed,&error);
    if((password_mode == "current") &&
       ((installed ? installed_spec.password_file : password_file).empty()))
      {
        _update_error(res_,-EINVAL,"there is no existing password file to reuse");
        return;
      }

    if((rv == 0) && (password_mode == "current") && installed)
      spec.password_file = installed_spec.password_file;

    if(rv == 0)
      rv = _service_spec(spec.host,spec.port,spec.password_file,&spec,&error);
    if(rv < 0)
      {
        _update_error(res_,rv == -EEXIST ? -EALREADY : rv,error);
        return;
      }

    if(inspect_rv < 0)
      {
        _update_error(res_,inspect_rv == -EEXIST ? -EALREADY : inspect_rv,error);
        return;
      }

    if(installed && setup_password)
      {
        _update_error(res_,-EALREADY,"remove the installed unit before choosing a new password");
        return;
      }

    if(installed &&
       (mode != (installed_spec.executable == ServiceInstall::MANAGED_EXECUTABLE ?
                 "install" : "running")))
      {
        _update_error(res_,-EALREADY,"remove the installed unit before changing executable mode");
        return;
      }

    if(mode == "running")
      {
        if(installed)
          spec.executable = installed_spec.executable;
        else
          rv = ServiceInstall::runnable_running_executable(&spec.executable,&error);
        if(rv < 0)
          {
            _update_error(res_,rv,error);
            return;
          }
      }

    if(body[SERVICE_EXECUTABLE_FIELD].get<std::string>() != spec.executable)
      {
        _update_error(res_,
                      -EALREADY,
                      "service executable destination changed; refresh Setup and confirm again");
        return;
      }

    rv = ServiceInstall::existing(spec,ServiceInstall::UNIT_DIRECTORY,&installed,&error);
    if(rv < 0)
      {
        _update_error(res_,rv == -EEXIST ? -EALREADY : rv,error);
        return;
      }

    if((mode == "install") && (!installed))
      {
        bool staged = false;
        rv = ServiceInstall::stage_executable("/proc/self/exe",
                                              ServiceInstall::MANAGED_EXECUTABLE,
                                              &staged,
                                              &error);
        if(rv < 0)
          {
            _update_error(res_,rv == -EEXIST ? -EALREADY : rv,error);
            return;
          }
      }

    if(setup_password)
      {
        bool created_password = false;
        rv = ServiceInstall::create_password(ServiceInstall::MANAGED_PASSWORD_DIRECTORY,
                                             *setup_password,
                                             &created_password,
                                             &error);
        if(rv < 0)
          {
            _update_error(res_,rv == -EEXIST ? -EALREADY : rv,error);
            return;
          }
      }

    const auto install_error = [&](int code_,const std::string &message_)
    {
      _update_error(res_,code_,message_);
      if(setup_password)
        {
          res_.set_header("Cache-Control","no-store");
          res_.set_content(json({{"error",{{"msg",message_}}},
                                 {"password",*setup_password}}).dump(),
            "application/json");
        }
    };
    rv = ServiceInstall::validate(spec,&error);
    if(rv < 0)
      {
        install_error(rv,error);
        return;
      }

    bool created = false;
    rv = ServiceInstall::write_unit(spec,ServiceInstall::UNIT_DIRECTORY,&created,&error);
    if(rv < 0)
      {
        install_error(rv == -EEXIST ? -EALREADY : rv,error);
        return;
      }

    rv = _service_command({"daemon-reload"},&error);
    if(rv == 0)
      rv = _service_command({"enable","--",ServiceInstall::UNIT_NAME},&error);
    if(rv < 0)
      {
        install_error(rv,error + (created ? "; unit file remains for retry" : ""));
        return;
      }

    const std::string destination_password_mode = spec.password_file.empty() ? "none" :
      spec.password_file == password_file ? "current" : "new";

    std::string output;
    int active = _run_mount_command(SYSTEMCTL_PATH,
                                    {"is-active","--quiet","--",ServiceInstall::UNIT_NAME},
                                    &output);
    if(active == 0)
      {
        json result = {{"result","active"},{"path",service_path},{"host",spec.host},
                       {"port",spec.port},{"password_mode",destination_password_mode}};
        if(setup_password)
          {
            result["password"] = *setup_password;
            res_.set_header("Cache-Control","no-store");
          }

        res_.set_content(result.dump(),"application/json");
        return;
      }

    if(active != 3)
      {
        install_error(-EIO,"cannot determine whether the enabled service is active");
        return;
      }

    service_start_requested = true;
    res_.status             = httplib::StatusCode::Accepted_202;
    res_.set_header("Connection","close");
    json result = {{"result","starting"},{"path",service_path},{"host",spec.host},
                   {"port",spec.port},{"password_mode",destination_password_mode}};
    if(setup_password)
      {
        result["password"] = *setup_password;
        res_.set_header("Cache-Control","no-store");
      }

    res_.set_content(result.dump(),"application/json");
    // Finish the response and release the listening socket before systemctl start.
    http_server.stop();
  };
  http_server.Post("/service/install",service_install);
  const auto service_remove = [&](const httplib::Request &req_,
                                  httplib::Response      &res_)
  {
    if(!_check_auth(req_))
      {
        res_.status = httplib::StatusCode::Unauthorized_401;
        res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                         "application/json");
        return;
      }

    std::lock_guard<std::mutex> lock(service_mutex);
    if((restart_requested.load()) ||
       (service_start_requested.load()) ||
       (service_remove_requested.load()) ||
       (service_stop_requested.load()))
      {
        _update_error(res_,-EALREADY,"a service transition is already in progress");
        return;
      }

    if(!req_.body.empty())
      {
        _update_error(res_,-EINVAL,"service removal request must be empty");
        return;
      }

    ServiceInstall::Spec spec;
    std::string error;
    int rv = _service_spec(host,port,password_file,&spec,&error);
    if(rv < 0)
      {
        _update_error(res_,rv,error);
        return;
      }

    bool installed = false;
    rv = ServiceInstall::inspect(ServiceInstall::UNIT_DIRECTORY,&spec,&installed,&error);

    if((rv < 0) || (!installed))
      {
        _update_error(res_,
                      -EALREADY,
                      rv < 0 ? error : "no matching mergerfs-webui service is installed");
        return;
      }

    pid_t main_pid = 0;
    rv = _service_main_pid(service_path,&main_pid,&error);
    if(rv < 0)
      {
        _update_error(res_,rv,error);
        return;
      }

    if((main_pid != 0) && (main_pid != ::getpid()))
      {
        _update_error(res_,
                      -EALREADY,
                      "another mergerfs-webui service process is running; no files were removed");
        return;
      }

    rv = _service_command({"disable","--",ServiceInstall::UNIT_NAME},&error);
    if(rv < 0)
      {
        _update_error(res_,rv,error + "; service files were not removed");
        return;
      }

    rv = ServiceInstall::remove_unit(spec,ServiceInstall::UNIT_DIRECTORY,&error);
    if(rv < 0)
      {
        _update_error(res_,
                      ((rv == -EEXIST) || (rv == -ENOENT) || (rv == -EAGAIN)) ?
                      -EALREADY :
                      rv,
                      "automatic startup was disabled, but service removal did not complete: " +
                      error);
        return;
      }

    rv = _service_command({"daemon-reload"},&error);
    if(rv < 0)
      {
        _update_error(res_,rv,"service file was removed, but systemd could not reload: " + error);
        return;
      }

    const bool stopping = main_pid == ::getpid();
    res_.status = (stopping ? httplib::StatusCode::Accepted_202 : httplib::StatusCode::OK_200);
    res_.set_content(json({{"result","removed"},
                           {"stopping",stopping},
                           {"path",service_path}}).dump(),
      "application/json");
    if(stopping)
      {
        service_remove_requested = true;
        res_.set_header("Connection","close");
        // Finish the response before this service's main process exits cleanly.
        http_server.stop();
      }
  };
  http_server.Delete("/service",service_remove);
  const auto service_stop = [&](const httplib::Request &req_,
                                httplib::Response      &res_)
  {
    if(!_check_auth(req_))
      {
        res_.status = httplib::StatusCode::Unauthorized_401;
        res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                         "application/json");
        return;
      }

    std::lock_guard<std::mutex> lock(service_mutex);
    if((restart_requested.load()) ||
       (service_start_requested.load()) ||
       (service_remove_requested.load()) ||
       (service_stop_requested.load()))
      {
        _update_error(res_,-EALREADY,"a service transition is already in progress");
        return;
      }

    if(!req_.body.empty())
      {
        _update_error(res_,-EINVAL,"service stop request must be empty");
        return;
      }

    ServiceInstall::Spec spec;
    std::string error;
    int rv = _service_spec(host,port,password_file,&spec,&error);
    if(rv < 0)
      {
        _update_error(res_,rv,error);
        return;
      }

    bool installed = false;
    rv = ServiceInstall::inspect(ServiceInstall::UNIT_DIRECTORY,&spec,&installed,&error);
    if((rv < 0) || (!installed))
      {
        _update_error(res_,
                      -EALREADY,
                      rv < 0 ? error : "no matching mergerfs-webui service is installed");
        return;
      }

    pid_t main_pid = 0;
    rv = _service_main_pid(service_path,&main_pid,&error);
    if(rv < 0)
      {
        _update_error(res_,rv,error);
        return;
      }

    std::string output;
    rv = _run_mount_command(SYSTEMCTL_PATH,
                            {"is-active","--quiet","--",ServiceInstall::UNIT_NAME},
                            &output);
    if((rv == 3) || ((rv == 0) && (main_pid == 0)))
      {
        _update_error(res_,-EALREADY,"the managed mergerfs-webui service is not active");
        return;
      }

    if(rv != 0)
      {
        _update_error(res_,-EIO,"cannot determine whether the managed service is active");
        return;
      }

    const bool stopping = main_pid == ::getpid();
    if(!stopping)
      {
        rv = _service_command({"stop","--",ServiceInstall::UNIT_NAME},&error);
        if(rv < 0)
          {
            _update_error(res_,rv,error);
            return;
          }
      }

    res_.status = (stopping ? httplib::StatusCode::Accepted_202 : httplib::StatusCode::OK_200);
    res_.set_content(json({{"result",stopping ? "stopping" : "stopped"},
                           {"stopping",stopping},
                           {"path",service_path}}).dump(),
      "application/json");
    if(stopping)
      {
        service_stop_requested = true;
        res_.set_header("Connection","close");
        // Finish the response before the managed MainPID exits successfully.
        http_server.stop();
      }
  };
  http_server.Post("/service/stop",service_stop);
  const auto restart = [&](const httplib::Request &req_,
                           httplib::Response      &res_)
  {
    if(!_check_auth(req_))
      {
        res_.status = httplib::StatusCode::Unauthorized_401;
        res_.set_content(json({{"error",{{"msg","authentication required"}}}}).dump(),
                         "application/json");
        return;
      }

    std::lock_guard<std::mutex> lock(service_mutex);
    if((restart_requested.load()) ||
       (service_start_requested.load()) ||
       (service_remove_requested.load()) ||
       (service_stop_requested.load()))
      {
        _update_error(res_,-EALREADY,"restart is already in progress");
        return;
      }

    std::string error;
    int rv = Update::restart_ready(&error);
    if(rv < 0)
      {
        _update_error(res_,rv,error);
        return;
      }

    if(restart_requested.exchange(true))
      {
        _update_error(res_,-EALREADY,"restart is already in progress");
        return;
      }

    res_.status = httplib::StatusCode::Accepted_202;
    res_.set_header("Connection","close");
    res_.set_content(json({{"result","restarting"}}).dump(),"application/json");
    // listen() joins workers after stop(); exec happens only after this response is sent.
    http_server.stop();
  };
  http_server.Post("/restart",restart);
  http_server.Get("/mounts",_get_mounts);
  http_server.Get("/mounts/mergerfs",_get_mounts_mergerfs);
  http_server.Get("/kvs",_get_kvs_route);
  http_server.Get("/kvs/:key",_get_kvs_key);
  http_server.Post("/kvs/:key",_post_kvs_key);
  http_server.Get("/persistence",_get_persistence);
  http_server.Post("/persistence",_post_persistence);
  http_server.Post("/persistence/preview",_post_persistence_preview);
  http_server.Get("/persistence/raw",_get_persistence_raw);
  http_server.Post("/persistence/raw",_post_persistence_raw);
  http_server.Get("/mount-definitions",_get_mount_definitions);
  http_server.Get("/mount-definitions/capabilities",_get_mount_definition_capabilities);
  http_server.Get("/directories",_get_directories);
  http_server.Post("/mount-definitions",_post_mount_definition);
  http_server.Delete("/mount-definitions",_delete_mount_definition);
  http_server.Post("/mount-actions",_post_mount_action);
  http_server.Get("/branches-info",_get_branches_info);

  std::cout << "host:port = http://" << host << ':' << port << std::endl;
  for(;;)
    {
      if(!http_server.listen(host,port))
        {
          std::cerr << "Failed to bind/listen on " << host << ':' << port << '\n';
          return EXIT_FAILURE;
        }

      if((service_remove_requested.load()) || (service_stop_requested.load()))
        return EXIT_SUCCESS;
      if(service_start_requested.load())
        {
          std::string error;
          if(_service_command({"start","--",ServiceInstall::UNIT_NAME},&error) == 0)
            return EXIT_SUCCESS;
          std::cerr << "Could not start mergerfs-webui.service; resuming foreground server: " <<
            error << '\n';
          service_start_requested = false;
          continue;
        }

      if(!restart_requested.load())
        return EXIT_SUCCESS;
      std::string error;
      if(Update::reexec(argc_,argv_,&error) < 0)
        std::cerr << "Restart failed; resuming the current binary: " << error << '\n';
      restart_requested = false;
    }
}
