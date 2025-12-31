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

#include "persistence.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <set>
#include <string_view>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace Persistence
{
  namespace
  {
    constexpr size_t MAX_FILE_SIZE    = 8 * 1024 * 1024;
    constexpr size_t READ_BUFFER_SIZE = 8192;
    constexpr int TEMP_FILE_ATTEMPTS  = 32;
    constexpr size_t NPOS = std::string::npos;
    std::mutex save_mutex;

    struct FD
    {
      int value = -1;
      explicit
      FD(int fd = -1)
        : value(fd)
      {
      }
      ~FD() { if(value >= 0) ::close(value); }
      FD(const FD &) = delete;
      FD &operator=(const FD &) = delete;
    };

    struct DirectoryStreamCloser
    {
      void operator()(DIR *stream) const { ::closedir(stream); }
    };

    struct Document
    {
      FD dir;
      FD file;
      std::string name;
      std::string text;
      struct stat metadata = {};
    };

    struct Token
    {
      std::string value;
      size_t begin = 0;
      size_t end = 0;
    };

    struct Line
    {
      std::string_view text;
      size_t offset;
    };

    struct Match
    {
      Source source;
      size_t begin = 0;
      size_t end = 0;
      size_t branch_begin = 0;
      size_t branch_end = 0;
      bool located = false;
      std::string replacement;
    };


    int
    fail(std::string       *error,
         int                code,
         const std::string &message)
    {
      if(error)
        *error = message;
      return -code;
    }


    bool
    space(char c)
    {
      return ((c == ' ') || (c == '\t') || (c == '\r'));
    }


    std::string_view
    trim(std::string_view text)
    {
      while((!text.empty()) && (space(text.front())))
        text.remove_prefix(1);
      while((!text.empty()) && (space(text.back())))
        text.remove_suffix(1);
      return text;
    }


    bool
    safe_key(std::string_view key)
    {
      if((key.empty()) ||
         (key == "version") ||
         (key == "branches") ||
         (key == "config") ||
         (key == "mountpoint") ||
         (key.substr(0,4) == "cmd."))
        return false;
      for(char c : key)
        {
          if((!std::isalnum(static_cast<unsigned char>(c))) &&
             (c != '.') &&
             (c != '_') &&
             (c != '-'))
            return false;
        }

      return true;
    }


    bool
    safe_value(std::string_view value)
    {
      for(unsigned char c : value)
        {
          if((c < 33) ||
             (c > 126) ||
             (c == ',') ||
             (c == '#') ||
             (c == '%') ||
             (c == '$') ||
             (c == ';') ||
             (c == '\\') ||
             (c == '"') ||
             (c == '\''))
            return false;
        }

      return true;
    }


    bool
    safe_branches(std::string_view value)
    {
      // Branch mode suffixes use commas; a branch is still one fstab/ExecStart word.
      if(value.empty())
        return false;
      for(unsigned char c : value)
        {
          if((c < 33) ||
             (c > 126) ||
             (c == '#') ||
             (c == '%') ||
             (c == '$') ||
             (c == ';') ||
             (c == '\\') ||
             (c == '"') ||
             (c == '\''))
            return false;
        }

      return true;
    }


    bool
    contains_mount_reference(std::string_view text,
                             std::string_view mount)
    {
      for(size_t start = text.find(mount); start != NPOS; start = text.find(mount,start + 1))
        {
          const size_t end = start + mount.size();
          const bool left =
            ((start == 0) ||
             (space(text[start - 1])) ||
             (text[start - 1] == '=') ||
             (text[start - 1] == '"') ||
             (text[start - 1] == '\''));
          const bool right =
            ((end == text.size()) ||
             (space(text[end])) ||
             (text[end] == '"') ||
             (text[end] == '\''));
          if((left) && (right))
            return true;
        }

      return false;
    }


    int
    open_directory(const std::string &path,
                   FD                *dir,
                   std::string       *error,
                   bool               create_missing = false)
    {
      if((path.empty()) || (path.front() != '/'))
        return fail(error,EINVAL,"persistence path must be absolute");
      FD current(::open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC));
      if(current.value < 0)
        return fail(error,errno,"cannot open filesystem root");
      size_t pos = 1;
      while(pos < path.size())
        {
          size_t end = path.find('/',pos);
          if(end == NPOS)
            end = path.size();
          const std::string part = path.substr(pos,end - pos);
          if((part.empty()) || (part == ".") || (part == ".."))
            return fail(error,EINVAL,"non-canonical persistence path: " + path);
          int next = ::openat(current.value,part.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
          if((next < 0) && (errno == ENOENT) && (create_missing))
            {
              if((::mkdirat(current.value,part.c_str(),0755) < 0) && (errno != EEXIST))
                return fail(error,errno,"cannot create persistence directory: " + path);
              next = ::openat(current.value,part.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            }

          if(next < 0)
            return fail(error,errno,"cannot open persistence directory without symlinks: " + path);
          ::close(current.value);
          current.value = next;
          pos           = end + 1;
        }

      dir->value    = current.value;
      current.value = -1;
      return 0;
    }


    int
    open_document(const std::string &path,
                  Document          *doc,
                  std::string       *error)
    {
      const size_t slash = path.rfind('/');
      if((slash == NPOS) ||
         (slash + 1 == path.size()) ||
         (path.substr(slash + 1) == ".") ||
         (path.substr(slash + 1) == ".."))
        return fail(error,EINVAL,"invalid persistence file path: " + path);
      const std::string directory = (slash) ? path.substr(0,slash) : "/";
      int rc = open_directory(directory,&doc->dir,error);
      if(rc)
        return rc;
      doc->name = path.substr(slash + 1);
      doc->file.value =
      ::openat(doc->dir.value,doc->name.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
      if(doc->file.value < 0)
        return fail(error,errno,"cannot open persistence file without symlinks: " + path);
      if(::fstat(doc->file.value,&doc->metadata) < 0)
        return fail(error,errno,"cannot stat persistence file: " + path);
      if((!S_ISREG(doc->metadata.st_mode)) ||
         (doc->metadata.st_nlink != 1) ||
         (doc->metadata.st_size < 0) ||
         (static_cast<uint64_t>(doc->metadata.st_size) > MAX_FILE_SIZE))
        {
          return fail(error,
                      EINVAL,
                      "persistence source is not a regular, singly linked, bounded file: " + path);
        }

      char buffer[READ_BUFFER_SIZE];
      for(;;)
        {
          ssize_t n = ::read(doc->file.value,buffer,sizeof(buffer));
          if((n < 0) && (errno == EINTR))
            continue;
          if(n < 0)
            return fail(error,errno,"cannot read persistence file: " + path);
          if(n == 0)
            break;
          if(doc->text.size() + static_cast<size_t>(n) > MAX_FILE_SIZE)
            return fail(error,EFBIG,"persistence file exceeds size limit: " + path);
          doc->text.append(buffer,static_cast<size_t>(n));
        }

      for(unsigned char c : doc->text)
        {
          if((c == 0) || ((c < 32) && (c != '\n') && (c != '\r') && (c != '\t')))
            return fail(error,EINVAL,"malformed control character in persistence file: " + path);
        }

      struct stat after;
      if(::fstat(doc->file.value,&after) < 0)
        return fail(error,errno,"cannot stat persistence file: " + path);
      if((after.st_size != static_cast<off_t>(doc->text.size())) ||
         (after.st_mtim.tv_sec != doc->metadata.st_mtim.tv_sec) ||
         (after.st_mtim.tv_nsec != doc->metadata.st_mtim.tv_nsec) ||
         (after.st_ctim.tv_sec != doc->metadata.st_ctim.tv_sec) ||
         (after.st_ctim.tv_nsec != doc->metadata.st_ctim.tv_nsec))
        return fail(error,EAGAIN,"persistence file changed while reading: " + path);
      return 0;
    }


    bool
    same_file(const struct stat &a,
              const struct stat &b)
    {
      return ((a.st_dev == b.st_dev) &&
              (a.st_ino == b.st_ino) &&
              (a.st_nlink == b.st_nlink) &&
              (a.st_size == b.st_size) &&
              (a.st_mode == b.st_mode) &&
              (a.st_uid == b.st_uid) &&
              (a.st_gid == b.st_gid) &&
              (a.st_mtim.tv_sec == b.st_mtim.tv_sec) &&
              (a.st_mtim.tv_nsec == b.st_mtim.tv_nsec) &&
              (a.st_ctim.tv_sec == b.st_ctim.tv_sec) &&
              (a.st_ctim.tv_nsec == b.st_ctim.tv_nsec));
    }


    int
    replace_document(Document          *doc,
                     const std::string &text,
                     std::string       *error)
    {
      if(text.size() > MAX_FILE_SIZE)
        return fail(error,EFBIG,"updated persistence file exceeds size limit");
      std::string temporary;
      FD out;
      static std::atomic<unsigned> sequence{0};
      for(int attempt = 0; attempt < TEMP_FILE_ATTEMPTS; ++attempt)
        {
          temporary = "." +
            doc->name +
            ".mergerfs-webui-" +
            std::to_string(::getpid()) +
            "-" +
            std::to_string(++sequence);
          out.value = ::openat(doc->dir.value,
                               temporary.c_str(),
                               O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,
                               0600);
          if(out.value >= 0)
            break;
          if(errno != EEXIST)
            return fail(error,errno,"cannot create temporary persistence file");
        }

      if(out.value < 0)
        return fail(error,EEXIST,"cannot reserve temporary persistence file");
      const auto abort = [&]() { ::unlinkat(doc->dir.value,temporary.c_str(),0); };
      if((::fchown(out.value,doc->metadata.st_uid,doc->metadata.st_gid) < 0) ||
         (::fchmod(out.value,doc->metadata.st_mode & 07777) < 0))
        {
          int saved = errno;
          abort();
          return fail(error,saved,"cannot preserve persistence file ownership or mode");
        }

      ssize_t names_length = ::flistxattr(doc->file.value,nullptr,0);
      if((names_length < 0) || (names_length > static_cast<ssize_t>(MAX_FILE_SIZE)))
        {
          int saved = (names_length < 0) ? errno : EFBIG;
          abort();
          return fail(error,saved,"cannot list persistence file extended attributes");
        }

      std::string names(static_cast<size_t>(names_length),'\0');
      if((names_length) && (::flistxattr(doc->file.value,&names[0],names.size()) != names_length))
        {
          int saved = (errno) ? errno : EAGAIN;
          abort();
          return fail(error,saved,"persistence file attributes changed while reading");
        }

      for(size_t begin = 0; begin < names.size();)
        {
          size_t end = names.find('\0',begin);
          if(end == NPOS)
            {
              abort();
              return fail(error,EINVAL,"malformed persistence file attribute list");
            }

          std::string name = names.substr(begin,end - begin);
          ssize_t size     = ::fgetxattr(doc->file.value,name.c_str(),nullptr,0);
          if((size < 0) || (size > static_cast<ssize_t>(MAX_FILE_SIZE)))
            {
              int saved = (size < 0) ? errno : EFBIG;
              abort();
              return fail(error,saved,"cannot read persistence file attribute: " + name);
            }

          std::string data(static_cast<size_t>(size),'\0');
          if((::fgetxattr(doc->file.value,name.c_str(),data.data(),data.size()) != size) ||
             (::fsetxattr(out.value,name.c_str(),data.data(),data.size(),0) < 0))
            {
              int saved = (errno) ? errno : EAGAIN;
              abort();
              return fail(error,saved,"cannot preserve persistence file attribute: " + name);
            }

          begin = end + 1;
        }

      size_t written = 0;
      while(written < text.size())
        {
          ssize_t n = ::write(out.value,text.data() + written,text.size() - written);
          if((n < 0) && (errno == EINTR))
            continue;
          if(n <= 0)
            {
              int saved = (n < 0) ? errno : EIO;
              abort();
              return fail(error,saved,"cannot write temporary persistence file");
            }

          written += static_cast<size_t>(n);
        }

      if(::fsync(out.value) < 0)
        {
          int saved = errno;
          abort();
          return fail(error,saved,"cannot sync temporary persistence file");
        }

      struct stat current;
      if((::fstat(doc->file.value,&current) < 0) ||
         (!same_file(current,doc->metadata)) ||
         (::fstatat(doc->dir.value,doc->name.c_str(),&current,AT_SYMLINK_NOFOLLOW) < 0) ||
         (!same_file(current,doc->metadata)))
        {
          abort();
          return fail(error,EAGAIN,"persistence file changed before replacement");
        }

      if(::renameat(doc->dir.value,temporary.c_str(),doc->dir.value,doc->name.c_str()) < 0)
        {
          int saved = errno;
          abort();
          return fail(error,saved,"cannot atomically replace persistence file");
        }

      if(::fsync(doc->dir.value) < 0)
        return fail(error,errno,"persistence file replaced but directory sync failed");
      return 0;
    }


    int
    unlink_document(Document    *doc,
                    std::string *error)
    {
      struct stat current;
      if((::fstat(doc->file.value,&current) < 0) ||
         (!same_file(current,doc->metadata)) ||
         (::fstatat(doc->dir.value,doc->name.c_str(),&current,AT_SYMLINK_NOFOLLOW) < 0) ||
         (!same_file(current,doc->metadata)))
        return fail(error,EAGAIN,"persistence file changed before removal");
      if(::unlinkat(doc->dir.value,doc->name.c_str(),0) < 0)
        return fail(error,errno,"cannot remove persistence file: " + doc->name);
      if(::fsync(doc->dir.value) < 0)
        return fail(error,errno,"persistence file removed but directory sync failed");
      return 0;
    }


    template<typename F>
    int
    each_line(const std::string &text,
              F                  callback)
    {
      for(size_t start = 0; start < text.size();)
        {
          size_t end = text.find('\n',start);
          if(end == NPOS)
            end = text.size();
          int rc = callback(Line{std::string_view(text.data() + start,end - start),start});
          if(rc)
            return rc;
          start = end + (end != text.size());
        }

      return 0;
    }


    bool
    decode_fstab(std::string_view  raw,
                 std::string      *decoded)
    {
      decoded->clear();
      for(size_t i = 0; i < raw.size(); ++i)
        {
          if(raw[i] != '\\')
            {
              decoded->push_back(raw[i]);
            }
          else
            {
              if(i + 3 >= raw.size())
                return false;
              unsigned number = 0;
              for(size_t j = 1; j <= 3; ++j)
                {
                  char c = raw[i + j];
                  if((c < '0') || (c > '7'))
                    return false;
                  number = number * 8 + static_cast<unsigned>(c - '0');
                }

              if(number == 0)
                return false;
              decoded->push_back(static_cast<char>(number));
              i += 3;
            }
        }

      return true;
    }


    int
    parse_options(std::string_view                   text,
                  std::map<std::string,std::string> *options,
                  bool                               fstab,
                  std::string                       *error)
    {
      for(size_t start = 0; start < text.size();)
        {
          size_t end = text.find(',',start);
          if(end == NPOS)
            end = text.size();
          std::string item;
          if(fstab)
            {
              if(!decode_fstab(text.substr(start,end - start),&item))
                return fail(error,EINVAL,"malformed fstab option escape");
            }
          else
            {
              item = text.substr(start,end - start);
            }

          const size_t equal    = item.find('=');
          const std::string key = item.substr(0,equal);
          if(fstab)
            {
              std::string_view raw = text.substr(start,end - start);
              size_t raw_equal     = raw.find('=');
              if(raw.substr(0,raw_equal) != key)
                return fail(error,ENOTSUP,"escaped mergerfs option names are unsupported");
            }

          if(key.empty())
            return fail(error,EINVAL,"empty configured mergerfs option");
          // fstab's systemd dependency option may occur once per branch.
          if((!((fstab) && (key == "x-systemd.requires-mounts-for"))) &&
             (!options->emplace(key,equal == NPOS ? "" : item.substr(equal + 1)).second))
            return fail(error,EINVAL,"duplicate configured mergerfs option: " + key);
          start = end + (end != text.size());
        }

      return 0;
    }


    std::string
    update_fstab_options(std::string_view   raw,
                         const std::string &key,
                         const std::string &value)
    {
      std::string updated(raw);
      for(size_t start = 0; start < raw.size();)
        {
          size_t end = raw.find(',',start);
          if(end == NPOS)
            end = raw.size();
          const size_t equal = raw.find('=',start);
          if((equal < end) && (raw.substr(start,equal - start) == key))
            {
              updated.replace(equal + 1,end - equal - 1,value);
              return updated;
            }

          start = end + (end != raw.size());
        }

      updated += (raw.empty() ? "" : ",") + key + "=" + value;
      return updated;
    }


    bool
    remove_option(std::string_view   raw,
                  const std::string &key,
                  std::string       *updated)
    {
      for(size_t start = 0; start < raw.size();)
        {
          size_t end = raw.find(',',start);
          if(end == NPOS)
            end = raw.size();
          size_t equal = raw.find('=',start);
          if(equal > end)
            equal = end;
          if(raw.substr(start,equal - start) == key)
            {
              // Remove the adjacent comma too, leaving every other option byte intact.
              if(end < raw.size())
                *updated = std::string(raw.substr(0,start)) + std::string(raw.substr(end + 1));
              else if(start)
                *updated = std::string(raw.substr(0,start - 1));
              else
                updated->clear();
              return true;
            }

          start = end + (end != raw.size());
        }

      return false;
    }


    int
    parse_fstab(const Document    &doc,
                const std::string &mount,
                Match             *match,
                int               *count,
                std::string       *error)
    {
      return each_line(doc.text,
                       [&](Line line)
                       {
                         size_t pos = 0;
                         while((pos < line.text.size()) && (space(line.text[pos])))
                           ++pos;
                         if((pos == line.text.size()) || (line.text[pos] == '#'))
                           return 0;
                         std::vector<Token> fields;
                         while((pos < line.text.size()) && (line.text[pos] != '#'))
                           {
                             size_t begin = pos;
                             while((pos < line.text.size()) && (!space(line.text[pos])))
                               ++pos;
                             if(begin != pos)
                               {
                                 fields.push_back(Token{
                                     std::string(line.text.substr(begin,pos - begin)),
                                     line.offset + begin,
                                     line.offset + pos
                                   });
                               }

                             while((pos < line.text.size()) && (space(line.text[pos])))
                               ++pos;
                           }

                         if(fields.size() < 3)
                           return 0;
                         if((fields[2].value != "mergerfs") && (fields[2].value != "fuse.mergerfs"))
                           return 0;
                         std::string target;
                         if(!decode_fstab(fields[1].value,&target))
                           return fail(error,EINVAL,"malformed mergerfs fstab mount escape");
                         if(target != mount)
                           return 0;
                         ++*count;
                         if(*count > 1)
                           return fail(error,EINVAL,"multiple fstab entries define this mount");
                         if((fields.size() < 4) || (fields.size() > 6))
                           {
                             return fail(error,
                                         EINVAL,
                                         "malformed mergerfs fstab entry for this mount");
                           }

                         match->source.type = "fstab";
                         std::string branches;
                         if(!decode_fstab(fields[0].value,&branches))
                           return fail(error,EINVAL,"malformed mergerfs fstab branch escape");
                         match->source.options["branches"] = branches;
                         int rc = parse_options(fields[3].value,&match->source.options,true,error);
                         if(rc)
                           return rc;
                         if(fields[3].value.find("branches=") != NPOS)
                           {
                             return fail(error,
                                         EINVAL,
                                         "branches defined in both fstab source and options");
                           }

                         match->begin        = fields[3].begin;
                         match->end          = fields[3].end;
                         match->branch_begin = fields[0].begin;
                         match->branch_end   = fields[0].end;
                         return 0;
                       });
    }


    bool
    fstab_has_mount(const Document    &doc,
                    const std::string &mount)
    {
      bool found = false;
      each_line(doc.text,
                [&](Line line)
                {
                  size_t pos = 0;
                  while((pos < line.text.size()) && (space(line.text[pos])))
                    ++pos;
                  if((pos == line.text.size()) || (line.text[pos] == '#'))
                    return 0;
                  while((pos < line.text.size()) && (!space(line.text[pos])))
                    ++pos;
                  while((pos < line.text.size()) && (space(line.text[pos])))
                    ++pos;
                  const size_t begin = pos;
                  while((pos < line.text.size()) && (!space(line.text[pos])))
                    ++pos;
                  if(begin == pos)
                    return 0;
                  std::string target;
                  if((decode_fstab(line.text.substr(begin,pos - begin),&target)) &&
                     (target == mount))
                    found = true;
                  return 0;
                });
      return found;
    }


    int
    existing_mount_unit(const std::string &name,
                        const Roots       &roots,
                        std::string       *error)
    {
      for(const std::string &directory : roots.systemd_dirs)
        {
          FD  dir;
          int rc = open_directory(directory,&dir,error);
          if(rc == -ENOENT)
            continue;
          if(rc)
            return rc;
          struct stat existing;
          if(::fstatat(dir.value,name.c_str(),&existing,AT_SYMLINK_NOFOLLOW) == 0)
            {
              return fail(error,
                          EEXIST,
                          "systemd mount unit already exists: " + directory + "/" + name);
            }

          if(errno != ENOENT)
            return fail(error,errno,"cannot check systemd mount unit: " + directory + "/" + name);
        }

      return 0;
    }


    struct LogicalLine
    {
      std::string text;
      std::vector<size_t> positions;
    };


    int
    service_lines(const std::string        &text,
                  std::vector<LogicalLine> *lines,
                  std::string              *error)
    {
      LogicalLine current;
      for(size_t start = 0; start < text.size();)
        {
          size_t end = text.find('\n',start);
          if(end == NPOS)
            end = text.size();
          size_t content_end = end;
          if((content_end > start) && (text[content_end - 1] == '\r'))
            --content_end;
          bool continued = ((content_end > start) && (text[content_end - 1] == '\\'));
          if(continued)
            --content_end;
          size_t first = start;
          if(!current.text.empty())
            {
              while((first < content_end) && (space(text[first])))
                ++first;
            }

          for(size_t i = first; i < content_end; ++i)
            {
              current.text.push_back(text[i]);
              current.positions.push_back(i);
            }

          if(continued)
            {
              if(end == text.size())
                return fail(error,EINVAL,"unfinished service line continuation");
              current.text.push_back(' ');
              current.positions.push_back(NPOS);
            }
          else
            {
              lines->push_back(std::move(current));
              current = LogicalLine{};
            }

          start = end + (end != text.size());
        }

      return 0;
    }


    int
    count_service_execstarts(const std::string &text,
                             std::string       *error)
    {
      std::vector<LogicalLine> lines;
      int rc = service_lines(text,&lines,error);
      if(rc)
        return rc;
      bool in_service = false;
      int count = 0;
      for(const LogicalLine &line : lines)
        {
          std::string_view content = trim(line.text);
          if((content.empty()) || (content.front() == '#') || (content.front() == ';'))
            continue;
          if(content.front() == '[')
            {
              in_service =
                ((content.back() == ']') &&
                 (trim(content.substr(1,content.size() - 2)) == "Service"));
              continue;
            }

          if(!in_service)
            continue;
          const size_t equal = content.find('=');
          if((equal != NPOS) && (trim(content.substr(0,equal)) == "ExecStart"))
            ++count;
        }

      return count;
    }


    bool
    token_span(const LogicalLine &line,
               size_t             begin,
               size_t             end,
               Token             *token)
    {
      if((begin == end) || (line.positions[begin] == NPOS))
        return false;
      for(size_t i = begin + 1; i < end; ++i)
        {
          if(line.positions[i] != line.positions[i - 1] + 1)
            return false;
        }

      token->begin = line.positions[begin];
      token->end   = line.positions[end - 1] + 1;
      return true;
    }


    int
    service_tokens(const LogicalLine  &line,
                   size_t              start,
                   std::vector<Token> *tokens,
                   std::string        *error)
    {
      for(size_t i = start; i < line.text.size();)
        {
          while((i < line.text.size()) && (space(line.text[i])))
            ++i;
          if(i == line.text.size())
            break;
          size_t begin = i;
          std::string value;
          char quote = 0;
          while((i < line.text.size()) && ((quote) || (!space(line.text[i]))))
            {
              char c = line.text[i++];
              if(c == '\\')
                {
                  if(i == line.text.size())
                    return fail(error,EINVAL,"unfinished service escape");
                  value.push_back(line.text[i++]);
                }
              else if((c == '"') || (c == '\''))
                {
                  if(!quote)
                    quote = c;
                  else if(quote == c)
                    quote = 0;
                  else
                    value.push_back(c);
                }
              else
                {
                  value.push_back(c);
                }
            }

          if(quote)
            return fail(error,EINVAL,"unterminated service quote");
          Token token;
          token.value = std::move(value);
          if(!token_span(line,begin,i,&token))
            return fail(error,ENOTSUP,"service token crosses a line continuation");
          tokens->push_back(std::move(token));
        }

      return 0;
    }


    std::string
    service_word(const std::string &word)
    {
      if(word.find_first_of(" \t\\\"'") == NPOS)
        return word;
      std::string result = "\"";
      for(char c : word)
        {
          if((c == '\\') || (c == '"'))
            result += '\\';
          result += c;
        }

      return result + '"';
    }


    int
    rewrite_service_option(const Document    &doc,
                           const Token       &token,
                           const std::string &key,
                           const std::string &value,
                           bool               remove,
                           std::string       *replacement,
                           std::string       *error)
    {
      std::string_view raw(doc.text.data() + token.begin,token.end - token.begin);
      std::string      updated;
      if(remove)
        {
          if(!remove_option(token.value,key,&updated))
            return fail(error,ENOENT,"option is absent from this service option group");
          if(updated.empty())
            {
              replacement->clear();
              return 0;
            }
        }
      else
        {
          updated = update_fstab_options(token.value,key,value);
        }

      if(raw == token.value)
        {
          *replacement = std::move(updated);
        }
      else if((raw.size() >= 2) &&
              ((raw.front() == '"') ||
               (raw.front() == '\'')) &&
              (raw.back() == raw.front()) &&
              (raw.substr(1,raw.size() - 2) == token.value))
        {
          *replacement = std::string(1,raw.front()) + updated + raw.front();
        }
      else
        {
          return fail(error,ENOTSUP,"service option uses unsupported quoting or escapes");
        }

      return 0;
    }


    int
    parse_ini(const Document    &doc,
              Match             *match,
              const std::string *edit_key,
              const std::string *edit_value,
              std::string       *error,
              bool               remove = false);
    int
    read_config_chain(const std::string     &initial,
                      std::set<std::string> *seen,
                      std::vector<Source>   *sources,
                      std::string           *error,
                      std::string_view       blocked);


    int
    parse_service(const Document    &doc,
                  const std::string &mount,
                  Match             *match,
                  int               *count,
                  const std::string *edit_key,
                  const std::string *edit_value,
                  std::string       *error,
                  bool               remove = false)
    {
      if(doc.text.find("mergerfs") == NPOS)
        return 0;
      std::vector<LogicalLine> lines;
      int rc = service_lines(doc.text,&lines,error);
      if(rc)
        return rc;
      bool in_service = false;
      for(const LogicalLine &line : lines)
        {
          std::string_view content = trim(line.text);
          if((content.empty()) || (content.front() == '#') || (content.front() == ';'))
            continue;
          if(content.front() == '[')
            {
              if(content.back() != ']')
                return fail(error,EINVAL,"malformed systemd section header");
              in_service = trim(content.substr(1,content.size() - 2)) == "Service";
              continue;
            }

          if(!in_service)
            continue;
          size_t equal = line.text.find('=');
          if((equal == NPOS) || (trim(std::string_view(line.text).substr(0,equal)) != "ExecStart"))
            continue;
          std::vector<Token> tokens;
          rc = service_tokens(line,equal + 1,&tokens,error);
          if(rc)
            {
              if((contains_mount_reference(line.text,mount)) &&
                 (line.text.find("mergerfs") != NPOS))
                return rc;
              continue;
            }

          if(tokens.empty())
            continue;
          const std::string &program = tokens[0].value;
          if((program != "mergerfs") &&
             (program != "/usr/bin/mergerfs") &&
             (program != "/usr/local/bin/mergerfs"))
            {
              if((contains_mount_reference(line.text,mount)) &&
                 (line.text.find("mergerfs") != NPOS))
                {
                  return fail(error,
                              ENOTSUP,
                              "mergerfs service is not a direct ExecStart invocation");
                }

              continue;
            }

          std::vector<Token>                positional;
          std::vector<Token>                option_words;
          std::vector<Token>                option_flags;
          std::map<std::string,std::string> options;
          bool unsupported = false;
          for(size_t i = 1; i < tokens.size(); ++i)
            {
              const std::string &word = tokens[i].value;
              if((word == "-f") || (word == "-d") || (word == "--foreground"))
                continue;
              if((word == "-o") || ((word.size() > 2) && (word.substr(0,2) == "-o")))
                {
                  if(!positional.empty())
                    {
                      unsupported = true;
                      break;
                    }

                  if(word == "-o")
                    {
                      if(++i == tokens.size())
                        {
                          unsupported = true;
                          break;
                        }

                      option_words.push_back(tokens[i]);
                      if(remove)
                        option_flags.push_back(tokens[i - 1]);
                    }
                  else
                    {
                      option_words.push_back(Token{
                          word.substr(2),
                          tokens[i].begin + 2,
                          tokens[i].end
                        });
                      if(remove)
                        option_flags.push_back(tokens[i]);
                    }

                  rc = parse_options(option_words.back().value,&options,false,error);
                  if(rc)
                    {
                      unsupported = true;
                      break;
                    }
                }
              else if((word.empty()) || (word.front() == '-'))
                {
                  unsupported = true;
                  break;
                }
              else
                {
                  positional.push_back(tokens[i]);
                }
            }

          bool config_only = false;
          if((!unsupported) && (positional.empty()))
            {
              const auto config = options.find("config");
              if((config != options.end()) &&
                 (!config->second.empty()) &&
                 (config->second.front() == '/'))
                {
                  std::set<std::string> seen;
                  std::vector<Source>   referenced;
                  rc = read_config_chain(config->second,&seen,&referenced,error,{});
                  if(!rc)
                    {
                      config_only = std::any_of(referenced.begin(),
                                                referenced.end(),
                                                [&](const Source &source)
                                                {
                                                  const auto location =
                                                    source.options.find("mountpoint");
                                                  return ((location != source.options.end()) &&
                                                          (location->second == mount));
                                                });
                    }

                  if((rc) && (contains_mount_reference(line.text,mount)))
                    return rc;
                }
            }

          const bool explicit_mount =
            ((positional.size() >= 2) &&
             (positional.back().value == mount));
          if((!explicit_mount) && (!config_only) && (!contains_mount_reference(line.text,mount)))
            continue;
          if((unsupported) ||
             ((!explicit_mount) &&
              (!config_only)) ||
             (program.find_first_of("%$;\\") != NPOS) ||
             (line.text.find('%') != NPOS) ||
             (line.text.find('$') != NPOS) ||
             (line.text.find(';') != NPOS))
            {
              return fail(error,
                          ENOTSUP,
                          "unsupported or ambiguous mergerfs service ExecStart for this mount");
            }

          if((explicit_mount) && (options.count("branches")))
            return fail(error,EINVAL,"branches defined in both service position and options");
          ++*count;
          if(*count > 1)
            return fail(error,EINVAL,"multiple ExecStart definitions for this mount");
          if(explicit_mount)
            {
              std::string branches = positional.front().value;
              for(size_t i = 1; i + 1 < positional.size(); ++i)
                branches += ":" + positional[i].value;
              options["branches"] = std::move(branches);
            }

          match->source.type    = "systemd";
          match->source.options = std::move(options);
          if(!edit_key)
            continue;
          if(*edit_key == "branches")
            {
              if(!explicit_mount)
                {
                  return fail(error,
                              ENOTSUP,
                              "persist config-only service branches in its referenced ini");
                }

              match->begin = positional.front().begin;
              match->end   = positional[positional.size() - 2].end;
              for(size_t i = 0; i + 2 < positional.size(); ++i)
                {
                  for(size_t j = positional[i].end; j < positional[i + 1].begin; ++j)
                    {
                      if((!space(doc.text[j])) && (doc.text[j] != '\\') && (doc.text[j] != '\n'))
                        {
                          return fail(error,
                                      ENOTSUP,
                                      "unsupported content between service branch paths");
                        }
                    }
                }

              match->replacement = service_word(*edit_value);
            }
          else
            {
              bool located = false;
              for(size_t i = 0; i < option_words.size(); ++i)
                {
                  const Token &token = option_words[i];
                  std::map<std::string,std::string> group;
                  rc = parse_options(token.value,&group,false,error);
                  if(rc)
                    return rc;
                  if(!group.count(*edit_key))
                    continue;
                  located      = true;
                  match->begin = token.begin;
                  match->end   = token.end;
                  rc = rewrite_service_option(doc,
                                              token,
                                              *edit_key,
                                              *edit_value,
                                              remove,
                                              &match->replacement,
                                              error);
                  if(rc)
                    return rc;
                  if((remove) && (match->replacement.empty()))
                    {
                      match->begin = option_flags[i].begin;
                      // Removing the sole option removes its -o flag as well.
                      // Consume an ordinary separating space, but never a
                      // continuation or surrounding indentation.
                      for(size_t j = 1; j < tokens.size(); ++j)
                        {
                          if((tokens[j].begin == match->begin) &&
                             (tokens[j - 1].end + 1 == match->begin) &&
                             (doc.text[tokens[j - 1].end] == ' '))
                            {
                              --match->begin;
                              break;
                            }
                        }
                    }
                  break;
                }

              if(remove)
                {
                  if(!located)
                    return fail(error,ENOENT,"option is absent from this service");
                }
              else
                {
                  if((!located) && (!option_words.empty()))
                    {
                      const Token &token = option_words.back();
                      match->begin = token.begin;
                      match->end   = token.end;
                      rc = rewrite_service_option(doc,
                                                  token,
                                                  *edit_key,
                                                  *edit_value,
                                                  false,
                                                  &match->replacement,
                                                  error);
                      if(rc)
                        return rc;
                    }

                  if(match->replacement.empty())
                    {
                      match->begin = match->end = positional[0].begin;
                      match->replacement = "-o " + *edit_key + "=" + *edit_value + " ";
                    }
                }
            }
        }

      return 0;
    }


    int
    parse_mount_unit(const Document    &doc,
                     const std::string &mount,
                     Match             *match,
                     int               *count,
                     const std::string *edit_key,
                     const std::string *edit_value,
                     std::string       *error,
                     bool               remove = false)
    {
      if(doc.text.find(mount) == NPOS)
        return 0;
      std::vector<LogicalLine> lines;
      int rc = service_lines(doc.text,&lines,error);
      if(rc)
        return rc;
      bool in_mount = false;
      int sections  = 0;
      std::map<std::string,Token> fields;
      bool duplicate = false;
      size_t what_line_end = 0;
      for(const LogicalLine &line : lines)
        {
          std::string_view content = trim(line.text);
          if((content.empty()) || (content.front() == '#') || (content.front() == ';'))
            continue;
          if(content.front() == '[')
            {
              if(content.back() != ']')
                return fail(error,EINVAL,"malformed systemd mount section");
              in_mount = trim(content.substr(1,content.size() - 2)) == "Mount";
              if(in_mount)
                ++sections;
              continue;
            }

          if(!in_mount)
            continue;
          size_t equal = line.text.find('=');
          if(equal == NPOS)
            {
              if(line.text.find(mount) != NPOS)
                return fail(error,EINVAL,"malformed systemd mount directive");
              continue;
            }

          std::string key(trim(std::string_view(line.text).substr(0,equal)));
          if((key != "Where") && (key != "What") && (key != "Type") && (key != "Options"))
            continue;
          size_t begin = equal + 1;
          while((begin < line.text.size()) && (space(line.text[begin])))
            ++begin;
          size_t end = line.text.size();
          while((end > begin) && (space(line.text[end - 1])))
            --end;
          Token token;
          token.value = line.text.substr(begin,end - begin);
          token.begin = token.end = line.positions[equal] + 1;
          if((begin != end) && (!token_span(line,begin,end,&token)))
            {
              if(line.text.find(mount) != NPOS)
                return fail(error,ENOTSUP,"systemd mount value crosses a line continuation");
              continue;
            }

          if(!fields.emplace(key,std::move(token)).second)
            duplicate = true;
          if(key == "What")
            what_line_end = ((line.positions.empty()) ? 0 : line.positions.back() + 1);
        }

      const auto where = fields.find("Where");
      if((where == fields.end()) || (where->second.value != mount))
        return 0;
      const auto type = fields.find("Type");
      if((type == fields.end()) ||
         ((type->second.value != "mergerfs") &&
          (type->second.value != "fuse.mergerfs")))
        return 0;
      if((sections != 1) ||
         (duplicate) ||
         (!fields.count("What")) ||
         (fields["What"].value.empty()) ||
         (fields["What"].value.find_first_of("%$;\\\\") != NPOS) ||
         (fields["Where"].value.find_first_of("%$;\\\\") != NPOS))
        return fail(error,ENOTSUP,"unsupported or ambiguous systemd mergerfs mount unit");
      ++*count;
      match->source.type                = "systemd";
      match->source.options["branches"] = fields["What"].value;
      const auto opts = fields.find("Options");
      if(opts != fields.end())
        {
          if(opts->second.value.find_first_of("%$;\\\\") != NPOS)
            return fail(error,ENOTSUP,"unsupported systemd mount options expansion");
          rc = parse_options(opts->second.value,&match->source.options,false,error);
          if(rc)
            return rc;
        }

      if(!edit_key)
        return 0;
      if(*edit_key == "branches")
        {
          match->begin       = fields["What"].begin;
          match->end         = fields["What"].end;
          match->replacement = *edit_value;
        }
      else if(opts != fields.end())
        {
          match->begin = opts->second.begin;
          match->end   = opts->second.end;
          if(remove)
            {
              if(!remove_option(opts->second.value,*edit_key,&match->replacement))
                return fail(error,ENOENT,"option is absent from this mount unit");
              if(match->replacement.empty())
                {
                  // Options= with no options would override systemd defaults.
                  // Drop the directive, including its original line ending.
                  size_t start = doc.text.rfind('\n',match->begin);
                  match->begin = ((start == NPOS) ? 0 : start + 1);
                  size_t end = doc.text.find('\n',match->end);
                  match->end = ((end == NPOS) ? doc.text.size() : end + 1);
                }
            }
          else
            {
              match->replacement = update_fstab_options(opts->second.value,*edit_key,*edit_value);
            }
        }
      else if(remove)
        {
          return fail(error,ENOENT,"option is absent from this mount unit");
        }
      else
        {
          match->begin = match->end = what_line_end;
          const std::string newline =
            ((((what_line_end < doc.text.size()) && (doc.text[what_line_end] == '\r'))) ?
             "\r\n" :
             "\n");
          match->replacement = newline + "Options=" + *edit_key + "=" + *edit_value;
        }

      return 0;
    }


    int
    parse_ini(const Document    &doc,
              Match             *match,
              const std::string *edit_key,
              const std::string *edit_value,
              std::string       *error,
              bool               remove)
    {
      match->source.type = "ini";
      int rc = each_line(doc.text,[&](Line line) {
      std::string_view content = trim(line.text);
      if((content.empty()) || (content.front() == '#')) return 0;
      size_t equal = line.text.find('=');
      if(content.front() == '[')
        return fail(error,EINVAL,"malformed plain mergerfs config line");
      std::string_view key_text = line.text.substr(0,equal);
      if(equal == NPOS)
        {
          size_t comment = key_text.find('#');
          if((comment != NPOS) && (comment > 0) && (space(key_text[comment-1])))
            key_text = key_text.substr(0,comment);
        }
      std::string_view key = trim(key_text);
      if((key.empty()) || (key.find_first_of(" \t#") != NPOS))
        return fail(error,EINVAL,"malformed mergerfs config key");
      std::string_view raw_value = equal == NPOS ? std::string_view{} : line.text.substr(equal+1);
      // A trailing whitespace-prefixed # comment is not part of the value.
      for(size_t i = 1; i < raw_value.size(); ++i)
        {
          if((raw_value[i] == '#') && (space(raw_value[i-1])))
            { raw_value = raw_value.substr(0,i); break; }
        }
      std::string_view value = trim(raw_value);
      if(!match->source.options.emplace(std::string(key),std::string(value)).second)
        return fail(error,EINVAL,"duplicate mergerfs config key: " + std::string(key));
      if((edit_key) && (key == *edit_key))
        {
          if(remove)
            {
              match->begin = line.offset;
              match->end = line.offset + line.text.size();
              if(match->end < doc.text.size())
                ++match->end;
              match->replacement.clear();
              match->located = true;
              return 0;
            }
          if(equal == NPOS)
            {
              match->begin = match->end = line.offset +
                static_cast<size_t>(key.data() - line.text.data()) + key.size();
              match->replacement = "=" + *edit_value;
            }
          else
            {
              size_t begin = line.offset + equal + 1;
              while((begin < line.offset + line.text.size()) && (space(doc.text[begin]))) ++begin;
              match->begin = begin;
              match->end = begin + value.size();
              match->replacement = *edit_value;
            }
          match->located = true;
        }
      return 0;
    });
      if((rc) || (!edit_key) || (match->located))
        return rc;
      if(remove)
        return fail(error,ENOENT,"option is absent from this config file");
      match->begin = match->end = doc.text.size();
      const std::string newline = (doc.text.find("\r\n") != NPOS) ? "\r\n" : "\n";
      match->replacement =
      (((doc.text.empty()) || (doc.text.back() == '\n')) ? "" : newline) + *edit_key + "=" +
      *edit_value + newline;
      return 0;
    }


    bool
    safe_path_character(unsigned char c)
    {
      return ((c < 128) &&
              ((std::isalnum(c)) ||
               (c == '/') ||
               (c == '.') ||
               (c == '_') ||
               (c == '-')));
    }


    bool
    safe_component(std::string_view name)
    {
      if((name.empty()) || (name == ".") || (name == ".."))
        return false;
      for(unsigned char c : name)
        {
          if((c == '/') || (!safe_path_character(c)))
            return false;
        }

      return true;
    }


    bool
    safe_path(std::string_view path)
    {
      if((path.empty()) || (path.front() != '/') || ((path.size() > 1) && (path.back() == '/')))
        return false;
      for(unsigned char c : path)
        {
          if(!safe_path_character(c))
            return false;
        }

      return true;
    }


    int
    read_config_chain(const std::string     &initial,
                      std::set<std::string> *seen,
                      std::vector<Source>   *sources,
                      std::string           *error,
                      std::string_view       blocked)
    {
      std::string path = initial;
      std::set<std::string> chain;
      while(!path.empty())
        {
          if((std::string_view(path) == blocked) || (!chain.insert(path).second))
            return fail(error,ELOOP,"cyclic mergerfs config reference: " + path);
          if(!seen->insert(path).second)
            return 0;
          if(!safe_path(path))
            return fail(error,EINVAL,"unsafe mergerfs config reference: " + path);
          Document doc;
          int      rc = open_document(path,&doc,error);
          if(rc)
            return rc;
          Match match;
          rc = parse_ini(doc,&match,nullptr,nullptr,error);
          if(rc)
            return rc;
          const auto config      = match.source.options.find("config");
          const std::string next = (config == match.source.options.end()) ? "" : config->second;
          if(sources)
            {
              match.source.path = path;
              sources->push_back(std::move(match.source));
            }

          path = next;
        }

      return 0;
    }


    int
    create_directory(const std::string &path,
                     std::string       *error)
    {
      FD dir;
      return open_directory(path,&dir,error,true);
    }


    int
    branch_mount_paths(std::string_view          branches,
                       std::vector<std::string> *paths,
                       std::string              *error)
    {
      paths->clear();
      for(size_t start = 0; start < branches.size();)
        {
          size_t end = branches.find(':',start);
          if(end == NPOS)
            end = branches.size();
          std::string_view item = branches.substr(start,end - start);
          std::string_view path = item.substr(0,item.find('='));
          if(!safe_path(path))
            return fail(error,EINVAL,"branch dependencies require safe absolute paths");
          paths->emplace_back(path);
          start = end + (end != branches.size());
        }

      if((paths->empty()) || (branches.back() == ':'))
        return fail(error,EINVAL,"branch dependencies require nonempty paths");
      return 0;
    }


    int
    update_fstab_branches(const Document    &doc,
                          const Match       &match,
                          const std::string &branches,
                          std::string       *updated,
                          std::string       *error)
    {
      constexpr std::string_view dependency = "x-systemd.requires-mounts-for";
      const std::string_view     raw(doc.text.data() + match.begin,match.end - match.begin);
      std::vector<std::string>   configured;
      std::string options;
      for(size_t start = 0; start < raw.size();)
        {
          size_t end = raw.find(',',start);
          if(end == NPOS)
            end = raw.size();
          const std::string_view item = raw.substr(start,end - start);
          const size_t equal = item.find('=');
          if(item.substr(0,equal) == dependency)
            {
              std::string path;
              if((equal == NPOS) || (!decode_fstab(item.substr(equal + 1),&path)))
                return fail(error,ENOTSUP,"cannot update malformed fstab branch dependencies");
              configured.push_back(std::move(path));
            }
          else
            {
              if(!options.empty())
                options += ',';
              options.append(item.data(),item.size());
            }

          start = end + (end != raw.size());
        }

      if(!configured.empty())
        {
          std::vector<std::string> previous;
          std::vector<std::string> next;
          int rc = branch_mount_paths(match.source.options.at("branches"),&previous,error);
          if(rc)
            return rc;
          if(configured != previous)
            {
              return fail(error,
                          ENOTSUP,
                          "fstab branch dependencies differ from the configured branches");
            }

          rc = branch_mount_paths(branches,&next,error);
          if(rc)
            return rc;
          for(const std::string &path : next)
            {
              if(!options.empty())
                options += ',';
              options += "x-systemd.requires-mounts-for=" + path;
            }

          updated->replace(match.begin,match.end - match.begin,options);
        }

      updated->replace(match.branch_begin,match.branch_end - match.branch_begin,branches);
      return 0;
    }


    int
    update_mount_unit_branches(const Document    &doc,
                               const Match       &match,
                               const std::string &branches,
                               std::string       *updated,
                               std::string       *error)
    {
      bool in_unit = false;
      size_t dependency_begin = 0;
      size_t dependency_end   = 0;
      std::string_view current;
      int count = 0;
      int rc = each_line(doc.text,
                         [&](Line line)
                         {
                           std::string_view content = trim(line.text);
                           if((content.empty()) ||
                              (content.front() == '#') ||
                              (content.front() == ';'))
                             return 0;
                           if(content.front() == '[')
                             {
                               in_unit = content == "[Unit]";
                               return 0;
                             }

                           if(!in_unit)
                             return 0;
                           size_t equal = line.text.find('=');
                           if((equal == NPOS) ||
                              (trim(line.text.substr(0,equal)) != "RequiresMountsFor"))
                             return 0;
                           if(++count != 1)
                             {
                               return fail(error,
                                           ENOTSUP,
                                           "multiple systemd branch dependency directives");
                             }

                           size_t begin = equal + 1;
                           while((begin < line.text.size()) && (space(line.text[begin])))
                             ++begin;
                           size_t end = line.text.size();
                           while((end > begin) && (space(line.text[end - 1])))
                             --end;
                           dependency_begin = line.offset + begin;
                           dependency_end   = line.offset + end;
                           current          = line.text.substr(begin,end - begin);
                           return 0;
                         });
      if(rc)
        return rc;
      if(count)
        {
          std::vector<std::string> previous;
          std::vector<std::string> configured;
          std::vector<std::string> next;
          rc = branch_mount_paths(match.source.options.at("branches"),&previous,error);
          if(rc)
            return rc;
          for(size_t pos = 0; pos < current.size();)
            {
              while((pos < current.size()) && (space(current[pos])))
                ++pos;
              size_t end = pos;
              while((end < current.size()) && (!space(current[end])))
                ++end;
              if(pos != end)
                configured.emplace_back(current.substr(pos,end - pos));
              pos = end;
            }

          if(configured != previous)
            {
              return fail(error,
                          ENOTSUP,
                          "systemd branch dependencies differ from the configured branches");
            }

          rc = branch_mount_paths(branches,&next,error);
          if(rc)
            return rc;
          std::string replacement;
          for(const std::string &path : next)
            {
              if(!replacement.empty())
                replacement += ' ';
              replacement += path;
            }

          if(dependency_begin < match.begin)
            {
              updated->replace(match.begin,match.end - match.begin,branches);
              updated->replace(dependency_begin,dependency_end - dependency_begin,replacement);
            }
          else
            {
              updated->replace(dependency_begin,dependency_end - dependency_begin,replacement);
              updated->replace(match.begin,match.end - match.begin,branches);
            }
        }
      else
        {
          updated->replace(match.begin,match.end - match.begin,branches);
        }

      return 0;
    }


    int
    validate_branches(const std::string        &branches,
                      std::vector<std::string> *paths,
                      std::string              *error)
    {
      if(!safe_branches(branches))
        return fail(error,EINVAL,"unsafe or empty mergerfs branches");
      if(paths)
        paths->clear();
      for(size_t start = 0; start < branches.size();)
        {
          size_t end = branches.find(':',start);
          if(end == NPOS)
            end = branches.size();
          if(end == start)
            return fail(error,EINVAL,"empty mergerfs branch path");
          const std::string_view item(branches.data() + start,end - start);
          size_t equal = item.find('=');
          const std::string_view path = item.substr(0,equal);
          if(!safe_path(path))
            return fail(error,EINVAL,"unsafe branch path: " + std::string(path));
          if(paths)
            paths->emplace_back(path);
          if(equal != NPOS)
            {
              const std::string_view suffix = item.substr(equal + 1);
              size_t comma = suffix.find(',');
              const std::string_view mode = suffix.substr(0,comma);
              if((mode != "RW") && (mode != "RO") && (mode != "NC"))
                return fail(error,EINVAL,"invalid branch mode: " + std::string(mode));
              if(comma != NPOS)
                {
                  const std::string_view minimum = suffix.substr(comma + 1);
                  size_t digits = 0;
                  while((digits < minimum.size()) &&
                        (std::isdigit(static_cast<unsigned char>(minimum[digits]))))
                    ++digits;
                  if((!digits) ||
                     ((digits < minimum.size()) &&
                      ((digits + 1 != minimum.size()) ||
                       (std::string_view("BKMGTPE").find(minimum[digits]) == NPOS))))
                    return fail(error,EINVAL,"invalid branch minfreespace");
                }
            }

          if((end != branches.size()) && (end + 1 == branches.size()))
            return fail(error,EINVAL,"empty mergerfs branch path");
          start = end + (end != branches.size());
        }

      return 0;
    }


    // A plain RW suffix restates the default. Keep RW when it introduces
    // a branch-specific minimum, since the suffix grammar requires a mode.
    bool
    strip_default_rw_modes(const std::string &branches,
                           std::string       *normalized)
    {
      size_t copied = 0;
      bool changed  = false;
      for(size_t begin = 0; begin < branches.size();)
        {
          size_t end = branches.find(':',begin);
          if(end == NPOS)
            end = branches.size();
          const size_t equal = branches.find('=',begin);
          if((equal < end) && (end - equal == 3) && (branches.compare(equal,3,"=RW") == 0))
            {
              if(!changed)
                normalized->reserve(branches.size());
              normalized->append(branches,copied,equal - copied);
              copied  = end;
              changed = true;
            }

          begin = end + (end != branches.size());
        }

      if(changed)
        normalized->append(branches,copied,branches.size() - copied);
      return changed;
    }


    std::string
    mount_unit_name(const std::string &mount)
    {
      if(mount == "/")
        return "-.mount";
      std::string    name;
      constexpr char HEX[] = "0123456789abcdef";
      for(size_t i = 1; i < mount.size(); ++i)
        {
          const unsigned char c = static_cast<unsigned char>(mount[i]);
          if(c == '/')
            {
              name += '-';
            }
          else if(c == '-')
            {
              name += "\\x2d";
            }
          else if((std::isalnum(c)) ||
                  (c == ':') ||
                  (c == '_') ||
                  ((c == '.') &&
                   (i != 1)))
            {
              name += static_cast<char>(c);
            }
          else
            {
              name += "\\x";
              name += HEX[c >> 4];
              name += HEX[c & 15];
            }
        }

      return name + ".mount";
    }


    struct NewFile
    {
      FD dir;
      FD file;
      std::string name;
      bool owned = false;
    };


    int
    prepare_new_file(const std::string &path,
                     NewFile           *target,
                     std::string       *error)
    {
      const size_t slash = path.rfind('/');
      if((slash == NPOS) || (slash + 1 == path.size()))
        return fail(error,EINVAL,"invalid new persistence file path: " + path);
      target->name = path.substr(slash + 1);
      int rc = open_directory(slash ? path.substr(0,slash) : "/",&target->dir,error);
      if(rc)
        return rc;
      struct stat existing;
      if(::fstatat(target->dir.value,target->name.c_str(),&existing,AT_SYMLINK_NOFOLLOW) == 0)
        return fail(error,EEXIST,"persistence file already exists: " + path);
      if(errno != ENOENT)
        return fail(error,errno,"cannot check new persistence file: " + path);
      return 0;
    }


    void
    remove_owned_file(NewFile *target)
    {
      if(!target->owned)
        return;
      struct stat owned;
      struct stat current;
      if((::fstat(target->file.value,&owned) == 0) &&
         (::fstatat(target->dir.value,target->name.c_str(),&current,AT_SYMLINK_NOFOLLOW) == 0) &&
         (owned.st_dev == current.st_dev) &&
         (owned.st_ino == current.st_ino) &&
         (current.st_nlink == 1))
        {
          if(::unlinkat(target->dir.value,target->name.c_str(),0) == 0)
            ::fsync(target->dir.value);
        }

      target->owned = false;
    }


    int
    create_new_file(NewFile           *target,
                    const std::string &text,
                    mode_t             mode,
                    std::string       *error)
    {
      if(text.size() > MAX_FILE_SIZE)
        return fail(error,EFBIG,"new persistence file exceeds size limit");
      target->file.value = ::openat(target->dir.value,
                                    target->name.c_str(),
                                    O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,
                                    0600);
      if(target->file.value < 0)
        return fail(error,errno,"cannot create new persistence file: " + target->name);
      target->owned = true;
      int code = 0;
      const char *message = "";
      size_t written      = 0;
      while(written < text.size())
        {
          ssize_t n = ::write(target->file.value,text.data() + written,text.size() - written);
          if((n < 0) && (errno == EINTR))
            continue;
          if(n <= 0)
            {
              code    = ((n < 0) ? errno : EIO);
              message = "cannot write new persistence file";
              break;
            }

          written += static_cast<size_t>(n);
        }

      if((!code) && (::fchmod(target->file.value,mode) < 0))
        {
          code    = errno;
          message = "cannot set new persistence file permissions";
        }

      if((!code) && (::fsync(target->file.value) < 0))
        {
          code    = errno;
          message = "cannot sync new persistence file";
        }

      if((!code) && (::fsync(target->dir.value) < 0))
        {
          code    = errno;
          message = "cannot sync new persistence directory";
        }

      if(code)
        {
          remove_owned_file(target);
          return fail(error,code,message);
        }

      return 0;
    }


    int
    collect(const std::string   &mount,
            const Roots         &roots,
            std::vector<Source> *sources,
            std::string         *error)
    {
      sources->clear();
      std::set<std::string> config_paths;
      std::set<std::string> seen_units;
      if(!roots.fstab.empty())
        {
          Document doc;
          int      rc = open_document(roots.fstab,&doc,error);
          if(rc)
            return rc;
          Match match;
          int   count = 0;
          rc = parse_fstab(doc,mount,&match,&count,error);
          if(rc)
            return rc;
          if(count)
            {
              match.source.path = roots.fstab;
              auto config = match.source.options.find("config");
              if(config != match.source.options.end())
                config_paths.insert(config->second);
              sources->push_back(std::move(match.source));
            }
        }

      for(const std::string &directory : roots.systemd_dirs)
        {
          FD  dir;
          int rc = open_directory(directory,&dir,error);
          if(rc == -ENOENT)
            continue;
          if(rc)
            return rc;
          DIR *stream = ::fdopendir(::dup(dir.value));
          if(!stream)
            return fail(error,errno,"cannot list systemd service directory: " + directory);
          std::vector<std::string> names;
          errno = 0;
          while(struct dirent *entry = ::readdir(stream))
            {
              std::string name = entry->d_name;
              if(((name.size() > 8) &&
                  (name.substr(name.size() - 8) == ".service")) ||
                 ((name.size() > 6) &&
                  (name.substr(name.size() - 6) == ".mount")))
                names.push_back(std::move(name));
              errno = 0;
            }

          int listing_error = errno;
          ::closedir(stream);
          if(listing_error)
            return fail(error,listing_error,"cannot list systemd services");
          std::sort(names.begin(),names.end());
          for(const std::string &name : names)
            {
              if(!seen_units.insert(name).second)
                continue;
              const std::string path = directory + (directory.back() == '/' ? "" : "/") + name;
              Document doc;
              rc = open_document(path,&doc,error);
              if((rc == -ELOOP) || (rc == -ENOENT))
                continue;
              if(rc)
                return rc;
              Match match;
              int   count = 0;
              rc =
                ((name.substr(name.size() - 6) == ".mount") ?
                 parse_mount_unit(doc,mount,&match,&count,nullptr,nullptr,error) :
                 parse_service(doc,mount,&match,&count,nullptr,nullptr,error));
              if(rc)
                return rc;
              if(count)
                {
                  match.source.path = path;
                  auto config = match.source.options.find("config");
                  if(config != match.source.options.end())
                    config_paths.insert(config->second);
                  sources->push_back(std::move(match.source));
                }
            }
        }

      std::set<std::string> seen_configs;
      for(const std::string &path : config_paths)
        {
          int rc = read_config_chain(path,&seen_configs,sources,error,{});
          if(rc)
            return rc;
        }

      return 0;
    }


    int
    collect_fstab_mountpoints(const Document        &doc,
                              std::set<std::string> *mounts,
                              std::string           *error)
    {
      return each_line(doc.text,
                       [&](Line line)
                       {
                         size_t pos = 0;
                         while((pos < line.text.size()) && (space(line.text[pos])))
                           ++pos;
                         if((pos == line.text.size()) || (line.text[pos] == '#'))
                           return 0;
                         std::vector<std::string_view> fields;
                         while((pos < line.text.size()) && (line.text[pos] != '#'))
                           {
                             size_t begin = pos;
                             while((pos < line.text.size()) && (!space(line.text[pos])))
                               ++pos;
                             if(begin != pos)
                               fields.push_back(line.text.substr(begin,pos - begin));
                             while((pos < line.text.size()) && (space(line.text[pos])))
                               ++pos;
                           }

                         if((fields.size() < 3) ||
                            ((fields[2] != "mergerfs") &&
                             (fields[2] != "fuse.mergerfs")))
                           return 0;
                         std::string mount;
                         if(!decode_fstab(fields[1],&mount))
                           return fail(error,EINVAL,"malformed mergerfs fstab mount escape");
                         if((mount.empty()) || (mount.front() != '/') || (mount.find('\0') != NPOS))
                           return 0;
                         if((fields.size() < 4) || (fields.size() > 6))
                           {
                             return fail(error,
                                         EINVAL,
                                         "malformed mergerfs fstab entry for this mount");
                           }

                         std::string branches;
                         if(!decode_fstab(fields[0],&branches))
                           return fail(error,EINVAL,"malformed mergerfs fstab branch escape");
                         std::map<std::string,std::string> options;
                         int rc = parse_options(fields[3],&options,true,error);
                         if(rc)
                           return rc;
                         if(fields[3].find("branches=") != NPOS)
                           {
                             return fail(error,
                                         EINVAL,
                                         "branches defined in both fstab source and options");
                           }

                         mounts->insert(std::move(mount));
                         return 0;
                       });
    }


    int
    collect_mount_unit_mountpoint(const Document        &doc,
                                  std::set<std::string> *mounts,
                                  std::string           *error)
    {
      if((doc.text.find("mergerfs") == NPOS) || (doc.text.find("Where") == NPOS))
        return 0;
      std::vector<LogicalLine> lines;
      int rc = service_lines(doc.text,&lines,error);
      if(rc)
        return rc;
      bool in_mount = false;
      std::string mount;
      for(const LogicalLine &line : lines)
        {
          std::string_view content = trim(line.text);
          if((content.empty()) || (content.front() == '#') || (content.front() == ';'))
            continue;
          if(content.front() == '[')
            {
              in_mount = content == "[Mount]";
              continue;
            }

          if(!in_mount)
            continue;
          size_t equal = content.find('=');
          if((equal == NPOS) || (trim(content.substr(0,equal)) != "Where"))
            continue;
          std::string_view value = trim(content.substr(equal + 1));
          if((!value.empty()) && (value.front() == '/'))
            {
              mount = value;
              break;
            }
        }

      if(mount.empty())
        return 0;
      Match match;
      int   count = 0;
      rc = parse_mount_unit(doc,mount,&match,&count,nullptr,nullptr,error);
      if((!rc) && (count))
        mounts->insert(std::move(mount));
      return rc;
    }


    int
    collect_service_mountpoints(const Document        &doc,
                                std::set<std::string> *mounts,
                                std::string           *error)
    {
      if(doc.text.find("mergerfs") == NPOS)
        return 0;
      std::vector<LogicalLine> lines;
      int rc = service_lines(doc.text,&lines,error);
      if(rc)
        return rc;
      bool in_service = false;
      for(const LogicalLine &line : lines)
        {
          std::string_view content = trim(line.text);
          if((content.empty()) || (content.front() == '#') || (content.front() == ';'))
            continue;
          if(content.front() == '[')
            {
              in_service = content == "[Service]";
              continue;
            }

          if(!in_service)
            continue;
          size_t equal = line.text.find('=');
          if((equal == NPOS) || (trim(std::string_view(line.text).substr(0,equal)) != "ExecStart"))
            continue;
          std::vector<Token> tokens;
          rc = service_tokens(line,equal + 1,&tokens,error);
          if(rc)
            return rc;
          if(tokens.empty())
            continue;
          const std::string &program = tokens.front().value;
          if((program != "mergerfs") &&
             (program != "/usr/bin/mergerfs") &&
             (program != "/usr/local/bin/mergerfs"))
            continue;
          std::vector<std::string> positional;
          std::map<std::string,std::string> options;
          bool unsupported =
            ((program.find_first_of("%$;\\") != NPOS) ||
             (line.text.find_first_of("%$;") != NPOS));
          for(size_t i = 1; (!unsupported) && (i < tokens.size()); ++i)
            {
              const std::string &word = tokens[i].value;
              if((word == "-f") || (word == "-d") || (word == "--foreground"))
                continue;
              if((word == "-o") || ((word.size() > 2) && (word.substr(0,2) == "-o")))
                {
                  if(!positional.empty())
                    {
                      unsupported = true;
                      break;
                    }

                  std::string_view option;
                  if(word == "-o")
                    {
                      if(++i == tokens.size())
                        {
                          unsupported = true;
                          break;
                        }

                      option = tokens[i].value;
                    }
                  else
                    {
                      option = std::string_view(word).substr(2);
                    }

                  rc = parse_options(option,&options,false,error);
                  if(rc)
                    return rc;
                }
              else if((word.empty()) || (word.front() == '-'))
                {
                  unsupported = true;
                }
              else
                {
                  positional.push_back(word);
                }
            }

          if(unsupported)
            continue;
          if(positional.size() >= 2)
            {
              if((!positional.back().empty()) &&
                 (positional.back().front() == '/') &&
                 (!options.count("branches")))
                mounts->insert(std::move(positional.back()));
              continue;
            }

          if(!positional.empty())
            continue;
          const auto config = options.find("config");
          if((config == options.end()) ||
             (config->second.empty()) ||
             (config->second.front() != '/'))
            continue;
          std::set<std::string> seen;
          std::vector<Source>   referenced;
          rc = read_config_chain(config->second,&seen,&referenced,error,{});
          if(rc)
            return rc;
          for(const Source &source : referenced)
            {
              const auto location = source.options.find("mountpoint");
              if((location != source.options.end()) &&
                 (!location->second.empty()) &&
                 (location->second.front() == '/'))
                mounts->insert(location->second);
            }
        }

      return 0;
    }


    int
    collect_mountpoints(const Roots           &roots,
                        std::set<std::string> *mounts,
                        std::string           *error)
    {
      if(!roots.fstab.empty())
        {
          Document doc;
          int      rc = open_document(roots.fstab,&doc,error);
          if(rc)
            return rc;
          rc = collect_fstab_mountpoints(doc,mounts,error);
          if(rc)
            return rc;
        }

      std::set<std::string> seen_units;
      for(const std::string &directory : roots.systemd_dirs)
        {
          FD  dir;
          int rc = open_directory(directory,&dir,error);
          if(rc == -ENOENT)
            continue;
          if(rc)
            return rc;
          std::unique_ptr<DIR,DirectoryStreamCloser> stream(::fdopendir(::dup(dir.value)));
          if(!stream)
            return fail(error,errno,"cannot list systemd service directory: " + directory);
          std::vector<std::string> names;
          errno = 0;
          while(struct dirent *entry = ::readdir(stream.get()))
            {
              std::string name = entry->d_name;
              if(((name.size() > 8) &&
                  (name.substr(name.size() - 8) == ".service")) ||
                 ((name.size() > 6) &&
                  (name.substr(name.size() - 6) == ".mount")))
                names.push_back(std::move(name));
              errno = 0;
            }

          if(errno)
            return fail(error,errno,"cannot list systemd services");
          std::sort(names.begin(),names.end());
          for(const std::string &name : names)
            {
              if(!seen_units.insert(name).second)
                continue;
              const std::string path = directory + (directory.back() == '/' ? "" : "/") + name;
              Document doc;
              rc = open_document(path,&doc,error);
              if((rc == -ELOOP) || (rc == -ENOENT))
                continue;
              if(rc)
                return rc;
              rc =
                ((name.substr(name.size() - 6) == ".mount") ?
                 collect_mount_unit_mountpoint(doc,mounts,error) :
                 collect_service_mountpoints(doc,mounts,error));
              if(rc)
                return rc;
            }
        }

      return 0;
    }
  }


  int
  list_mountpoints(const Roots              &roots,
                   std::vector<std::string> *mounts,
                   std::string              *error)
  {
    if(error)
      error->clear();
    if(!mounts)
      return fail(error,EINVAL,"invalid mountpoint listing destination");
    mounts->clear();
    std::set<std::string> found;
    int rc = collect_mountpoints(roots,&found,error);
    if(rc)
      return rc;
    mounts->assign(found.begin(),found.end());
    if(error)
      error->clear();
    return 0;
  }


  int
  list_directories(const std::string &path,
                   DirectoryListing  *listing,
                   std::string       *error)
  {
    if(error)
      error->clear();
    if((!listing) || (!safe_path(path)) || (path.size() > 4096))
      return fail(error,EINVAL,"unsafe directory path: " + path);

    FD  dir;
    int rc = open_directory(path,&dir,error);
    if(rc)
      return rc;
    std::unique_ptr<DIR,DirectoryStreamCloser> stream(::fdopendir(dir.value));
    if(!stream)
      return fail(error,errno,"cannot list directory: " + path);
    dir.value = -1; // fdopendir owns this descriptor.

    DirectoryListing result;
    result.path = path;
    if(path != "/")
      {
        size_t slash = path.rfind('/');
        result.parent = ((slash) ? path.substr(0,slash) : "/");
      }

    constexpr size_t MAX_SCANNED_ENTRIES = 16384;
    constexpr size_t MAX_DIRECTORIES     = 4096;
    constexpr size_t MAX_LISTING_BYTES   = 1024 * 1024;
    size_t scanned = 0;
    size_t bytes   = 0;
    for(;;)
      {
        errno = 0;
        struct dirent *entry = ::readdir(stream.get());
        if(!entry)
          {
            if(errno)
              return fail(error,errno,"cannot read directory: " + path);
            break;
          }

        std::string_view name(entry->d_name);
        if((name == ".") || (name == ".."))
          continue;
        if(++scanned > MAX_SCANNED_ENTRIES)
          return fail(error,E2BIG,"directory has too many entries to browse: " + path);
        if(!safe_component(name))
          continue;
        struct stat metadata;
        if(::fstatat(::dirfd(stream.get()),entry->d_name,&metadata,AT_SYMLINK_NOFOLLOW) < 0)
          {
            if(errno == ENOENT)
              continue; // The entry disappeared while listing.
            return fail(error,errno,"cannot inspect directory entry in: " + path);
          }

        if(!S_ISDIR(metadata.st_mode))
          continue;
        const size_t entry_bytes = path.size() + name.size() * 2 + 1;
        if((result.directories.size() == MAX_DIRECTORIES) ||
           (entry_bytes > MAX_LISTING_BYTES - bytes))
          return fail(error,E2BIG,"directory listing is too large to browse: " + path);
        bytes += entry_bytes;
        std::string child =
          ((path == "/") ?
           "/" + std::string(name) :
           path + "/" + std::string(name));
        result.directories.push_back({std::string(name),std::move(child)});
      }

    std::sort(result.directories.begin(),
              result.directories.end(),
              [](const Directory &a, const Directory &b) { return a.name < b.name; });
    *listing = std::move(result);
    return 0;
  }


  int
  discover(const std::string   &mount,
           const Roots         &roots,
           std::vector<Source> *sources,
           std::string         *error)
  {
    if(error)
      error->clear();
    if((!sources) || (mount.empty()) || (mount.front() != '/') || (mount.find('\0') != NPOS))
      return fail(error,EINVAL,"invalid mountpoint or discovery destination");
    int rc = collect(mount,roots,sources,error);
    if((!rc) && (error))
      error->clear();
    return rc;
  }


  int
  create(const Definition &definition,
         const Roots      &roots,
         Created          *created,
         std::string      *error)
  {
    if(error)
      error->clear();
    if((!created) || ((definition.type != "fstab") && (definition.type != "systemd")))
      return fail(error,EINVAL,"invalid persistence definition type or destination");
    if(definition.mountpoint == "/")
      return fail(error,EINVAL,"root cannot be a new mergerfs mountpoint");
    if(!safe_path(definition.mountpoint))
      return fail(error,EINVAL,"unsafe mountpoint path");
    std::vector<std::string> branch_paths;
    int rc = validate_branches(definition.branches,&branch_paths,error);
    if(rc)
      return rc;

    std::string normalized_branches;
    const std::string &written_branches =
      ((strip_default_rw_modes(definition.branches,&normalized_branches)) ?
       normalized_branches :
       definition.branches);

    std::set<std::string> keys;
    std::string           options;
    std::string           ini_text;
    for(const auto &entry : definition.options)
      {
        if((!safe_key(entry.first)) ||
           (!safe_value(entry.second)) ||
           (!keys.insert(entry.first).second))
          {
            return fail(error,
                        EINVAL,
                        "unsafe, duplicate or read-only mergerfs option: " + entry.first);
          }

        if(definition.ini_path.empty())
          {
            if(!options.empty())
              options += ',';
            options += entry.first + "=" + entry.second;
          }
        else
          {
            ini_text += entry.first + "=" + entry.second + "\n";
          }
      }

    if(!definition.ini_path.empty())
      {
        if(!safe_path(definition.ini_path))
          return fail(error,EINVAL,"unsafe mergerfs ini path");
        const std::string name = definition.ini_path.substr(definition.ini_path.rfind('/') + 1);
        if((name.size() <= 4) || (name.substr(name.size() - 4) != ".ini"))
          return fail(error,EINVAL,"new mergerfs config must have a plain .ini filename");
      }

    if(((definition.type == "fstab") &&
        (roots.fstab.empty())) ||
       ((definition.type == "systemd") &&
        ((roots.systemd_dirs.empty()) ||
         (roots.systemd_dirs.front().empty()))))
      return fail(error,EINVAL,"requested persistence root is not configured");

    const std::string unit_name =
      ((definition.type == "systemd") ?
       mount_unit_name(definition.mountpoint) :
       "");
    const std::string path =
      ((definition.type == "fstab") ?
       roots.fstab :
       roots.systemd_dirs.front() + (roots.systemd_dirs.front().back() == '/' ? "" : "/") +
       unit_name);
    if(path == definition.ini_path)
      return fail(error,EINVAL,"ini and mount definition paths must differ");
    if(unit_name.size() > 255)
      return fail(error,ENAMETOOLONG,"systemd mount unit filename exceeds filesystem limit");

    std::lock_guard<std::mutex> lock(save_mutex);
    std::vector<Source> sources;
    rc = collect(definition.mountpoint,roots,&sources,error);
    if(rc)
      return rc;
    if(!sources.empty())
      return fail(error,EEXIST,"a startup definition already exists for this mountpoint");

    Document fstab;
    if(!roots.fstab.empty())
      {
        rc = open_document(roots.fstab,&fstab,error);
        if(rc)
          return rc;
        if(fstab_has_mount(fstab,definition.mountpoint))
          return fail(error,EEXIST,"fstab already defines this mountpoint");
      }

    if(definition.type == "systemd")
      {
        rc = existing_mount_unit(unit_name,roots,error);
        if(rc)
          return rc;
        rc = create_directory(roots.systemd_dirs.front(),error);
        if(rc)
          return rc;
      }

    if(!definition.ini_path.empty())
      {
        const size_t slash = definition.ini_path.rfind('/');
        rc = create_directory(slash ? definition.ini_path.substr(0,slash) : "/",error);
        if(rc)
          return rc;
      }

    rc = create_directory(definition.mountpoint,error);
    if(rc)
      return rc;
    for(const std::string &branch_path : branch_paths)
      {
        rc = create_directory(branch_path,error);
        if(rc)
          return rc;
      }

    NewFile unit;
    if(definition.type == "systemd")
      {
        rc = prepare_new_file(path,&unit,error);
        if(rc)
          return rc;
      }

    NewFile ini;
    if(!definition.ini_path.empty())
      {
        rc = prepare_new_file(definition.ini_path,&ini,error);
        if(rc)
          return rc;
      }

    std::string value =
      ((definition.ini_path.empty()) ?
       (options.empty() ? "defaults" : options) :
       "config=" + definition.ini_path);
    std::string branch_requirements;
    for(const std::string &branch_path : branch_paths)
      {
        if(definition.type == "fstab")
          {
            value += ",x-systemd.requires-mounts-for=" + branch_path;
          }
        else
          {
            if(!branch_requirements.empty())
              branch_requirements += ' ';
            branch_requirements += branch_path;
          }
      }

    std::string text;
    if(definition.type == "fstab")
      {
        const std::string newline = (fstab.text.find("\r\n") != NPOS) ? "\r\n" : "\n";
        text = fstab.text;
        if((!text.empty()) && (text.back() != '\n'))
          text += newline;
        text +=
        written_branches + "\t" + definition.mountpoint + "\tfuse.mergerfs\t" + value + "\t0\t0" +
        newline;
        if(text.size() > MAX_FILE_SIZE)
          return fail(error,EFBIG,"updated fstab exceeds size limit");
      }
    else
      {
        text = "[Unit]\nDescription=mergerfs " +
          definition.mountpoint +
          "\nDefaultDependencies=no\nWants=local-fs.target remote-fs.target" +
          "\nAfter=local-fs.target remote-fs.target\nRequiresMountsFor=" +
          branch_requirements +
          "\nConflicts=umount.target\nBefore=umount.target\n\n" +
          "[Mount]\nWhat=" +
          written_branches +
          "\nWhere=" +
          definition.mountpoint +
          "\nType=fuse.mergerfs\n";
        if((!definition.ini_path.empty()) || (!options.empty()))
          text += "Options=" + value + "\n";
        text += "\n[Install]\nWantedBy=multi-user.target\n";
      }

    if(!definition.ini_path.empty())
      {
        rc = create_new_file(&ini,ini_text,0640,error);
        if(rc)
          return rc;
      }

    if(definition.type == "systemd")
      rc = create_new_file(&unit,text,0644,error);
    else
      rc = replace_document(&fstab,text,error);
    if(rc)
      {
        if((definition.type == "fstab") && (!definition.ini_path.empty()))
          {
            // A directory-sync error occurs after rename. Keep an ini that the
            // newly committed fstab references rather than breaking the entry.
            Document    current;
            Match       match;
            int         count = 0;
            std::string check_error;
            if((open_document(path,&current,&check_error) == 0) &&
               (parse_fstab(current,definition.mountpoint,&match,&count,&check_error) == 0) &&
               (count == 1) &&
               (match.source.options["config"] == definition.ini_path))
              return rc;
          }

        remove_owned_file(&ini);
        return rc;
      }

    created->type       = definition.type;
    created->path       = path;
    created->mountpoint = definition.mountpoint;
    created->ini_path   = definition.ini_path;
    if(error)
      error->clear();
    return 0;
  }


  namespace
  {
    // The token is an optimistic-concurrency fingerprint, not an authorization
    // token. Include both file identity and bytes: replacing a file with the
    // same contents, or changing a referenced config, invalidates a preview.


    void
    fingerprint_bytes(uint64_t         *hash,
                      std::string_view  bytes)
    {
      for(unsigned char byte : bytes)
        {
          *hash ^= byte;
          *hash *= UINT64_C(1099511628211);
        }
    }


    void
    fingerprint_number(uint64_t *hash,
                       uint64_t  number)
    {
      for(unsigned i = 0; i != 8; ++i)
        {
          *hash ^= static_cast<unsigned char>(number);
          *hash *= UINT64_C(1099511628211);
          number >>= 8;
        }
    }


    void
    fingerprint_string(uint64_t         *hash,
                       std::string_view  text)
    {
      fingerprint_number(hash,text.size());
      fingerprint_bytes(hash,text);
    }


    void
    fingerprint_document(uint64_t       *hash,
                         const Document &doc)
    {
      const struct stat &s = doc.metadata;
      fingerprint_number(hash,s.st_dev);
      fingerprint_number(hash,s.st_ino);
      fingerprint_number(hash,s.st_nlink);
      fingerprint_number(hash,s.st_size);
      fingerprint_number(hash,s.st_mode);
      fingerprint_number(hash,s.st_uid);
      fingerprint_number(hash,s.st_gid);
      fingerprint_number(hash,s.st_mtim.tv_sec);
      fingerprint_number(hash,s.st_mtim.tv_nsec);
      fingerprint_number(hash,s.st_ctim.tv_sec);
      fingerprint_number(hash,s.st_ctim.tv_nsec);
      fingerprint_string(hash,doc.text);
    }


    std::string
    fingerprint_hex(uint64_t hash)
    {
      constexpr char digits[] = "0123456789abcdef";
      std::string result(16,'0');
      for(size_t i = result.size(); i != 0; --i)
        {
          result[i - 1] = digits[hash & 15];
          hash >>= 4;
        }

      return result;
    }


    std::vector<std::string_view>
    bounded_lines(const std::string &text)
    {
      std::vector<std::string_view> lines;
      for(size_t begin = 0; begin < text.size();)
        {
          size_t end = text.find('\n',begin);
          end = ((end == NPOS) ? text.size() : end + 1);
          lines.emplace_back(text.data() + begin,end - begin);
          begin = end;
        }

      return lines;
    }


    void
    changed_lines(const std::string &before,
                  const std::string &after,
                  Preview           *result)
    {
      result->changed = before != after;
      result->before.clear();
      result->after.clear();
      result->before_line = result->after_line = 0;
      if(!result->changed)
        return;
      const auto old_lines = bounded_lines(before);
      const auto new_lines = bounded_lines(after);
      size_t first = 0;
      while((first < old_lines.size()) &&
            (first < new_lines.size()) &&
            (old_lines[first] == new_lines[first]))
        ++first;
      size_t old_end = old_lines.size();
      size_t new_end = new_lines.size();
      while((old_end > first) &&
            (new_end > first) &&
            (old_lines[old_end - 1] == new_lines[new_end - 1]))
        {
          --old_end;
          --new_end;
        }

      result->before_line = result->after_line = first + 1;
      for(size_t i = first; i < old_end; ++i)
        result->before.append(old_lines[i]);
      for(size_t i = first; i < new_end; ++i)
        result->after.append(new_lines[i]);
    }


    struct ChainEntry
    {
      std::string next;
      uint64_t fingerprint;
    };


    int
    config_chain(const std::string                &start,
                 const std::string                &source_path,
                 std::map<std::string,ChainEntry> *cache,
                 std::vector<std::string>         *paths,
                 std::string                      *error)
    {
      std::set<std::string> seen;
      paths->clear();
      paths->push_back(source_path);
      for(std::string path = start; !path.empty();)
        {
          if((path == source_path) || (!seen.insert(path).second))
            return fail(error,ELOOP,"cyclic mergerfs config reference: " + path);
          if(!safe_path(path))
            return fail(error,EINVAL,"unsafe mergerfs config reference: " + path);
          auto entry = cache->find(path);
          if(entry == cache->end())
            {
              Document doc;
              int      rc = open_document(path,&doc,error);
              if(rc)
                return rc;
              Match match;
              rc = parse_ini(doc,&match,nullptr,nullptr,error);
              if(rc)
                return rc;
              const auto config      = match.source.options.find("config");
              const std::string next = (config == match.source.options.end()) ? "" : config->second;
              uint64_t hash = UINT64_C(14695981039346656037);
              fingerprint_document(&hash,doc);
              entry = cache->emplace(path,ChainEntry{next,hash}).first;
            }

          paths->push_back(path);
          path = entry->second.next;
        }

      return 0;
    }


    int
    validate_save_option(const std::string &mount,
                         const std::string &type,
                         const std::string &key,
                         const std::string &value,
                         bool               remove,
                         std::string       *error)
    {
      if((mount.empty()) || (mount.front() != '/') || (mount.find('\0') != NPOS))
        return fail(error,EINVAL,"unsafe or read-only persistence option");
      if(remove)
        {
          if(((!safe_key(key)) && (key != "config")) || (!value.empty()))
            return fail(error,EINVAL,"unsafe or read-only persistence option removal");
          return 0;
        }

      if(((!safe_key(key)) &&
          (key != "branches") &&
          (key != "config")) ||
         ((key != "branches") &&
          ((key == "config") ?
           !safe_path(value) :
           (type == "ini") ?
           ((!value.empty()) && (!safe_branches(value))) :
           !safe_value(value))))
        return fail(error,EINVAL,"unsafe or read-only persistence option");
      if(key == "branches")
        return validate_branches(value,nullptr,error);
      return 0;
    }


    int
    prepare_save(const std::string &mount,
                 const Roots       &roots,
                 const std::string &type,
                 const std::string &path,
                 const std::string &key,
                 const std::string &value,
                 bool               remove,
                 Document          *doc,
                 std::string       *updated,
                 Preview           *result,
                 std::string       *error)
    {
      int rc = validate_save_option(mount,type,key,value,remove,error);
      if(rc)
        return rc;

      std::string normalized_branches;
      const std::string &written_value =
        ((((key == "branches") &&
           (strip_default_rw_modes(value,&normalized_branches)))) ?
         normalized_branches :
         value);
      std::vector<Source> sources;
      rc = collect(mount,roots,&sources,error);
      if(rc)
        return rc;
      const auto found = std::find_if(sources.begin(),
                                      sources.end(),
                                      [&](const Source &source)
                                      {
                                        return ((source.type == type) && (source.path == path));
                                      });
      if(found == sources.end())
        return fail(error,ENOENT,"requested persistence source does not define this mount");
      if((remove) && (!found->options.count(key)))
        return fail(error,ENOENT,"option is absent from the selected persistence source");
      if((remove) &&
         (key == "config") &&
         (type == "systemd") &&
         (path.size() >= 8) &&
         (path.substr(path.size() - 8) == ".service") &&
         (!found->options.count("branches")))
        return fail(error,EINVAL,"cannot remove config from a config-only service");
      if((key == "config") && (!remove))
        {
          const auto previous = found->options.find("config");
          if((previous == found->options.end()) || (previous->second != value))
            {
              std::set<std::string> seen;
              const bool config_only_service =
                ((type == "systemd") &&
                 (path.size() >= 8) &&
                 (path.substr(path.size() - 8) == ".service") &&
                 (!found->options.count("branches")));
              std::vector<Source> referenced;
              rc = read_config_chain(value,
                                     &seen,
                                     config_only_service ? &referenced : nullptr,
                                     error,
                                     type == "ini" ? std::string_view(path) : std::string_view{});
              if(rc)
                return rc;
              if((config_only_service) &&
                 (std::none_of(referenced.begin(),
                               referenced.end(),
                               [&](const Source &source)
                               {
                                 const auto location = source.options.find("mountpoint");
                                 return ((location != source.options.end()) &&
                                         (location->second == mount));
                               })))
                {
                  return fail(error,
                              EINVAL,
                              "config-only service requires a config for this mountpoint");
                }
            }
        }

      if((type == "ini") && (key == "branches"))
        {
          const auto location = found->options.find("mountpoint");
          const bool config_only = std::any_of(sources.begin(),
                                               sources.end(),
                                               [&](const Source &source)
                                               {
                                                 const auto config = source.options.find("config");
                                                 return ((source.type == "systemd") &&
                                                         (config != source.options.end()) &&
                                                         (config->second == path) &&
                                                         (!source.options.count("branches")));
                                               });
          if((location == found->options.end()) || (location->second != mount) || (!config_only))
            return fail(error,ENOTSUP,"ini branches cannot replace a positional mount source");
        }

      rc = open_document(path,doc,error);
      if(rc)
        return rc;
      Match match;
      if(type == "fstab")
        {
          int count = 0;
          rc = parse_fstab(*doc,mount,&match,&count,error);
          if((!rc) && (count != 1))
            rc = fail(error,EAGAIN,"fstab mount definition changed since discovery");
          if((!rc) && (key != "branches"))
            {
              const std::string_view raw =
                std::string_view(doc->text).substr(match.begin,match.end - match.begin);
              if(remove)
                {
                  if(!remove_option(raw,key,&match.replacement))
                    {
                      rc = fail(error,ENOENT,"option is absent from this fstab entry");
                    }
                  else
                    {
                      if(key == "x-systemd.requires-mounts-for")
                        {
                          std::string next;
                          while(remove_option(match.replacement,key,&next))
                            match.replacement = std::move(next);
                        }

                      if(match.replacement.empty())
                        {
                          if(key == "defaults")
                            {
                              rc = fail(error,
                                        EINVAL,
                                        "cannot remove the sole fstab defaults placeholder");
                            }
                          else
                            {
                              match.replacement = "defaults";
                            }
                        }
                    }
                }
              else if(key == "x-systemd.requires-mounts-for")
                {
                  // This option is emitted once per branch. A single-value edit
                  // cannot update a multi-branch dependency list without
                  // making it disagree with the configured branch paths.
                  std::vector<std::string> paths;
                  rc = branch_mount_paths(match.source.options.at("branches"),&paths,error);
                  if(rc)
                    return rc;
                  if((paths.size() != 1) || (value != paths.front()))
                    {
                      return fail(error,
                                  ENOTSUP,
                                  "edit branches to update fstab branch dependencies");
                    }

                  size_t occurrences = 0;
                  constexpr std::string_view dependency = "x-systemd.requires-mounts-for";
                  for(size_t start = 0; start < raw.size();)
                    {
                      size_t end = raw.find(',',start);
                      if(end == NPOS)
                        end = raw.size();
                      const std::string_view item = raw.substr(start,end - start);
                      if(item.substr(0,item.find('=')) == dependency)
                        ++occurrences;
                      start = end + (end != raw.size());
                    }

                  if(occurrences > 1)
                    {
                      return fail(error,
                                  ENOTSUP,
                                  "edit branches to update repeated fstab branch dependencies");
                    }

                  match.replacement = update_fstab_options(raw,key,value);
                }
              else
                {
                  match.replacement = update_fstab_options(raw,key,value);
                }
            }
        }
      else if(type == "systemd")
        {
          int count = 0;
          rc =
            ((((path.size() >= 6) && (path.substr(path.size() - 6) == ".mount"))) ?
             parse_mount_unit(*doc,mount,&match,&count,&key,&written_value,error,remove) :
             parse_service(*doc,mount,&match,&count,&key,&written_value,error,remove));
          if((!rc) && (count != 1))
            rc = fail(error,EAGAIN,"service mount definition changed since discovery");
        }
      else if(type == "ini")
        {
          rc = parse_ini(*doc,&match,&key,&written_value,error,remove);
        }
      else
        {
          return fail(error,EINVAL,"unsupported persistence source type");
        }

      if(rc)
        return rc;
      if((remove) && (!match.source.options.count(key)))
        return fail(error,ENOENT,"option is absent from this persistence source");
      if((match.begin > match.end) || (match.end > doc->text.size()))
        return fail(error,EINVAL,"invalid persistence replacement span");
      *updated = doc->text;
      if((type == "fstab") && (key == "branches"))
        {
          rc = update_fstab_branches(*doc,match,written_value,updated,error);
        }
      else if((type == "systemd") &&
              (key == "branches") &&
              (path.size() >= 6) &&
              (path.substr(path.size() - 6) == ".mount"))
        {
          rc = update_mount_unit_branches(*doc,match,written_value,updated,error);
        }
      else
        {
          updated->replace(match.begin,match.end - match.begin,match.replacement);
        }

      if(rc)
        return rc;
      if(updated->size() > MAX_FILE_SIZE)
        return fail(error,EFBIG,"updated persistence file exceeds size limit");
      if((type == "ini") && (*updated != doc->text))
        {
          std::vector<Source> confirmed;
          rc = collect(mount,roots,&confirmed,error);
          if(rc)
            return rc;
          if(std::none_of(confirmed.begin(),
                          confirmed.end(),
                          [&](const Source &source)
                          {
                            return ((source.type == type) && (source.path == path));
                          }))
            return fail(error,EAGAIN,"config file is no longer referenced by this mount");
        }

      if(!result)
        return 0;
      result->path = path;
      changed_lines(doc->text,*updated,result);
      const auto config = match.source.options.find("config");
      const std::string before_config =
        ((config == match.source.options.end()) ?
         "" :
         config->second);
      const std::string after_config = (key == "config") ? (remove ? "" : value) : before_config;
      std::map<std::string,ChainEntry> cache;
      rc = config_chain(before_config,path,&cache,&result->config_before,error);
      if(rc)
        return rc;
      rc = config_chain(after_config,path,&cache,&result->config_after,error);
      if(rc)
        return rc;
      uint64_t hash = UINT64_C(14695981039346656037);
      fingerprint_string(&hash,path);
      fingerprint_document(&hash,*doc);
      for(const auto &entry : cache)
        {
          fingerprint_string(&hash,entry.first);
          fingerprint_number(&hash,entry.second.fingerprint);
          fingerprint_string(&hash,entry.second.next);
        }

      fingerprint_number(&hash,result->config_before.size());
      for(const std::string &item : result->config_before)
        fingerprint_string(&hash,item);
      fingerprint_number(&hash,result->config_after.size());
      for(const std::string &item : result->config_after)
        fingerprint_string(&hash,item);
      result->revision = fingerprint_hex(hash);
      return 0;
    }


    bool
    valid_utf8(std::string_view text)
    {
      for(size_t i = 0; i < text.size();)
        {
          const unsigned char first = static_cast<unsigned char>(text[i]);
          if(first < 0x80)
            {
              ++i;
              continue;
            }

          const size_t length =
            ((((first >= 0xc2) && (first <= 0xdf))) ?
             2 :
             (((first >= 0xe0) && (first <= 0xef))) ?
             3 :
             (((first >= 0xf0) && (first <= 0xf4))) ?
             4 :
             0);
          if((!length) || (length > text.size() - i))
            return false;
          const unsigned char second = static_cast<unsigned char>(text[i + 1]);
          if((second < 0x80) ||
             (second > 0xbf) ||
             ((first == 0xe0) &&
              (second < 0xa0)) ||
             ((first == 0xed) &&
              (second > 0x9f)) ||
             ((first == 0xf0) &&
              (second < 0x90)) ||
             ((first == 0xf4) &&
              (second > 0x8f)))
            return false;
          for(size_t j = 2; j < length; ++j)
            {
              if((static_cast<unsigned char>(text[i + j]) & 0xc0) != 0x80)
                return false;
            }

          i += length;
        }

      return true;
    }


    bool
    valid_raw_text(std::string_view text,
                   bool             single_line)
    {
      if((single_line) && (text.empty()))
        return false;
      for(unsigned char c : text)
        {
          if((c == 0) ||
             ((c < 32) &&
              (c != '\t') &&
              ((single_line) ||
               ((c != '\n') &&
                (c != '\r')))))
            return false;
        }

      return valid_utf8(text);
    }


    bool
    raw_supported(const std::string &type,
                  const std::string &path)
    {
      return ((type == "fstab") ||
              (type == "ini") ||
              ((type == "systemd") &&
               (path.size() >= 6) &&
               (path.compare(path.size() - 6,6,".mount") == 0)));
    }


    int
    prepare_raw(const std::string &mount,
                const Roots       &roots,
                const std::string &type,
                const std::string &path,
                Document          *doc,
                Raw               *result,
                size_t            *row_begin,
                size_t            *row_end,
                std::string       *error)
    {
      if((mount.empty()) ||
         (mount.front() != '/') ||
         (mount.find('\0') != NPOS) ||
         (path.empty()) ||
         (path.find('\0') != NPOS))
        return fail(error,EINVAL,"invalid raw persistence source");
      if(!raw_supported(type,path))
        {
          return fail(error,
                      ENOTSUP,
                      "raw editing is supported only for fstab, .mount and referenced ini");
        }

      std::vector<Source> sources;
      int rc = collect(mount,roots,&sources,error);
      if(rc)
        return rc;
      if(std::none_of(sources.begin(),
                      sources.end(),
                      [&](const Source &source)
                      {
                        return ((source.type == type) && (source.path == path));
                      }))
        {
          return fail(error,
                      ENOENT,
                      "requested raw persistence source is not discovered for this mount");
        }

      rc = open_document(path,doc,error);
      if(rc)
        return rc;
      result->type  = type;
      result->path  = path;
      result->scope = ((type == "fstab") ? "entry" : "file");
      if(type == "fstab")
        {
          Match match;
          int   count = 0;
          rc = parse_fstab(*doc,mount,&match,&count,error);
          if(rc)
            return rc;
          if(count != 1)
            return fail(error,EAGAIN,"fstab entry changed since discovery");
          const size_t preceding = doc->text.rfind('\n',match.branch_begin);
          *row_begin = ((preceding == NPOS) ? 0 : preceding + 1);
          const size_t newline = doc->text.find('\n',*row_begin);
          *row_end = ((newline == NPOS) ? doc->text.size() : newline);
          if((*row_end > *row_begin) && (doc->text[*row_end - 1] == '\r'))
            --*row_end;
          result->text = doc->text.substr(*row_begin,*row_end - *row_begin);
        }
      else
        {
          result->text = doc->text;
        }

      if(!valid_raw_text(result->text,false))
        return fail(error,ENOTSUP,"persistence source cannot be represented as UTF-8 text");
      uint64_t hash = UINT64_C(14695981039346656037);
      fingerprint_string(&hash,mount);
      fingerprint_string(&hash,type);
      fingerprint_string(&hash,path);
      fingerprint_document(&hash,*doc);
      result->revision = fingerprint_hex(hash);
      return 0;
    }
  }


  int
  raw_read(const std::string &mount,
           const Roots       &roots,
           const std::string &type,
           const std::string &path,
           Raw               *result,
           std::string       *error)
  {
    if(error)
      error->clear();
    if(!result)
      return fail(error,EINVAL,"missing raw persistence destination");
    std::lock_guard<std::mutex> lock(save_mutex);
    Document doc;
    size_t   row_begin = 0;
    size_t   row_end = 0;
    return prepare_raw(mount,roots,type,path,&doc,result,&row_begin,&row_end,error);
  }


  int
  raw_save(const std::string &mount,
           const Roots       &roots,
           const std::string &type,
           const std::string &path,
           const std::string &text,
           const std::string &expected_revision,
           std::string       *error)
  {
    if(error)
      error->clear();
    if(expected_revision.empty())
      return fail(error,EINVAL,"raw save requires an expected revision");
    if(text.size() > MAX_FILE_SIZE)
      return fail(error,EFBIG,"raw persistence text exceeds size limit");
    if(!valid_raw_text(text,type == "fstab"))
      {
        return fail(error,
                    ENOTSUP,
                    "raw persistence text must be valid UTF-8 without control characters");
      }

    std::lock_guard<std::mutex> lock(save_mutex);
    Document doc;
    Raw      current;
    size_t   row_begin = 0;
    size_t   row_end = 0;
    int      rc = prepare_raw(mount,roots,type,path,&doc,&current,&row_begin,&row_end,error);
    if((rc == -EAGAIN) || (rc == -ESTALE))
      {
        return fail(error,
                    EAGAIN,
                    "raw persistence source changed since it was read; reload before saving");
      }

    if(rc)
      return rc;
    if(expected_revision != current.revision)
      {
        return fail(error,
                    EAGAIN,
                    "raw persistence source changed since it was read; reload before saving");
      }

    std::string updated;
    if(type == "fstab")
      {
        Document candidate;
        candidate.text = text;
        Match parsed;
        int   count = 0;
        rc = parse_fstab(candidate,mount,&parsed,&count,error);
        if((rc) || (count != 1))
          {
            return fail(error,
                        ENOTSUP,
                        "raw fstab edit must remain one mergerfs entry for the same mount");
          }

        rc = validate_branches(parsed.source.options.at("branches"),nullptr,error);
        if(rc)
          return fail(error,ENOTSUP,"raw fstab entry has invalid mergerfs branches");
        updated = doc.text;
        updated.replace(row_begin,row_end - row_begin,text);
      }
    else
      {
        updated = text;
      }

    if(updated.size() > MAX_FILE_SIZE)
      return fail(error,EFBIG,"updated persistence file exceeds size limit");
    if(updated == doc.text)
      return 0;
    std::vector<Source> confirmed;
    rc = collect(mount,roots,&confirmed,error);
    if((rc == -ENOENT) || (rc == -ELOOP) || (rc == -EINVAL) || (rc == -EAGAIN) || (rc == -ESTALE))
      return fail(error,EAGAIN,"raw persistence source changed before saving");
    if(rc)
      return rc;
    if(std::none_of(confirmed.begin(),
                    confirmed.end(),
                    [&](const Source &source)
                    {
                      return ((source.type == type) && (source.path == path));
                    }))
      return fail(error,EAGAIN,"raw persistence source is no longer discovered for this mount");
    rc = replace_document(&doc,updated,error);
    if((!rc) && (error))
      error->clear();
    return rc;
  }


  int
  preview(const std::string &mount,
          const Roots       &roots,
          const std::string &type,
          const std::string &path,
          const std::string &key,
          const std::string &value,
          Preview           *result,
          std::string       *error,
          bool               remove)
  {
    if(error)
      error->clear();
    if(!result)
      return fail(error,EINVAL,"missing persistence preview destination");
    std::lock_guard<std::mutex> lock(save_mutex);
    Document    doc;
    std::string updated;
    return prepare_save(mount,roots,type,path,key,value,remove,&doc,&updated,result,error);
  }


  int
  save(const std::string &mount,
       const Roots       &roots,
       const std::string &type,
       const std::string &path,
       const std::string &key,
       const std::string &value,
       std::string       *error,
       const std::string *expected_revision,
       bool               remove)
  {
    if(error)
      error->clear();
    int rc = validate_save_option(mount,type,key,value,remove,error);
    if(rc)
      return rc;
    std::lock_guard<std::mutex> lock(save_mutex);
    Document    doc;
    std::string updated;
    Preview     result;
    rc = prepare_save(mount,
                      roots,
                      type,
                      path,
                      key,
                      value,
                      remove,
                      &doc,
                      &updated,
                      expected_revision ? &result : nullptr,
                      error);
    if((expected_revision) &&
       ((rc == -ENOENT) ||
        (rc == -ELOOP) ||
        (rc == -EINVAL) ||
        (rc == -ENOTSUP) ||
        (rc == -EAGAIN) ||
        (rc == -ESTALE)))
      return fail(error,EAGAIN,"persistence source or config changed since preview; preview again");
    if(rc)
      return rc;
    if((expected_revision) && (*expected_revision != result.revision))
      return fail(error,EAGAIN,"persistence source or config changed since preview; preview again");
    if(updated == doc.text)
      return 0;
    rc = replace_document(&doc,updated,error);
    if((!rc) && (error))
      error->clear();
    return rc;
  }


  int
  remove(const std::string &mount,
         const Roots       &roots,
         const std::string &type,
         const std::string &path,
         std::string       *retained_ini_path,
         std::string       *error)
  {
    if(error)
      error->clear();
    if((!retained_ini_path) ||
       (mount.empty()) ||
       (mount.front() != '/') ||
       (mount.find('\0') != NPOS) ||
       ((type != "fstab") &&
        (type != "systemd")))
      return fail(error,EINVAL,"invalid mountpoint or removable persistence source");
    retained_ini_path->clear();
    std::lock_guard<std::mutex> lock(save_mutex);
    std::vector<Source> sources;
    int rc = collect(mount,roots,&sources,error);
    if(rc)
      return rc;
    const auto found = std::find_if(sources.begin(),
                                    sources.end(),
                                    [&](const Source &source)
                                    {
                                      return ((source.type == type) && (source.path == path));
                                    });
    if(found == sources.end())
      return fail(error,ENOENT,"requested persistence source does not define this mount");

    Document doc;
    rc = open_document(path,&doc,error);
    if(rc)
      return rc;
    Match match;
    int   count = 0;
    if(type == "fstab")
      {
        rc = parse_fstab(doc,mount,&match,&count,error);
      }
    else if((path.size() >= 6) && (path.substr(path.size() - 6) == ".mount"))
      {
        rc = parse_mount_unit(doc,mount,&match,&count,nullptr,nullptr,error);
      }
    else
      {
        rc = parse_service(doc,mount,&match,&count,nullptr,nullptr,error);
        if(!rc)
          {
            const int execstarts = count_service_execstarts(doc.text,error);
            if(execstarts < 0)
              return execstarts;
            if(execstarts != 1)
              {
                return fail(error,
                            ENOTSUP,
                            "cannot remove a service with multiple ExecStart definitions");
              }
          }
      }

    if(rc)
      return rc;
    if((count != 1) || (match.source.options != found->options))
      return fail(error,EAGAIN,"mount definition changed since discovery");

    const auto config = found->options.find("config");
    const std::string retained = (config == found->options.end()) ? "" : config->second;
    if(type == "fstab")
      {
        const size_t previous_newline = doc.text.rfind('\n',match.branch_begin);
        const size_t begin   = (previous_newline == NPOS) ? 0 : previous_newline + 1;
        const size_t newline = doc.text.find('\n',match.branch_end);
        const size_t end     = (newline == NPOS) ? doc.text.size() : newline + 1;
        std::string updated  = doc.text;
        updated.erase(begin,end - begin);
        rc = replace_document(&doc,updated,error);
      }
    else
      {
        rc = unlink_document(&doc,error);
      }

    if(rc)
      return rc;
    *retained_ini_path = retained;
    if(error)
      error->clear();
    return 0;
  }
}
