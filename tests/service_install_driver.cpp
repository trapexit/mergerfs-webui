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

#include <cstring>
#include <charconv>
#include <iostream>


int
main(int    argc_,
     char **argv_)
{
  if((argc_ == 2) && (std::strcmp(argv_[1],"runnable-running") == 0))
    {
      std::string path;
      std::string error;
      if(ServiceInstall::runnable_running_executable(&path,&error) != 0)
        {
          std::cerr << error << '\n';
          return 1;
        }

      std::cout << path << '\n';
      return 0;
    }

  if((argc_ == 4) && (std::strcmp(argv_[1],"stage") == 0))
    {
      bool created = false;
      std::string error;
      if(ServiceInstall::stage_executable(argv_[2],argv_[3],&created,&error) != 0)
        {
          std::cerr << error << '\n';
          return 1;
        }

      std::cout << (created ? "created" : "unchanged") << '\n';
      return 0;
    }

  if((argc_ == 4) && (std::strcmp(argv_[1],"password") == 0))
    {
      bool created = false;
      std::string error;
      if(ServiceInstall::create_password(argv_[2],argv_[3],&created,&error) != 0)
        {
          std::cerr << error << '\n';
          return 1;
        }

      std::cout << (created ? "created" : "unchanged") << '\n';
      return 0;
    }

  if((argc_ == 4) && (std::strcmp(argv_[1],"replace-password") == 0))
    {
      std::string error;
      if(ServiceInstall::replace_password(argv_[2],argv_[3],&error) != 0)
        {
          std::cerr << error << '\n';
          return 1;
        }

      std::cout << "replaced\n";
      return 0;
    }

  if((argc_ == 11) && (std::strcmp(argv_[1],"replace") == 0))
    {
      ServiceInstall::Spec current{argv_[3],argv_[4],8080,
                                   std::strcmp(argv_[5],"none") == 0 ? "" : argv_[5]};
      if(std::strcmp(argv_[6],"other-port") == 0)
        current.port = 8081;
      else if(std::strcmp(argv_[6],"default") != 0)
        {
          int port = 0;
          const auto end = argv_[6] + std::strlen(argv_[6]);
          const auto parsed = std::from_chars(argv_[6],end,port);
          if((parsed.ec != std::errc{}) || (parsed.ptr != end) ||
             (port < 1) || (port > 65535))
            {
              std::cerr << "unknown current port: " << argv_[6] << '\n';
              return 2;
            }
          current.port = port;
        }
      ServiceInstall::Spec spec{argv_[7],argv_[8],8081,
                                std::strcmp(argv_[9],"none") == 0 ? "" : argv_[9]};
      if(std::strcmp(argv_[10],"default-port") == 0)
        spec.port = 8080;
      else if(std::strcmp(argv_[10],"same-port") == 0)
        spec.port = current.port;
      else
        {
          int port = 0;
          const auto end = argv_[10] + std::strlen(argv_[10]);
          const auto parsed = std::from_chars(argv_[10],end,port);
          if((parsed.ec != std::errc{}) || (parsed.ptr != end) ||
             (port < 1) || (port > 65535))
            {
              std::cerr << "unknown new port: " << argv_[10] << '\n';
              return 2;
            }
          spec.port = port;
        }
      bool created = false;
      std::string error;
      int rv = ServiceInstall::replace_unit(current,spec,argv_[2],&created,&error);
      if(rv < 0)
        {
          std::cerr << rv << ": " << error << '\n';
          return 1;
        }

      std::cout << (created ? "replaced" : "unchanged") << '\n';
      return 0;
    }

  if((argc_ == 4) && (std::strcmp(argv_[1],"validate") == 0))
    {
      ServiceInstall::Spec spec{argv_[2],"0.0.0.0",8080,
                               std::strcmp(argv_[3],"none") == 0 ? "" : argv_[3]};
      std::string error;
      if(ServiceInstall::validate(spec,&error) != 0)
        {
          std::cerr << error << '\n';
          return 1;
        }

      std::cout << "valid\n";
      return 0;
    }

  if((argc_ == 3) &&
     ((std::strcmp(argv_[1],"inspect") == 0) ||
      (std::strcmp(argv_[1],"remove-installed") == 0)))
    {
      ServiceInstall::Spec spec;
      bool installed = false;
      std::string error;
      int rv = ServiceInstall::inspect(argv_[2],&spec,&installed,&error);
      if((rv == 0) && installed && (std::strcmp(argv_[1],"remove-installed") == 0))
        rv = ServiceInstall::remove_unit(spec,argv_[2],&error);
      if(rv < 0)
        {
          std::cerr << rv << ": " << error << '\n';
          return 1;
        }

      if(!installed)
        std::cout << "absent\n";
      else
        std::cout << spec.executable << '\t' << spec.host << '\t'
                  << spec.port << '\t' << spec.password_file << '\n';
      return 0;
    }

  if((argc_ == 7) && (std::strcmp(argv_[1],"remove") == 0))
    {
      ServiceInstall::Spec spec{argv_[3],argv_[4],8080,std::strcmp(argv_[5],"none") == 0 ? "" : argv_[5]};
      if(std::strcmp(argv_[6],"other-port") == 0)
        spec.port = 8081;
      std::string error;
      int rv = ServiceInstall::remove_unit(spec,argv_[2],&error);
      if(rv < 0)
        {
          std::cerr << rv << ": " << error << '\n';
          return 1;
        }

      std::cout << "removed\n";
      return 0;
    }

  if(argc_ != 6)
    return 2;
  ServiceInstall::Spec spec{argv_[2],argv_[3],8080,std::strcmp(argv_[4],"none") == 0 ? "" : argv_[4]};
  if(std::strcmp(argv_[5],"other-port") == 0)
    spec.port = 8081;
  else if(std::strcmp(argv_[5],"default") != 0)
    {
      const char *end = argv_[5] + std::strlen(argv_[5]);
      const auto parsed = std::from_chars(argv_[5],end,spec.port);
      if((parsed.ec != std::errc()) || (parsed.ptr != end))
        return 2;
    }
  bool created = false;
  std::string error;
  int rv = ServiceInstall::write_unit(spec,argv_[1],&created,&error);
  if(rv < 0)
    {
      std::cerr << error << '\n';
      return 1;
    }

  std::cout << (created ? "created" : "unchanged") << '\n';
  return 0;
}
