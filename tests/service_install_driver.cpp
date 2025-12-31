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
#include <iostream>


int
main(int    argc_,
     char **argv_)
{
  if((argc_ == 2) && (std::strcmp(argv_[1],"trust-running") == 0))
    {
      std::string path;
      std::string error;
      if(ServiceInstall::trusted_running_executable(&path,&error) != 0)
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
