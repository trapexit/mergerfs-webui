#include "mergerfs_update.hpp"
#include "json.hpp"

#include <cstdlib>
#include <iostream>
#include <map>

using nlohmann::json;

namespace
{
  struct Context
  {
    std::map<std::string,std::string> owners;
    std::string switch_path;
    unsigned hits = 0;
    unsigned switch_after = 1;
  };


  MergerfsUpdate::Owner
  lookup(const std::string &path,
         void              *pointer)
  {
    Context &context = *static_cast<Context*>(pointer);
    if((path == context.switch_path) && (++context.hits > context.switch_after))
      return MergerfsUpdate::Owner::PACKAGE;
    const auto found = context.owners.find(path);
    if(found == context.owners.end())
      return MergerfsUpdate::Owner::UNOWNED;
    if(found->second == "package")
      return MergerfsUpdate::Owner::PACKAGE;
    return MergerfsUpdate::Owner::UNKNOWN;
  }


  json
  describe(const MergerfsUpdate::Status &s)
  {
    return {
        {"state",s.state},
        {"path",s.path},
        {"version",s.version},
        {"manager",s.manager},
        {"package",s.package},
        {"static_version",s.static_version},
        {"in_place_allowed",s.in_place_allowed},
        {"static_install_allowed",s.static_install_allowed},
        {"warnings",s.warnings}
      };
  }
}


int
main(int    argc,
     char **argv)
{
  if((argc < 5) || ((std::string(argv[1]) != "status") && (std::string(argv[1]) != "install")))
    return 2;
  Context context;
  try
    {
      context.owners = json::parse(argv[4]).get<std::map<std::string,std::string>>();
    }
  catch(const json::exception &)
    {
      return 2;
    }

  MergerfsUpdate::Fixture fixture{argv[2],argv[3],lookup,&context};
  std::string error;
  if(std::string(argv[1]) == "status")
    {
      if(argc != 5)
        return 2;
      MergerfsUpdate::Status status;
      int rc = MergerfsUpdate::test_status(fixture,&status,&error);
      std::cout << json{{"rc",rc},{"error",error},{"status",describe(status)}} << '\n';
    }
  else
    {
      if((argc != 10) && (argc != 11))
        return 2;
      MergerfsUpdate::Release release{argv[6],{},argv[7],std::strtoull(argv[8],nullptr,10)};
      if(argc == 11)
        {
          context.switch_path = argv[10];
          const size_t separator = context.switch_path.rfind('@');
          if(separator != std::string::npos)
            {
              context.switch_after =
              std::strtoul(context.switch_path.c_str() + separator + 1,nullptr,10);
              context.switch_path.resize(separator);
            }
        }

      MergerfsUpdate::Result result;
      int rc = MergerfsUpdate::test_install_archive(fixture,release,argv[5],argv[9],&result,&error);
      std::cout <<
          json{
              {"rc",rc},
              {"error",error},
              {"result",{{"path",result.path},{"warnings",result.warnings}}}
            } << '\n';
    }
}
