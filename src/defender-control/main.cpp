// to-do:
// write argument parser
// create cli program
// maybe make a ui for this
//
#include "dcontrol.hpp"
#include "wmic.hpp"
#include "trusted.hpp"

int main()
{
  if (!trusted::is_system_group())
  {
    // Because we are a primary token, we can't swap ourselves with an impersonation token
    // There will always be a need to re-create the process with the token as primary.
    // 
    auto path = util::get_current_path();
    std::cout << path << std::endl;

    system("pause");
    return 1;
  }

  printf(dcontrol::check_defender() ?
    "Windows defender is ACTIVE\n" :
    "Windows defender is OFF\n");

  if (dcontrol::check_defender())
  {
    if (dcontrol::disable_defender())
      printf("Disabled windows defender!\n");
  }
  else
  {
    if (dcontrol::enable_defender())
      printf("Enabled windows defender!\n");
  }

  system("pause");
  return 0;
}
