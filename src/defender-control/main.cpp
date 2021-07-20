// to-do:
// write argument parser
// create cli program
// maybe make a ui for this
//
#include "dcontrol.hpp"
#include "wmic.hpp"

int main()
{
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
