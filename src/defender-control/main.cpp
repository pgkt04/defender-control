#include "dcontrol.hpp"
#include "wmic.hpp"

// to-do:
// write argument parser
// create cli program
// maybe make a ui for this

// entrypoint
//
int main()
{
  printf(DCONTROL::check_defender() ?
    "Windows defender is ACTIVE turning off..\n" :
    "Windows defender is OFF turning on...\n");

  if (DCONTROL::check_defender())
    wmic::test_exec(true);
  else
    wmic::test_exec(false);

  system("pause");

  return 0;
}
