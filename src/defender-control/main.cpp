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
    "Windows defender is ACTIVE\n" :
    "Windows defender is OFF\n");

  wmic::test_exec();

  system("pause");

  return 0;
}
