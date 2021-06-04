#include "dcontrol.h"

// to-do:
// write argument parser
// create cli program
// maybe make a ui for this

// entrypoint
//
int main()
{
  if (DCONTROL::check_defender()) {
    printf("Windows defender is ACTIVE\n");
  }
  else {
    printf("Windows defender is OFF\n");
  }

  system("pause");

  return 0;
}
