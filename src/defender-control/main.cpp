#include "dcontrol.h"

// to-do:
// write argument parser
// create cli program
// maybe make a ui for this



// entrypoint
//
int main()
{
  if (DCONTROL::is_av_running()) {
    printf("running...\n");
  }
  else {
    printf("not running...\n");
  }

  system("pause");

  return 0;
}
