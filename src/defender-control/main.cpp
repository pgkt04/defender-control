// to-do:
// make a ui for this
//
#include "dcontrol.hpp"
#include "wmic.hpp"
#include "trusted.hpp"

int main(int argc, char** argv)
{
  if (!trusted::has_admin())
  {
    printf("Must run as admin!\n");
    system("pause");
    return EXIT_FAILURE;
  }

  // Because we are a primary token, we can't swap ourselves with an impersonation token.
  // There will always be a need to re-create the process with the token as primary.
  //
  if (!trusted::is_system_group() && argc == 1)
  {
    printf("Restarting with privileges\n");
    trusted::create_process(util::get_current_path());
    return EXIT_SUCCESS;
  }

  try
  {
    // Disable smart screen, defender & tamper protection
    //
    dcontrol::kill_smartscreen();
    dcontrol::manage_windefend(false);
    dcontrol::toggle_tamper(false);

    printf(dcontrol::check_defender() ?
      "Windows defender is ACTIVE\n" :
      "Windows defender is OFF\n");

    if (dcontrol::disable_defender())
      printf("Disabled windows defender!\n");

  }
  catch (std::exception e)
  {
    printf("%s\n", e.what());
  }

  system("pause");

  return EXIT_SUCCESS;
}
