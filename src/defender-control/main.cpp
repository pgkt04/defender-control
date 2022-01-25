// to-do:
// make a ui for this
// argument support -s check
//
#include "dcontrol.hpp"
#include "wmic.hpp"
#include "trusted.hpp"

bool check_silent(int argc, char** argv)
{
  for (int i = 0; i < argc; i++)
  {
    if (!strcmp(argv[i], "-s"))
      return true;
  }
  return false;
}

int main(int argc, char** argv)
{
  auto silent = check_silent(argc, argv);

  if (!trusted::has_admin())
  {
    printf("Must run as admin!\n");

    if (!silent)
      system("pause");

    return EXIT_FAILURE;
  }

  // Because we are a primary token, we can't swap ourselves with an impersonation token.
  // There will always be a need to re-create the process with the token as primary.
  // we check for argc == 1, assuming we aren't launching with any parameters
  //
  if (!trusted::is_system_group()) // && argc == 1
  {
    printf("Restarting with privileges\n");
    trusted::create_process(util::get_current_path().append(silent ? " -s" : ""));
    return EXIT_SUCCESS;
  }

  try
  {
    dcontrol::kill_smartscreen();
    dcontrol::manage_windefend(false);
    dcontrol::toggle_tamper(false);

    printf(dcontrol::check_defender() ?
      "Windows defender is currently ACTIVE\n" :
      "Windows defender is currently OFF\n");

#if DEFENDER_CONFIG == DEFENDER_DISABLE
    if (dcontrol::disable_defender())
    {
      dcontrol::manage_security_center(false);
      printf("Disabled windows defender!\n");
    }
    else
      printf("Failed to disable defender...\n");
#elif DEFENDER_CONFIG == DEFENDER_ENABLE
    if (dcontrol::enable_defender())
      printf("Enabled windows defender!\n");
    else
      printf("Failed to enable defender...\n");
#elif DEFENDER_CONFIG == DEFENDER_GUI
#endif



  }
  catch (std::exception e)
  {
    printf("%s\n", e.what());
  }

  if (!silent)
    system("pause");

  return EXIT_SUCCESS;
}
