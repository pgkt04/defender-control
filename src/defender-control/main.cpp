// to-do:
// write argument parser
// create cli program
// maybe make a ui for this
//
#include "dcontrol.hpp"
#include "wmic.hpp"

int main()
{
  printf(DCONTROL::check_defender() ?
    "Windows defender is ACTIVE turning off..\n" :
    "Windows defender is OFF turning on...\n");

  auto helper = new wmic::helper(
    "Root\\Microsoft\\Windows\\Defender",
    "MSFT_MpPreference",
    "Set"
  );

  if (auto error = helper->get_last_error())
  {
    printf("Error has occured: %d", error);
    system("pause");
    return 1;
  }

  if (DCONTROL::check_defender())
    helper->execute_cmd<BOOL>("DisableRealtimeMonitoring", wmic::variant_type::t_bool, TRUE);
  else 
    helper->execute_cmd<BOOL>("DisableRealtimeMonitoring", wmic::variant_type::t_bool, FALSE);

  system("pause");
  return 0;
}
