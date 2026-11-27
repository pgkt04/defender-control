// to-do:
// make a ui for this
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

// True if the user asked for a status check (-c / -check)
//
bool check_status_flag(int argc, char** argv)
{
  for (int i = 0; i < argc; i++)
  {
    if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "-check"))
      return true;
  }
  return false;
}

// Generic flag check.
//
bool has_flag(int argc, char** argv, const char* flag)
{
  for (int i = 0; i < argc; i++)
  {
    if (!strcmp(argv[i], flag))
      return true;
  }
  return false;
}

int main(int argc, char** argv)
{
  // -tilog: we were launched by the Task Scheduler as the TrustedInstaller worker,
  // which runs in session 0 with no console. Redirect output to the log file the
  // parent will print back. Must happen before any printf.
  //
  if (has_flag(argc, argv, "-tilog"))
    trusted::redirect_output_to_ti_log();

  auto silent = check_silent(argc, argv);

  // -worker: this process IS the elevated worker (spawned by either TI launcher).
  // Skip the self-relaunch and go straight to the work.
  //
  auto worker = has_flag(argc, argv, "-worker");

  // Status check mode: just report and exit (no elevation/relaunch needed).
  //
  if (check_status_flag(argc, argv))
  {
    dcontrol::report_status();

    if (!silent)
      system("pause");

    return EXIT_SUCCESS;
  }

  if (!trusted::has_admin())
  {
    printf("Must run as admin!\n");

    if (!silent)
      system("pause");

    return EXIT_FAILURE;
  }

  // Because we are a primary token, we can't swap ourselves with an impersonation
  // token. There will always be a need to re-create the process with the token as
  // primary. The worker flag (set on relaunch) tells us we are already elevated, so
  // we don't rely on token-SID detection (a scheduler-spawned TI worker's user SID
  // is the TI service account, NOT S-1-5-18).
  //
  if (!worker && !trusted::is_system_group())
  {
    // Preserve our flags across the relaunch.
    std::wstring exe  = util::string_to_wide(util::get_current_path());
    std::wstring args = L"-s -worker -tilog";

    trusted::reset_ti_log();

    // Preferred: clean TI via the Task Scheduler "RunEx" technique.
    LONG exit_code = 0;
    if (trusted::run_as_ti_scheduled(exe, args, &exit_code))
    {
      printf("Running as TrustedInstaller (Task Scheduler)...\n\n");
      trusted::print_ti_log();
      printf("\n[TrustedInstaller worker finished, exit=%ld]\n", exit_code);
    }
    else
    {
      // Fallback: original token-theft launcher (no log redirection -> the worker
      // shares this console, so don't pass -tilog).
      printf("Scheduled-task launch unavailable; falling back to token impersonation...\n");
      std::string relaunch = util::get_current_path();
      relaunch += " -s -worker";
      trusted::create_process(relaunch);
    }

    if (!silent)
      system("pause");

    return EXIT_SUCCESS;
  }

  try
  {
    if (dcontrol::is_tamper_enabled_wmi())
    {
      printf("\n*** WARNING: Tamper Protection appears to be ENABLED ***\n");
      printf("Writes to protected keys (Wd* services, Defender keys, IFEO,\n");
      printf("autologgers) will be blocked by the kernel regardless of token.\n");
      printf("Turn it off first: Windows Security > Virus & threat protection >\n");
      printf("Manage settings > Tamper Protection = Off, then re-run.\n\n");
    }

    dcontrol::kill_smartscreen();
    dcontrol::kill_defender_processes();
    dcontrol::manage_windefend(false);
    dcontrol::toggle_tamper(false);

    printf(dcontrol::check_defender() ?
      "Windows defender is currently ACTIVE\n" :
      "Windows defender is currently OFF\n");

#if DEFENDER_CONFIG == DEFENDER_DISABLE
    // Disable all services, policies, and protections
    dcontrol::disable_services_registry();
    dcontrol::set_group_policies(true);
    dcontrol::disable_smartscreen_registry();
    dcontrol::disable_amsi();
    dcontrol::disable_etw_logging();
    dcontrol::set_defender_internal_state(true);
    dcontrol::disable_safe_boot_registration();
    dcontrol::set_ifeo_debugger_hijack(true);
    dcontrol::set_disallow_run(true);
    dcontrol::disable_wtds();
    dcontrol::disable_application_guard();
    dcontrol::disable_exploit_guard();
    dcontrol::disable_smartscreen_extras();
    dcontrol::disable_minifilter_altitude();
    dcontrol::disable_vbs();
      dcontrol::disable_scheduled_tasks();
      dcontrol::soft_delete_binaries();

      if (dcontrol::disable_defender())
    {
      dcontrol::manage_security_center(false);
      dcontrol::disable_notifications();
      dcontrol::disable_security_ui();
      printf("Disabled windows defender!\n");
    }
    else
      printf("Failed to disable defender...\n");
#elif DEFENDER_CONFIG == DEFENDER_ENABLE
    // Re-enable everything in reverse order
    dcontrol::restore_binaries();
    dcontrol::enable_scheduled_tasks();
    dcontrol::enable_vbs();
    dcontrol::enable_security_ui();
    dcontrol::enable_notifications();
    dcontrol::enable_minifilter_altitude();
    dcontrol::enable_smartscreen_extras();
    dcontrol::enable_exploit_guard();
    dcontrol::enable_application_guard();
    dcontrol::enable_wtds();
    dcontrol::set_disallow_run(false);
    dcontrol::set_ifeo_debugger_hijack(false);
    dcontrol::enable_safe_boot_registration();
    dcontrol::set_defender_internal_state(false);
    dcontrol::enable_etw_logging();
    dcontrol::enable_amsi();
    dcontrol::enable_smartscreen_registry();
    dcontrol::set_group_policies(false);
    dcontrol::enable_services_registry();

    if (dcontrol::enable_defender())
      printf("Enabled windows defender!\n");
    else
      printf("Failed to enable defender...\n");
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
