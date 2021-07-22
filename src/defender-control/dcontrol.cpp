#include "dcontrol.hpp"

namespace dcontrol
{
  // Toggles windows tamper protection
  //
  void toggle_tamper(bool enable)
  {
    HKEY hkey;

    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender\\Features", hkey))
    {
      if (enable)
      {
        if (!reg::set_keyval(hkey, L"TamperProtection", 5))
          std::cout << "failed to write to TamperProtection" << std::endl;
      }
      else
      {
        if (!reg::set_keyval(hkey, L"TamperProtection", 0))
          std::cout << "failed to write to TamperProtection" << std::endl;
      }
    }
  }

  // Ends the smart screen process
  //
  void kill_smartscreen()
  {
    auto pid = util::get_pid("smartscreen.exe");
    auto proc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    TerminateProcess(proc, 0);
  }

  // Stop or run the windefend service
  //
  bool manage_windefend(bool enable)
  {
    auto sc_manager = OpenSCManagerA(0, 0, SC_MANAGER_CONNECT);

    if (!sc_manager)
      return false;

    auto service = OpenServiceA(
      sc_manager,
      "WinDefend",
      SERVICE_START | SERVICE_CHANGE_CONFIG | SERVICE_STOP | DELETE
    );

    if (!service)
    {
      CloseServiceHandle(sc_manager);
      return false;
    }

    if (enable)
    {
      // TODO implement
      //

      // Change to auto-start
      //

      // Start the service
      //
    }
    else
    {
      // Stop the service
      //
      SERVICE_STATUS scStatus;
      if (!ControlService(service, SERVICE_CONTROL_STOP, &scStatus))
      {
        auto last_error = GetLastError();

        if (last_error == ERROR_SERVICE_NOT_ACTIVE)
          return true;

        throw std::runtime_error("Failed to stop windefend service " + std::to_string(last_error));
        return false;
      }

      // Change to DEMAND
      //
      if (!ChangeServiceConfigA(
        service,
        SERVICE_NO_CHANGE,
        SERVICE_DEMAND_START,
        SERVICE_NO_CHANGE,
        0, 0, 0, 0, 0, 0, 0
      ))
      {
        throw std::runtime_error("Failed to modify windefend service" + std::to_string(GetLastError()));
        return false;
      }

      // Allow time for service to stop
      // TODO: Handle this automatically
      //
      Sleep(3000);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);

    return true;
  }

  // disables window defender
  //
  bool disable_defender()
  {
    HKEY hkey;

    // DisableAntiSpyware
    if (reg::create_registry(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", hkey))
    {
      if (!reg::set_keyval(hkey, L"DisableAntiSpyware", 1))
        std::cout << "failed to write to DisableAntiSpyware" << std::endl;
    }
    else
      std::cout << "Failed to access Policies-Microsoft-Windows Defender" << std::endl;

    // SecurityHealth
    //
    if (reg::create_registry(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
      hkey))
    {
      if (!reg::set_keyval_bin(hkey, L"SecurityHealth", 3))
        std::cout << "failed to write to SecurityHealth" << std::endl;
    }
    else
      std::cout << "failed to access CurrentVersion" << std::endl;

    // Protected by anti-tamper
    //
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender", hkey))
    {
      if (!reg::set_keyval(hkey, L"DisableAntiSpyware", 1))
        std::cout << "failed to write to DisableAntiSpyware" << std::endl;
    }
    else
      std::cout << "Failed to access Microsoft-Windows Defender" << std::endl;

    // Protected by anti-tamper
    // Start (3 off) (2 on)
    //
    if (reg::create_registry(L"SYSTEM\\CurrentControlSet\\Services\\WinDefend", hkey))
    {
      if (!reg::set_keyval(hkey, L"Start", 3))
        std::cout << "failed to write to Start" << std::endl;
    }
    else
      std::cout << "Failed to acccess CurrentControlSet-Services-Windefend" << std::endl;


    // Protected by anti-tamper
    //
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", hkey))
    {
      if (!reg::set_keyval(hkey, L"DisableRealtimeMonitoring", 1))
        std::cout << "failed to disable DisableRealtimeMonitoring" << std::endl;
    }
    else
      std::cout << "Failed to access Microsoft-Windows Defender-Real-time Protection" << std::endl;

    auto helper = new wmic::helper(
      "Root\\Microsoft\\Windows\\Defender",
      "MSFT_MpPreference",
      "Set"
    );

    if (auto error = helper->get_last_error())
    {
      printf("Error has occured: %d\n", error);
      return false;
    }

    // string types
    //
    helper->execute("EnableControlledFolderAccess", "Disabled");
    helper->execute("PUAProtection", "disable");

    // bool types
    //
    helper->execute<BOOL>("DisableRealtimeMonitoring", wmic::variant_type::t_bool, TRUE);
    helper->execute<BOOL>("DisableBehaviorMonitoring", wmic::variant_type::t_bool, TRUE);
    helper->execute<BOOL>("DisableBlockAtFirstSeen", wmic::variant_type::t_bool, TRUE);
    helper->execute<BOOL>("DisableIOAVProtection", wmic::variant_type::t_bool, TRUE);
    helper->execute<BOOL>("DisablePrivacyMode", wmic::variant_type::t_bool, TRUE);
    helper->execute<BOOL>("SignatureDisableUpdateOnStartupWithoutEngine", wmic::variant_type::t_bool, TRUE);
    helper->execute<BOOL>("DisableArchiveScanning", wmic::variant_type::t_bool, TRUE);
    helper->execute<BOOL>("DisableIntrusionPreventionSystem", wmic::variant_type::t_bool, TRUE);
    helper->execute<BOOL>("DisableScriptScanning", wmic::variant_type::t_bool, TRUE);
    helper->execute<BOOL>("DisableAntiSpyware", wmic::variant_type::t_bool, TRUE);
    helper->execute<BOOL>("DisableAntiVirus", wmic::variant_type::t_bool, TRUE);

    // values
    //
    helper->execute<uint8_t>("SubmitSamplesConsent", wmic::variant_type::t_uint8, 2);
    helper->execute<uint8_t>("MAPSReporting", wmic::variant_type::t_uint8, 0);
    helper->execute<uint8_t>("HighThreatDefaultAction", wmic::variant_type::t_uint8, 6);
    helper->execute<uint8_t>("ModerateThreatDefaultAction", wmic::variant_type::t_uint8, 6);
    helper->execute<uint8_t>("LowThreatDefaultAction", wmic::variant_type::t_uint8, 6);
    helper->execute<uint8_t>("SevereThreatDefaultAction", wmic::variant_type::t_uint8, 6);
    helper->execute<uint8_t>("ScanScheduleDay", wmic::variant_type::t_uint8, 8);

    // Delete smart screen
    // Disable windefend
    // Set windefend to DEMAND

    delete helper;

    return true;
  }

  bool enable_defender()
  {
    if (!util::sub_43604B())
      return false;

    util::set_privilege(SE_DEBUG_NAME, TRUE);

    HKEY hkey;

    if (!reg::create_registry(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", hkey))
      std::cout << "failed to access Policies" << std::endl;

    if (!reg::set_keyval(hkey, L"DisableAntiSpyware", 0))
      std::cout << "failed to write to DisableAntiSpyware" << std::endl;

    if (!reg::create_registry(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
      hkey))
      std::cout << "failed to access CurrentVersion" << std::endl;

    if (!reg::set_keyval_bin(hkey, L"SecurityHealth", 2))
      std::cout << "failed to write to SecurityHealth" << std::endl;

    auto helper = new wmic::helper(
      "Root\\Microsoft\\Windows\\Defender",
      "MSFT_MpPreference",
      "Set"
    );

    if (auto error = helper->get_last_error())
    {
      printf("Error has occured: %d\n", error);
      return false;
    }

    // string types
    //
    helper->execute("EnableControlledFolderAccess", "Enabled");
    helper->execute("PUAProtection", "enable");

    // bool types
    //
    helper->execute<BOOL>("DisableRealtimeMonitoring", wmic::variant_type::t_bool, FALSE);
    helper->execute<BOOL>("DisableBehaviorMonitoring", wmic::variant_type::t_bool, FALSE);
    helper->execute<BOOL>("DisableBlockAtFirstSeen", wmic::variant_type::t_bool, FALSE);
    helper->execute<BOOL>("DisableIOAVProtection", wmic::variant_type::t_bool, FALSE);
    helper->execute<BOOL>("DisablePrivacyMode", wmic::variant_type::t_bool, FALSE);
    helper->execute<BOOL>("SignatureDisableUpdateOnStartupWithoutEngine", wmic::variant_type::t_bool, FALSE);
    helper->execute<BOOL>("DisableArchiveScanning", wmic::variant_type::t_bool, FALSE);
    helper->execute<BOOL>("DisableIntrusionPreventionSystem", wmic::variant_type::t_bool, FALSE);
    helper->execute<BOOL>("DisableScriptScanning", wmic::variant_type::t_bool, FALSE);
    helper->execute<BOOL>("DisableAntiSpyware", wmic::variant_type::t_bool, FALSE);
    helper->execute<BOOL>("DisableAntiVirus", wmic::variant_type::t_bool, FALSE);

    delete helper;

    return true;
  }

  // Returns true if RealTimeMonitoring is activated
  //
  bool check_defender(uint32_t flags)
  {
    //return REG::read_key(
    //  L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
    //  L"DisableRealtimeMonitoring") == 0;

    auto helper = new wmic::helper(
      "Root\\Microsoft\\Windows\\Defender",
      "MSFT_MpPreference",
      "Set"
    );

    if (auto error = helper->get_last_error())
    {
      // Throw error instead
      //
      printf("Error has occured: %d\n", error);
      delete helper;
      return true;
    }

    bool result = false;
    helper->get<bool>("DisableRealtimeMonitoring", wmic::variant_type::t_bool, result);
    delete helper;
    return (!result);
  }
}
// Query WMI 