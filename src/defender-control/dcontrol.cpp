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

    // TODO: Create a better solution to terminate smartscreen
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
    // The state of global data maintained by dynamic-link libraries 
    // (DLLs) may be compromised if TerminateProcess is used rather than ExitProcess.
    // e.g. Injecting code to execute ExitProcess and manually unloaded everything 

    TerminateProcess(proc, 0);

    if (proc)
      CloseHandle(proc);
  }

  // TODO: create a single function

  bool manage_security_service(bool enable, std::string service_name)
  {
    auto sc_manager = OpenSCManagerA(0, 0, SC_MANAGER_CONNECT);

    if (!sc_manager)
      return false;

    auto service = OpenServiceA(
      sc_manager,
      service_name.c_str(),
      enable ? SERVICE_ALL_ACCESS :
      (SERVICE_CHANGE_CONFIG | SERVICE_STOP | DELETE)
    );

    if (!service)
    {
      CloseServiceHandle(sc_manager);
      return false;
    }

    if (enable)
    {
      // Change to auto-start
      if (!ChangeServiceConfigA(
        service,
        SERVICE_NO_CHANGE,
        SERVICE_AUTO_START,
        SERVICE_NO_CHANGE,
        0, 0, 0, 0, 0, 0, 0
      ))
      {
        throw std::runtime_error("Failed to modify " + service_name + " " + std::to_string(GetLastError()));
        return false;
      }

      // Start the service
      if (!StartServiceA(service, 0, NULL))
      {
        throw std::runtime_error("Failed to start " + service_name);
        return false;
      }
    }
    else
    {
      // Stop the service
      SERVICE_STATUS scStatus;
      if (!ControlService(service, SERVICE_CONTROL_STOP, &scStatus))
      {
        auto last_error = GetLastError();

        if (last_error == ERROR_SERVICE_NOT_ACTIVE)
          return true;

        throw std::runtime_error(
          "Failed to stop " + service_name + " " + std::to_string(last_error)
        );
        return false;
      }

      // Change to DEMAND
      if (!ChangeServiceConfigA(
        service,
        SERVICE_NO_CHANGE,
        SERVICE_DEMAND_START,
        SERVICE_NO_CHANGE,
        0, 0, 0, 0, 0, 0, 0
      ))
      {
        throw std::runtime_error(
          "Failed to modify " + service_name + " " + std::to_string(GetLastError())
        );

        return false;
      }

      // Allow time for service to stop
      // TODO: Handle this automatically
      Sleep(3000);
    }

    return true;
  }

  // Stop or run security center (wscvc)
  // The default value is autostart
  //
  bool manage_security_center(bool enable)
  {
    // handle registry calls
    // https://superuser.com/questions/1199112/how-to-tell-the-state-of-a-service-from-the-registry
    // https://stackoverflow.com/questions/291519/how-does-currentcontrolset-differ-from-controlset001-and-controlset002
    // https://web.archive.org/web/20110514163940/http://support.microsoft.com/kb/103000
    //

    // auto ret = manage_security_service(enable, "wscsvc");

    HKEY hkey;
    if (reg::create_registry(L"SYSTEM\\CurrentControlSet\\Services\\wscsvc", hkey))
    {
      if (enable)
      {
        if (!reg::set_keyval(hkey, L"Start", 2)) // Automatic
        {
          printf("failed to write to wscsvc\n");
          return false;
        }
      }
      else
      {
        if (!reg::set_keyval(hkey, L"Start", 4)) // Disabled
        {
          printf("failed to write to wscsvc\n");
          return false;
        }
      }
    }

    return true;
  }

  // Stop or run the windefend service
  //
  bool manage_windefend(bool enable)
  {
    return manage_security_service(enable, "WinDefend");
  }

  // Disables window defender
  //
  bool disable_defender()
  {
    HKEY hkey;

    // DisableAntiSpyware
    if (reg::create_registry(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", hkey))
    {
      if (!reg::set_keyval(hkey, L"DisableAntiSpyware", 1))
        printf("failed to write to DisableAntiSpyware\n");
    }
    else
      printf("Failed to access Policies\n");

    // SecurityHealth
    if (reg::create_registry(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
      hkey))
    {
      if (!reg::set_keyval_bin(hkey, L"SecurityHealth", 3))
        printf("Failed to write to SecurityHealth\n");
    }
    else
      printf("Failed to access CurrentVersion\n");

    // Protected by anti-tamper
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender", hkey))
    {
      if (!reg::set_keyval(hkey, L"DisableAntiSpyware", 1))
        printf("Failed to write to DisableAntiSpyware");
    }
    else
      printf("Failed to access Windows Defender\n");

    // Protected by anti-tamper
    // Start (3 off) (2 on)
    if (reg::create_registry(L"SYSTEM\\CurrentControlSet\\Services\\WinDefend", hkey))
    {
      reg::set_keyval(hkey, L"Start", 3);
    }
    else
      printf("Failed to access CurrentControlSet\n");

    // Protected by anti-tamper
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", hkey))
    {
      if (!reg::set_keyval(hkey, L"DisableRealtimeMonitoring", 1))
        printf("Failed to write to DisableRealTimeMonitoring\n");
    }
    else
      printf("Failed to access Real-Time Protection");

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
    helper->execute("EnableControlledFolderAccess", "Disabled");
    helper->execute("PUAProtection", "disable");

    // bool types
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
    helper->execute<uint8_t>("SubmitSamplesConsent", wmic::variant_type::t_uint8, 2);
    helper->execute<uint8_t>("MAPSReporting", wmic::variant_type::t_uint8, 0);
    helper->execute<uint8_t>("HighThreatDefaultAction", wmic::variant_type::t_uint8, 6);
    helper->execute<uint8_t>("ModerateThreatDefaultAction", wmic::variant_type::t_uint8, 6);
    helper->execute<uint8_t>("LowThreatDefaultAction", wmic::variant_type::t_uint8, 6);
    helper->execute<uint8_t>("SevereThreatDefaultAction", wmic::variant_type::t_uint8, 6);
    helper->execute<uint8_t>("ScanScheduleDay", wmic::variant_type::t_uint8, 8);

    delete helper;

    return true;
  }

  // Enables defender, assumes we have TrustedInstaller permissions
  bool enable_defender()
  {
    HKEY hkey;

    // DisableAntiSpyware
    if (reg::create_registry(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", hkey))
    {
      if (!reg::set_keyval(hkey, L"DisableAntiSpyware", 0))
        printf("failed to write to DisableAntiSpyware\n");
    }
    else
      printf("Failed to access Policies\n");

    // SecurityHealth
    if (reg::create_registry(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
      hkey))
    {
      if (!reg::set_keyval_bin(hkey, L"SecurityHealth", 2))
        printf("Failed to write to SecurityHealth\n");
    }
    else
      printf("Failed to access CurrentVersion\n");

    // Protected by anti-tamper
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender", hkey))
    {
      if (!reg::set_keyval(hkey, L"DisableAntiSpyware", 0))
        printf("Failed to write to DisableAntiSpyware");
    }
    else
      printf("Failed to access Windows Defender\n");

    // Protected by anti-tamper
    // Start (3 off) (2 on)
    if (reg::create_registry(L"SYSTEM\\CurrentControlSet\\Services\\WinDefend", hkey))
      reg::set_keyval(hkey, L"Start", 2);
    else
      printf("Failed to access CurrentControlSet\n");

    // Protected by anti-tamper
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", hkey))
    {
      if (!reg::set_keyval(hkey, L"DisableRealtimeMonitoring", 0))
        printf("Failed to write to DisableRealTimeMonitoring\n");
    }
    else
      printf("Failed to access Real-Time Protection");

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

    // BSTR types
    helper->execute("EnableControlledFolderAccess", "Enabled");
    helper->execute("PUAProtection", "enable");

    auto helper_disable = [](wmic::helper* h, const char* name) {
      h->execute<BOOL>(name, wmic::variant_type::t_bool, FALSE);
    };

    // BOOL types
    helper_disable(helper, "DisableRealtimeMonitoring");
    helper_disable(helper, "DisableBehaviorMonitoring");
    helper_disable(helper, "DisableBlockAtFirstSeen");
    helper_disable(helper, "DisableIOAVProtection");
    helper_disable(helper, "DisablePrivacyMode");
    helper_disable(helper, "SignatureDisableUpdateOnStartupWithoutEngine");
    helper_disable(helper, "DisableArchiveScanning");
    helper_disable(helper, "DisableIntrusionPreventionSystem");
    helper_disable(helper, "DisableScriptScanning");
    helper_disable(helper, "DisableAntiSpyware");
    helper_disable(helper, "DisableAntiVirus");

    // Cleanup
    delete helper;

    manage_windefend(true);
    manage_security_center(true);

    return true;
  }

  // Returns true if RealTimeMonitoring is activated
  //
  bool check_defender(uint32_t flags)
  {
    // Unreliable method if anti-tamper is enabled.
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