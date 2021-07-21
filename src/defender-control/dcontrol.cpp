#include "dcontrol.hpp"

namespace dcontrol
{
  // disables window defender
  //
  bool disable_defender()
  {
    HKEY hkey;

    // DisableAntiSpyware
    if (REG::create_registry(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", hkey))
    {
      if (!REG::set_keyval(hkey, L"DisableAntiSpyware", 1))
        std::cout << "failed to write to DisableAntiSpyware" << std::endl;
    }
    else
      std::cout << "Failed to access Policies-Microsoft-Windows Defender" << std::endl;

    // SecurityHealth
    //
    if (REG::create_registry(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run", 
      hkey))
    {
      if (!REG::set_keyval_bin(hkey, L"SecurityHealth", 3))
        std::cout << "failed to write to SecurityHealth" << std::endl;
    }
    else
      std::cout << "failed to access CurrentVersion" << std::endl;

    // Protected by anti-tamper
    //
    if (REG::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender", hkey))
    {
      if (!REG::set_keyval(hkey, L"DisableAntiSpyware", 1))
        std::cout << "failed to write to DisableAntiSpyware" << std::endl;
    }
    else
      std::cout << "Failed to access Microsoft-Windows Defender" << std::endl;

    // Protected by anti-tamper
    // Start (3 off) (2 on)
    //
    if (REG::create_registry(L"SYSTEM\\CurrentControlSet\\Services\\WinDefend", hkey))
    {
      if (!REG::set_keyval(hkey, L"Start", 3))
        std::cout << "failed to write to Start" << std::endl;
    }
    else
      std::cout << "Failed to acccess CurrentControlSet-Services-Windefend" << std::endl;


    // Protected by anti-tamper
    //
    if (REG::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", hkey))
    {
      if (!REG::set_keyval(hkey, L"DisableRealtimeMonitoring", 1))
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
      printf("Error has occured: %d", error);
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

    return true;
  }

  bool enable_defender()
  {
    if (!util::sub_43604B())
      return false;

    util::set_privilege(SE_DEBUG_NAME, TRUE);

    HKEY hkey;

    if (!REG::create_registry(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", hkey))
      std::cout << "failed to access Policies" << std::endl;

    if (!REG::set_keyval(hkey, L"DisableAntiSpyware", 0))
      std::cout << "failed to write to DisableAntiSpyware" << std::endl;

    if (!REG::create_registry(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
      hkey))
      std::cout << "failed to access CurrentVersion" << std::endl;

    if (!REG::set_keyval_bin(hkey, L"SecurityHealth", 2))
      std::cout << "failed to write to SecurityHealth" << std::endl;

    auto helper = new wmic::helper(
      "Root\\Microsoft\\Windows\\Defender",
      "MSFT_MpPreference",
      "Set"
    );

    if (auto error = helper->get_last_error())
    {
      printf("Error has occured: %d", error);
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

    return true;
  }

  // Checks whether Real-Time Protection is activated on windows
  //
  bool check_defender(uint32_t flags)
  {
    return REG::read_key(
      L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
      L"DisableRealtimeMonitoring") == 0;
  }
}