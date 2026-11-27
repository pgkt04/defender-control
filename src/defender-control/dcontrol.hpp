#pragma once
#include <Windows.h>
#include <iostream>
#include "settings.hpp"
#include "reg.hpp"
#include "util.hpp"
#include "wmic.hpp"

namespace dcontrol
{
  // Toggles windows tamper protection
  //
  void toggle_tamper(bool enable);

  // Returns true if Tamper Protection appears to be ENABLED (writes to protected
  // Defender keys will be blocked by the kernel filter regardless of token).
  //
  bool is_tamper_enabled();

  // Authoritative Tamper Protection check via WMI (MSFT_MpComputerStatus).
  // More reliable than the registry read, which can report "off" while the kernel
  // filter is still enforcing. Falls back to is_tamper_enabled() if WMI is unavailable.
  //
  bool is_tamper_enabled_wmi();

  // Disables window defender
  //
  bool disable_defender();

  // Enables defender, assumes we have TrustedInstaller permissions.
  // Also performs offline-safe recovery (clears tampering values, resets ownership,
  // restores service Start values, recreates MpDefenderCoreService when missing,
  // restores the WdBoot ELAM group) so a single enable recovers a Defender wedged by
  // a disable cycle. REBOOT afterwards so WinDefend auto-starts at boot.
  //
  bool enable_defender();

  // Returns true if RealTimeMonitoring is activated
  //
  bool check_defender(uint32_t flags = 0);

  // Print a human-readable report of Defender's current state (for a -c run).
  // Reads live WMI status plus key registry/process facts; safe to run after a
  // reboot when the Security UI is locked down.
  //
  void report_status();

  // Ends the smart screen process
  //
  void kill_smartscreen();

  // Kill all defender-related processes
  //
  void kill_defender_processes();

  // Stop or run the windefend service
  //
  bool manage_windefend(bool enable);

  // Stop or run the security center
  //
  bool manage_security_center(bool enable);

  // Disable/enable defender services via registry Start value
  //
  void disable_services_registry();
  void enable_services_registry();

  // Set/clear all group policy registry keys
  //
  void set_group_policies(bool disable);

  // Disable/enable SmartScreen via registry
  //
  void disable_smartscreen_registry();
  void enable_smartscreen_registry();

  // Disable/enable AMSI
  //
  void disable_amsi();
  void enable_amsi();

  // Disable/enable ETW logging and autologgers
  //
  void disable_etw_logging();
  void enable_etw_logging();

  // Set/clear Defender internal state flags
  //
  void set_defender_internal_state(bool disable);

  // Remove/restore WinDefend Safe Boot registration
  //
  void disable_safe_boot_registration();
  void enable_safe_boot_registration();

  // Set/remove IFEO debugger hijack on Defender executables
  //
  void set_ifeo_debugger_hijack(bool enable);

  // Set/remove Explorer DisallowRun policy for Defender executables
  //
  void set_disallow_run(bool enable);

  // Suppress/restore Defender notifications
  //
  void disable_notifications();
  void enable_notifications();

  // Lock down/restore Windows Security UI
  //
  void disable_security_ui();
  void enable_security_ui();

  // Disable/enable Web Threat Defense / Enhanced Phishing Protection (Win11 22H2+)
  //
  void disable_wtds();
  void enable_wtds();

  // Disable/enable Application Guard
  //
  void disable_application_guard();
  void enable_application_guard();

  // Disable/enable Exploit Guard Network Protection
  //
  void disable_exploit_guard();
  void enable_exploit_guard();

  // Disable/enable additional SmartScreen areas (Legacy Edge, IE zones)
  //
  void disable_smartscreen_extras();
  void enable_smartscreen_extras();

  // Remove/restore WdFilter minifilter altitude registration
  //
  void disable_minifilter_altitude();
  void enable_minifilter_altitude();

  // Disable/enable VBS, HVCI, Device Guard and System Guard secure launch
  //
  void disable_vbs();
  void enable_vbs();

  // Disable/enable Defender-related scheduled tasks
  //
  void disable_scheduled_tasks();
  void enable_scheduled_tasks();

  // Binary soft-deletion: rename Defender's executables/drivers to ".OLD" as
  // TrustedInstaller so the engine cannot launch at the next boot.
  // soft_delete_binaries() also writes a manifest used by restore_binaries(), which
  // renames every ".OLD" back and hands ownership to TI. Takes full effect after a
  // normal reboot (the running PPL engine cannot be killed live). No Safe Mode required.
  //
  void soft_delete_binaries();
  void restore_binaries();
}