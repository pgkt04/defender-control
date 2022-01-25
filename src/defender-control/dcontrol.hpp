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

  // Disables window defender
  //
  bool disable_defender();

  // Enables defender, assumes we have TrustedInstaller permissions
  //
  bool enable_defender();

  // Returns true if RealTimeMonitoring is activated
  //
  bool check_defender(uint32_t flags = 0);

  // Ends the smart screen process
  //
  void kill_smartscreen();

  // Stop or run the windefend service
  //
  bool manage_windefend(bool enable);

  // Stop or run the security center
  //
  bool manage_security_center(bool enable);
}