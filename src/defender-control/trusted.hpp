#pragma once
#include <Windows.h>
#include <string>
#include <TlHelp32.h>
#include <sddl.h>
#include <iostream>

namespace trusted
{
  bool enable_privilege(std::string privilege);
  DWORD get_pid(std::string process_name);
  bool impersonate_system();
  bool impersonate_trusted(DWORD pid);
  DWORD start_trusted();

  // Check current permissions for SYSTEM
  //
  bool is_system_group();

  // Checks if the current process is elevated
  //
  bool has_admin();
}
