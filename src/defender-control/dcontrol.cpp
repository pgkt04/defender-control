#include "dcontrol.h"

namespace DCONTROL
{
  // forget about this for now
  //
  bool enable_control()
  {
    return true;
  }

  // write a working poc
  //
  bool disable_control()
  {

    return true;
  }

  // Checks whether Real-Time Protection is activated on windows
  //
  bool check_defender()
  {
    LSTATUS status;
    HKEY hkey;
    DWORD result{};
    DWORD buff_sz = sizeof(DWORD);

    // https://docs.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view
    // KEY_WOW64_64KEY if we are in an x86 environment
    // KEY_ALL_ACCESS to access
    // but we only need to read for this call

    status = RegOpenKeyExW(
      HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
      0,
      KEY_READ | KEY_WOW64_64KEY,
      &hkey
    );

    // running by default if we can't identify it
    //
    if (status)
    {
      std::cout << "Error opening Real-Time Protection key" << std::endl;
      return true;
    }

    status = RegQueryValueExW(
      hkey,
      L"DisableRealtimeMonitoring",
      0, NULL,
      reinterpret_cast<LPBYTE>(&result),
      &buff_sz
    );

    if (status)
    {
      std::cout << "Failed to read DisableRealtimeMonitoring" << std::endl;
      return true;
    }

    return result == 0;
  }
}