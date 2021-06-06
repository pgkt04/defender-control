#include "dcontrol.h"

namespace REG
{
  // reads a key from HKEY_LOCAL_MACHINE
  //
  DWORD read_key(const wchar_t* root_name, const wchar_t* value_name, uint32_t flags)
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
      root_name,
      0,
      KEY_READ | KEY_WOW64_64KEY,
      &hkey
    );

    if (status)
    {
      if (flags & DBG_MSG)
        std::cout << "Error opening " << root_name << " key" << std::endl;

      return -1;
    }

    status = RegQueryValueExW(
      hkey,
      value_name,
      0, NULL,
      reinterpret_cast<LPBYTE>(&result),
      &buff_sz
    );

    if (status)
    {
      if (flags & DBG_MSG)
        std::cout << "Failed to read " << result << std::endl;

      return -1;
    }

    RegCloseKey(hkey);

    return result;
  }

  // creates a registry in HKEY_LOCAL_MACHINE with KEY_ALL_ACCESS permissions
  //
  bool create_registry(const wchar_t* root_name, HKEY& hkey)
  {
    LSTATUS status;

    status = RegOpenKeyExW(
      HKEY_LOCAL_MACHINE,
      root_name,
      0,
      KEY_ALL_ACCESS | KEY_WOW64_64KEY,
      &hkey
    );

    if (!status)
      return true;

    status = RegCreateKeyExW(
      HKEY_LOCAL_MACHINE,
      root_name,
      0, 0,
      REG_OPTION_NON_VOLATILE,
      KEY_ALL_ACCESS, 0,
      &hkey,
      0
    );

    if (status)
    {
      std::cout << "could not find or create " << root_name << std::endl;
      return false;
    }

    return true;
  }

  bool set_keyval(HKEY& hkey, const wchar_t* value_name, DWORD value)
  {
    if (RegSetValueExW(hkey, value_name, 0, REG_DWORD,
      reinterpret_cast<LPBYTE>(&value), sizeof(DWORD)))
    {
      return false;
    }
    return true;
  }

  bool set_keyval_bin(HKEY& hkey, const wchar_t* value_name, DWORD value)
  {
    if (RegSetValueExW(hkey, value_name, 0, REG_BINARY,
      reinterpret_cast<LPBYTE>(&value), sizeof(DWORD)))
    {
      return false;
    }
    return true;
    
  }
}

namespace DCONTROL
{
  // disables window defender
  //
  bool disable_defender()
  {
    // create DisableRealtimeMonitoring if it does not exist then set value to 1
    // [RegCreateKeyExW]
    // lpSubKey: SOFTWARE\Policies\Microsoft\Windows Defender
    // [RegSetValueExW]
    // lpValueName: DisableAntiSpyware
    // [RegCreateKeyExW]
    // lpSubKey: SOFTWARE\Microsoft\Windows Defender
    // [RegCreateKeyExW]
    // lpSubKey: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
    // [RegCreateKeyExW]
    // lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
    // [RegSetValueExW]
    // lpValueName: Start
    // [RegOpenKeyExW]
    // lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    // [RegQueryValueExW]
    // lpValueName: SecurityHealth
    // [RegCreateKeyExW]
    // lpSubKey: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
    // [RegSetValueExW]
    // lpValueName: SecurityHealth
    // [RegOpenKeyExW]
    // lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    // [RegEnumValueW]
    // lpValueName: SecurityHealth
    // [RegOpenKeyExW]
    // lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
    // [RegQueryValueExW]
    // lpValueName: DisableRealtimeMonitoring

    HKEY hkey;

    // SecurityHealth
    {
        if (!REG::create_registry(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run", hkey))
        {
          std::cout << "failed to access CurrentVersion" << std::endl;
          return false;
        }

      if (!REG::set_keyval_bin(hkey, L"SecurityHealth", 3))
      {
        std::cout << "failed to write to SecurityHealth" << std::endl;
        return false;
      }
    }

    // Start (3 off) (2 on)
    {
      if (!REG::create_registry(L"SYSTEM\\CurrentControlSet\\Services\\WinDefend", hkey))
      {
        std::cout << "failed to access CurrentControlSet" << std::endl;
        return false;
      }

      if (!REG::set_keyval(hkey, L"Start", 3))
      {
        std::cout << "failed to write to Start" << std::endl;
        return false;
      }
    }

    // DisableAntiSpyware
    {
      if (!REG::create_registry(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", hkey))
      {
        std::cout << "failed to access Policies" << std::endl;
        return false;
      }

      if (!REG::set_keyval(hkey, L"DisableAntiSpyware", 1))
      {
        std::cout << "failed to write to DisableAntiSpyware" << std::endl;
        return false;
      }

      if (!REG::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender", hkey))
      {
        std::cout << "failed to access Windows Defender" << std::endl;
        return false;
      }

      if (!REG::set_keyval(hkey, L"DisableAntiSpyware", 1))
      {
        std::cout << "failed to write to DisableAntiSpyware" << std::endl;
        return false;
      }
    }

    // DisableRealtimeMonitoring
    {
      if (!REG::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", hkey))
      {
        std::cout << "failed to access registry" << std::endl;
        return false;
      }
      if (!REG::set_keyval(hkey, L"DisableRealtimeMonitoring", 1))
      {
        std::cout << "failed to disable DisableRealtimeMonitoring" << std::endl;
        return false;
      }
    }

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