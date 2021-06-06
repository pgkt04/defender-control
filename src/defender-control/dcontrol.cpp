#include "dcontrol.h"

namespace REG
{
  void init_key(DWORD* a1)
  {
    *a1 = -2147483646;
  }

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

#if 0
    HKEY temp{};
    HKEY phkResult;
    RegConnectRegistryW(0, temp, &phkResult);
#endif

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

#if 0
    HKEY temp{};
    HKEY phkResult;
    RegConnectRegistryW(0, temp, &phkResult);
#endif

#if 0
    // 0x20119 or 131353
    status = RegOpenKeyExW(
      HKEY_LOCAL_MACHINE,
      root_name,
      0,
      131353,
      &hkey
    );

    if (status == ERROR_SUCCESS)
    {
      std::wcout << "Successfully opened " << root_name << std::endl;
      return true;
    }
#endif

    //[RegCreateKeyExW]
    //hKey: 80000002
    //lpSubKey: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
    //lpClass:
    //samDesired: 131334
    //Reserved: 0
    //lpSecurityAttributes: 00000000
    //dwOptions: 0
    //lpdwDisposition: 008BF04C

    DWORD dwDisposition;

    status = RegCreateKeyExW(
      HKEY_LOCAL_MACHINE,
      root_name,
      0,
      0,
      0,
      131334,
      0,
      &hkey,
      &dwDisposition
    );

    if (status)
    {
      std::wcout << "could not find or create " << root_name << " error: " << status << std::endl;
      return false;
    }

#if 0
    std::cout << "disposition: " << dwDisposition << std::endl;
#endif

    return true;
  }

  bool set_keyval(HKEY& hkey, const wchar_t* value_name, DWORD value)
  {
    auto ret = RegSetValueExW(hkey, value_name, 0, REG_DWORD,
      reinterpret_cast<LPBYTE>(&value), 4);

    if (ret)
    {
      std::cout << "Set error: " << ret << std::endl;
      return false;
    }

    return true;
  }

  bool set_keyval_bin(HKEY& hkey, const wchar_t* value_name, DWORD value)
  {
    auto ret = RegSetValueExW(hkey, value_name, 0, REG_BINARY,
      reinterpret_cast<LPBYTE>(&value), 12);

    if (ret)
    {
      std::cout << "Set error: " << ret << std::endl;
      return false;
    }
    return true;

  }
}

namespace DCONTROL
{
  char sub_43604B()
  {
    char v0; // bl
    SC_HANDLE v1; // eax
    SC_HANDLE v2; // esi
    void* v3; // eax

    v0 = 0;
    v1 = OpenSCManagerW(0, 0, 8u);
    v2 = v1;
    if (v1)
    {
      v3 = LockServiceDatabase(v1);
      if (v3)
      {
        UnlockServiceDatabase(v3);
        CloseServiceHandle(v2);
        return 1;
      }
      if (GetLastError() == 1055)
        v0 = 1;
      CloseServiceHandle(v2);
    }
    return v0;
  }

  // disables window defender
  //
  bool disable_defender()
  {
    if (!sub_43604B())
    {
      std::cout << "permission error" << std::endl;
      return false;
    }

    HKEY hkey;

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

#if 0
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
#endif
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

    std::cout << "Wrote to Start" << std::endl;


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

    std::cout << "Wrote to SecurityHealth" << std::endl;


#if 0
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
#endif

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