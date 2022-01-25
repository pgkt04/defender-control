#include "reg.hpp"

namespace reg
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
        wprintf(L"Error opening %ls key \n", root_name);
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
        wprintf(L"Failed to read %d\n", result);

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

    DWORD dwDisposition;

    status = RegCreateKeyExW(
      HKEY_LOCAL_MACHINE,
      root_name,
      0, 0, 0,
      131334,
      0,
      &hkey,
      &dwDisposition
    );

    if (status)
    {
      wprintf(L"Could not find or create %ls error %d\n", root_name, status);
      return false;
    }

    return true;
  }

  // Set value in registry as a DWORD
  //
  bool set_keyval(HKEY& hkey, const wchar_t* value_name, DWORD value)
  {
    auto ret = RegSetValueExW(hkey, value_name, 0, REG_DWORD,
      reinterpret_cast<LPBYTE>(&value), 4);

    if (ret)
    {
      // wprintf(L"Set error: %d\n", ret);
      return false;
    }

    return true;
  }

  // Set value in registry as binary mode
  //
  bool set_keyval_bin(HKEY& hkey, const wchar_t* value_name, DWORD value)
  {
    auto ret = RegSetValueExW(hkey, value_name, 0, REG_BINARY,
      reinterpret_cast<LPBYTE>(&value), 12);

    if (ret)
    {
      // wprintf(L"Set error: %d\n", ret);
      return false;
    }
    return true;
  }
}
