#include "reg.hpp"

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
      std::wcout << "could not find or create " << root_name << " error: " << status << std::endl;
      return false;
    }

    return true;
  }

  bool set_keyval(HKEY& hkey, const wchar_t* value_name, DWORD value)
  {
    auto ret = RegSetValueExW(hkey, value_name, 0, REG_DWORD,
      reinterpret_cast<LPBYTE>(&value), 4);

    if (ret)
    {
      std::cout << "set error: " << ret << std::endl;
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
