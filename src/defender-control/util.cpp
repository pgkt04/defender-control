#include "util.hpp"

namespace util
{
  // Converts a string to wide
  //
  std::wstring string_to_wide(const std::string& s)
  {
    std::wstring temp(s.length(), L' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
  }

  // Converts a wide to string
  //
  std::string wide_to_string(const std::wstring& s) {
    std::string temp(s.length(), ' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
  }

  // Sets the programs debug priviliges
  //
  bool set_privilege(LPCSTR privilege, BOOL enable)
  {
    TOKEN_PRIVILEGES priv = { 0,0,0,0 };
    HANDLE token = nullptr;
    LUID luid = { 0,0 };

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) 
    {
      if (token)
        CloseHandle(token);

      return false;
    }

    if (!LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &luid)) 
    {
      if (token)
        CloseHandle(token);

      return false;
    }
    priv.PrivilegeCount = 1;
    priv.Privileges[0].Luid = luid;
    priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, false, &priv, 0, nullptr, nullptr))
    {
      if (token)
        CloseHandle(token);

      return false;
    }
    if (token)
      CloseHandle(token);

    return true;
  }

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
}