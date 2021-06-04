// this is to poc for dumping out registry files as part 2 of the reversal
//
// TO-DO:
// inject and write findings
// list of functions to hook from ADVAPI32
// RegEnumValueW [done]
// RegDeleteValueW [done]
// RegDeleteKeyW [done]
// RegSetValueExW [done]
// RegCreateKeyExW [done]
// RegConnectRegistryW [done]
// RegEnumKeyExW
// RegCloseKey
// RegQueryValueExW
// RegOpenKeyExW
// reformat printing if succesfully hooked

#include "pch.h"

std::wstring string_to_wide(const std::string& s)
{
  std::wstring temp(s.length(), L' ');
  std::copy(s.begin(), s.end(), temp.begin());
  return temp;
}

std::string wide_to_string(const std::wstring& s) {
  std::string temp(s.length(), ' ');
  std::copy(s.begin(), s.end(), temp.begin());
  return temp;
}

namespace RegHooks
{
  // helper to check when we enable defender 
  // address: 0046AB70
  // base: 400000
  // rel: base+6AB70
  // we can try a thiscall variant or cdecltype
  // https://www.unknowncheats.me/forum/849605-post6.html
  // int __thiscall enable_def_helper(int *this, int a2, _DWORD *a3)
  // pattern: 55 8B EC 83 E4 F8 83 EC 64 53 56 8B 75 08 8B 46 08 8B D9 57 8D 4C 24 50 89 44 24 20 C7 44 24
  //
  using enable_def_helper_t = int(__thiscall*)(void*, int, DWORD*);
  uintptr_t enable_def_help_addr;

  int __fastcall enable_def_helper(void* pThis, void* edx, int a2, DWORD* a3)
  {
    std::cout << "activation routine" << std::endl;
    auto v37 = *(DWORD*)(a2 + 8);
    std::cout << "v37: " << v37 << std::endl;
    return (reinterpret_cast<enable_def_helper_t>(enable_def_help_addr))(pThis, a2, a3);
  }

  // WM_COMMAND handler
  // base+05F48E
  //
  using handle_command_t = char(__stdcall*)(int, UINT, UINT);
  uintptr_t handle_command_addr;

  char __stdcall HandleCommand(int a1, UINT wparam, UINT lparam)
  {
    std::cout << "handlecommand(" << wparam << ", " << lparam << ")" << std::endl;
    return (reinterpret_cast<handle_command_t>(handle_command_addr))(a1, wparam, lparam);
  }

  // hook for RegEnumValueW
  // ms docs: https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluew
  //
  using regenumvaluew_t = LSTATUS(__stdcall*)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
  uintptr_t regenumvaluew_addr;

  LSTATUS __stdcall hk_RegEnumValueW(
    HKEY hKey,
    DWORD dwIndex,
    LPWSTR lpValueName,
    LPDWORD lpcchValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
  )
  {
    // there is a bug with a ridiculously large string we want to skip if we see it
    //
    auto converted = wide_to_string(lpValueName);

    if (converted.size() < MAX_PATH)
    {
      std::cout << "[RegEnumValueW]" << std::endl;
      std::cout << "lpValueName: " << converted.c_str() << std::endl;
    }

    return (reinterpret_cast<regenumvaluew_t>(regenumvaluew_addr))
      (hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData);
  }

  // hook for RegDeleteValueW
  // ms docs: https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regdeletevaluew
  // 
  using regdeletevaluew_t = LSTATUS(__stdcall*)(HKEY, LPCWSTR);
  uintptr_t regdeletevaluew_addr;

  LSTATUS __stdcall hk_RegDeleteValueW(
    HKEY    hKey,
    LPCWSTR lpValueName
  )
  {
    std::cout << "[RegDeleteValueW]" << std::endl;
    std::cout << "lpValueName" << wide_to_string(lpValueName).c_str() << std::endl;

    return (reinterpret_cast<regdeletevaluew_t>(regdeletevaluew_addr))(hKey, lpValueName);;
  }

  // hook for RegDeleteKeyW
  // https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regdeletekeyw
  //  
  using regdeletekeyw_t = LSTATUS(__stdcall*)(HKEY, LPCWSTR);
  uintptr_t regdeletekeyw_addr;

  LSTATUS __stdcall hk_RegDeleteKeyW(
    HKEY    hKey,
    LPCWSTR lpSubKey
  )
  {
    std::cout << "[RegDeleteValueW]" << std::endl;
    std::cout << "lpSubkey" << wide_to_string(lpSubKey).c_str() << std::endl;

    return (reinterpret_cast<regdeletekeyw_t>(regdeletekeyw_addr))(hKey, lpSubKey);
  }

  // RegSetValueExW
  // ms docs: https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw
  //
  using regsetkeyvalueexw_t = LSTATUS(__stdcall*)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
  uintptr_t regsetvalue_addr;

  LSTATUS __stdcall hk_RegSetValueExW(
    HKEY       hKey,
    LPCWSTR    lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE* lpData,
    DWORD      cbData
  )
  {
    std::cout << "[RegSetValueExW]" << std::endl;
    std::cout << "lpValueName: " << wide_to_string(lpValueName).c_str() << std::endl;
    return (reinterpret_cast<regsetkeyvalueexw_t>(regsetvalue_addr))(hKey, lpValueName, Reserved, dwType, lpData, cbData);
  }

  // RegCreateKeyExW
  // ms docs: https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw
  //
  using RegCreateKeyExW_t = LSTATUS(__stdcall*)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES,
    PHKEY, LPDWORD);
  uintptr_t RegCreateKeyExW_addr;

  LSTATUS __stdcall hk_RegCreateKeyExW(
    HKEY                        hKey,
    LPCWSTR                     lpSubKey,
    DWORD                       Reserved,
    LPWSTR                      lpClass,
    DWORD                       dwOptions,
    REGSAM                      samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY                       phkResult,
    LPDWORD                     lpdwDisposition
  )
  {
    std::cout << "[RegCreateKeyExW]" << std::endl;
    std::cout << "lpSubKey: " << wide_to_string(lpSubKey).c_str() << std::endl;
    std::cout << "lpClass: " << wide_to_string(lpClass).c_str() << std::endl;

    return (reinterpret_cast<RegCreateKeyExW_t>(RegCreateKeyExW_addr))
      (hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
  }

  // RegConnectRegistryW
  // ms docs: https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regconnectregistryw
  //
  using RegConnectRegistryW_t = LSTATUS(__stdcall*)(LPCWSTR, HKEY, PHKEY);
  uintptr_t RegConnectRegistryW_addr;

  LSTATUS __stdcall hk_RegConnectRegistryW(
    LPCWSTR lpMachineName,
    HKEY    hKey,
    PHKEY   phkResult
  )
  {
    std::cout << "[RegConnectRegistryW]" << std::endl;
    std::cout << "MachineName: " << wide_to_string(lpMachineName).c_str() << std::endl;
    return (reinterpret_cast<RegConnectRegistryW_t>(RegConnectRegistryW_addr))(lpMachineName, hKey, phkResult);
  }
}

namespace DetourHelper
{
  // places a hook 
  //
  void perf_hook(PVOID* oFunction, PVOID pDetour) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(oFunction, pDetour);
    DetourTransactionCommit();
  }

  // removes a hook
  //
  void undo_hook(PVOID* oFunction, PVOID pDetour) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(oFunction, pDetour);
    DetourTransactionCommit();
  }
}

uintptr_t get_func_addr(HMODULE mod, const char* name)
{
  auto ret = reinterpret_cast<uintptr_t>(GetProcAddress(mod, name));
  if (!ret)
    std::cout << "failed to get " << name << std::endl;
  std::cout << "obtained " << name << " from " << mod << std::endl;
  return ret;
}

void thread_main()
{
  // setup console
  //
  AllocConsole();
  UNREFERENCED_PARAMETER(freopen("CONIN$", "r", stdin));
  UNREFERENCED_PARAMETER(freopen("CONOUT$", "w", stdout));
  UNREFERENCED_PARAMETER(freopen("CONOUT$", "w", stderr));
  SetConsoleTitleA("Log");

  // setup hooks
  //
  auto advapi32 = GetModuleHandleA("Advapi32.dll");

  if (!advapi32)
  {
    std::cout << "advapi32.dll not found" << std::endl;
    return;
  }

  RegHooks::regdeletekeyw_addr = get_func_addr(advapi32, "RegDeleteKeyW");
  RegHooks::regdeletevaluew_addr = get_func_addr(advapi32, "RegDeleteValueW");
  RegHooks::regenumvaluew_addr = get_func_addr(advapi32, "RegEnumValueW");
  RegHooks::regsetvalue_addr = get_func_addr(advapi32, "RegSetValueExW");
  RegHooks::RegCreateKeyExW_addr = get_func_addr(advapi32, "RegCreateKeyExW");
  RegHooks::RegConnectRegistryW_addr = get_func_addr(advapi32, "RegConnectRegistryW");

  std::cout << "imports resolved\npreparing to hook" << std::endl;

  // reg hooks
  //
  DetourHelper::perf_hook((PVOID*)&RegHooks::regdeletekeyw_addr, RegHooks::hk_RegDeleteKeyW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::regdeletevaluew_addr, RegHooks::hk_RegDeleteValueW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::regenumvaluew_addr, RegHooks::hk_RegEnumValueW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::regsetvalue_addr, RegHooks::hk_RegSetValueExW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::RegCreateKeyExW_addr, RegHooks::hk_RegCreateKeyExW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::RegConnectRegistryW_addr, RegHooks::hk_RegConnectRegistryW);


  // native hooks
  // pretty redunant dont need to enable them
  // 
#if 0
  RegHooks::enable_def_help_addr = (uintptr_t)GetModuleHandleA(0) + 0x6AB70;
  DetourHelper::perf_hook((PVOID*)&RegHooks::enable_def_help_addr, RegHooks::enable_def_helper);

  RegHooks::handle_command_addr = (uintptr_t)GetModuleHandleA(0) + 0x5F48E;
  DetourHelper::perf_hook((PVOID*)&RegHooks::handle_command_addr, RegHooks::HandleCommand);
#endif
}

BOOL APIENTRY DllMain(HMODULE hModule,
  DWORD  ul_reason_for_call,
  LPVOID lpReserved
)
{
  switch (ul_reason_for_call)
  {
  case DLL_PROCESS_ATTACH:
    CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(thread_main), 0, 0, 0);
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}

