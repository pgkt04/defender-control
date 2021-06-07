// this is to poc for dumping out registry files 
//

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
  // 0x464DC  
  // 
  using alt_start_proc_t = char(__stdcall*)(LPCWSTR, LPCWSTR, LPCWSTR, LPVOID, LPWSTR,
    HANDLE, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
  uintptr_t alt_start_proc_addr;

  char __stdcall hk_alt_start_proc(LPCWSTR lpUsername, LPCWSTR lpDomain,
    LPCWSTR lpPassword, LPVOID Environment, LPWSTR lpCommandLine,
    HANDLE TokenHandle, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
  {
    std::cout << "[Alt Start Proc]" << std::endl;

    return (reinterpret_cast<alt_start_proc_t>(alt_start_proc_addr))(lpUsername, lpDomain,
      lpPassword, Environment, lpCommandLine,
      TokenHandle, lpCurrentDirectory, lpStartupInfo,
      lpProcessInformation);
  }

  // 0x45E0
  //
  using control_table_t = int(__stdcall*)(DWORD*, int);
  uintptr_t ControlTable_addr;

  std::vector<int> cache =
  {
    0x493730, 0x49451c, 0x4950c8, 0x4956f8,
    0x494db0, 0x495620, 0x493b20, 0x4954dc,
    0x4947a4, 0x495b30, 0x494d44
  };

  int __stdcall hk_ControlTable(DWORD* a1, int a2)
  {
    auto ret = (reinterpret_cast<control_table_t>(ControlTable_addr))(a1, a2);

    bool found = false;

    for (auto i : cache)
    {
      if (i == ret)
        found = true;
    }

    if (!found)
    {
      std::cout << "[Control Table] 0x" << std::hex << ret << std::endl;
      cache.push_back(ret);
    }

    return ret;
  }

  // int __stdcall wmic_1(int a1, _DWORD *a2)
  // 0x6CDA0
  // 
  using wmic_1_t = int(__stdcall*)(int, DWORD*);
  uintptr_t wmic_1_addr;

  int __stdcall hk_wmic_1(int a1, DWORD* a2)
  {
    std::cout << "[wmic_1]" << std::endl;
    return (reinterpret_cast<wmic_1_t>(wmic_1_addr))(a1, a2);
  }

  // int __thiscall hk_wmic_2(void* this, int a2, int a3)
  // address: 0x75ACA
  //
  using hk_wmic_2_t = int(__thiscall*)(void*, int, int);
  uintptr_t wmic_2_addr;

  int __fastcall hk_wmic_2(void* pthis, void* edx, int a2, int a3)
  {
    std::cout << "[wmic_2]" << std::endl;
    return (reinterpret_cast<hk_wmic_2_t>(wmic_2_addr))(pthis, a2, a3);
  }

  // wmic helper for setup
  // address: 0x7A999
  // 
  using wmic_helper_t = int(__stdcall*)(int, int, wchar_t*, void*, wchar_t*, void*);
  uintptr_t wmic_helper_addr;

  int __stdcall hk_wmic_helper(int a1, int a2, wchar_t* a3, void* Src, wchar_t* String, void* a6)
  {
    std::cout << "[wmic helper]" << std::endl;
    return (reinterpret_cast<wmic_helper_t>(wmic_helper_addr))(a1, a2, a3, Src, String, a6);
  }

  // helper to check when we enable defender 
  // address: 6AB70
  // calling convention: https://www.unknowncheats.me/forum/849605-post6.html
  // pattern: 55 8B EC 83 E4 F8 83 EC 64 53 56 8B 75 08 8B 46 08 8B D9 57 8D 4C 24 50 89 44 24 20 C7 44 24
  //
  using enable_def_helper_t = int(__thiscall*)(void*, int, DWORD*);
  uintptr_t enable_def_help_addr;

  int __fastcall hk_enable_def(void* pThis, void* edx, int a2, DWORD* a3)
  {
    std::cout << "enabling defender" << std::endl;
    return (reinterpret_cast<enable_def_helper_t>(enable_def_help_addr))(pThis, a2, a3);
  }

  // Disable defender handler
  using disable_def_t = int(__thiscall*)(void*, int, DWORD*);
  uintptr_t disable_def_addr;

  // disable defender routine:
  // 0x6AEAF
  // int __thiscall DisableDefender(void *this, int a1, _DWORD *a2)

  int __fastcall hk_disable_def(void* pThis, void* edx, int a1, DWORD* a2)
  {
    std::cout << "disabling defender" << std::endl;
    return (reinterpret_cast<disable_def_t>(disable_def_addr))(pThis, a1, a2);
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
    std::cout << "Reserved: " << Reserved << std::endl;
    std::cout << "dwType: " << dwType << std::endl;
    std::cout << "cbData: " << cbData << std::endl;

    auto ret = (reinterpret_cast<regsetkeyvalueexw_t>(regsetvalue_addr))(hKey, lpValueName, Reserved, dwType, lpData, cbData);

    std::cout << "Ret: " << ret << std::endl;

    return ret;
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
    std::cout << "hKey: " << hKey << std::endl;
    std::cout << "lpSubKey: " << wide_to_string(lpSubKey).c_str() << std::endl;
    std::cout << "lpClass: " << wide_to_string(lpClass).c_str() << std::endl;
    std::cout << "samDesired: " << samDesired << std::endl;
    std::cout << "Reserved: " << Reserved << std::endl;
    std::cout << "lpSecurityAttributes: " << lpSecurityAttributes << std::endl;
    std::cout << "dwOptions: " << dwOptions << std::endl;
    std::cout << "lpdwDisposition: " << lpdwDisposition << std::endl;

    auto ret = (reinterpret_cast<RegCreateKeyExW_t>(RegCreateKeyExW_addr))
      (hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);

    std::cout << "Ret: " << ret << std::endl;

    return ret;
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

  // RegEnumKeyExW
  // ms docs: https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexw
  //
  using RegEnumKeyExW_t = LSTATUS(__stdcall*)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
  uintptr_t RegEnumKeyExW_addr;

  LSTATUS __stdcall hk_RegEnumKeyExW(
    HKEY      hKey,
    DWORD     dwIndex,
    LPWSTR    lpName,
    LPDWORD   lpcchName,
    LPDWORD   lpReserved,
    LPWSTR    lpClass,
    LPDWORD   lpcchClass,
    PFILETIME lpftLastWriteTime
  )
  {
    std::cout << "[RegEnumKeyExW]" << std::endl;
    std::cout << "lpName: " << wide_to_string(lpName).c_str() << std::endl;

    return (reinterpret_cast<RegEnumKeyExW_t>(RegEnumKeyExW_addr))
      (hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
  }

  // RegCloseKey
  // ms docs: https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey
  // seems redundant to hook
  //
  LSTATUS __stdcall hk_RegCloseKey(
    HKEY hKey
  )
  {
    return EXIT_SUCCESS;
  }

  // RegQueryValueExW 
  // ms docs: https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw
  //
  using RegQueryValueExW_t = LSTATUS(__stdcall*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
  uintptr_t RegQueryValueExW_addr;

  LSTATUS __stdcall hk_RegQueryValueExW(
    HKEY    hKey,
    LPCWSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE  lpData,
    LPDWORD lpcbData
  )
  {
    std::cout << "[RegQueryValueExW]" << std::endl;
    std::cout << "lpValueName: " << wide_to_string(lpValueName).c_str() << std::endl;

    return (reinterpret_cast<RegQueryValueExW_t>(RegQueryValueExW_addr))
      (hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
  }

  // RegOpenKeyExW
  // ms docs: https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw
  //
  using RegOpenKeyExW_t = LSTATUS(__stdcall*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
  uintptr_t RegOpenKeyExW_addr;

  LSTATUS __stdcall hk_RegOpenKeyExW(
    HKEY    hKey,
    LPCWSTR lpSubKey,
    DWORD   ulOptions,
    REGSAM  samDesired,
    PHKEY   phkResult
  )
  {
    std::cout << "[RegOpenKeyExW]" << std::endl;
    std::cout << "lpValueName: " << wide_to_string(lpSubKey).c_str() << std::endl;
    std::cout << "ulOptions: " << ulOptions << std::endl;
    std::cout << "samDesired: " << samDesired << std::endl;

    return (reinterpret_cast<RegOpenKeyExW_t>(RegOpenKeyExW_addr))
      (hKey, lpSubKey, ulOptions, samDesired, phkResult);
  }

  // CreateProcessW 
  // ms docs: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
  //
  using CreateProcessW_t = BOOL(__stdcall*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
  uintptr_t CreateProcessW_addr;

  BOOL __stdcall hk_CreateProcessW(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
  )
  {
    std::cout << "[CreateProcessW]" << std::endl;
    std::cout << "lpCommandLine: " << wide_to_string(lpCommandLine).c_str() << std::endl;

    return (reinterpret_cast<CreateProcessW_t>(CreateProcessW_addr))(
      lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
      bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
      lpStartupInfo, lpProcessInformation);
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
  auto kernel32 = GetModuleHandleA("Kernel32.dll");

  if (!advapi32)
  {
    std::cout << "advapi32.dll not found" << std::endl;
    return;
  }

  if (!kernel32)
  {
    std::cout << "kernel32.dll not found" << std::endl;
    return;
  }

  RegHooks::regdeletekeyw_addr = get_func_addr(advapi32, "RegDeleteKeyW");
  RegHooks::regdeletevaluew_addr = get_func_addr(advapi32, "RegDeleteValueW");
  RegHooks::regenumvaluew_addr = get_func_addr(advapi32, "RegEnumValueW");
  RegHooks::regsetvalue_addr = get_func_addr(advapi32, "RegSetValueExW");
  RegHooks::RegCreateKeyExW_addr = get_func_addr(advapi32, "RegCreateKeyExW");
  RegHooks::RegConnectRegistryW_addr = get_func_addr(advapi32, "RegConnectRegistryW");
  RegHooks::RegEnumKeyExW_addr = get_func_addr(advapi32, "RegEnumKeyExW");
  RegHooks::RegQueryValueExW_addr = get_func_addr(advapi32, "RegQueryValueExW");
  RegHooks::RegOpenKeyExW_addr = get_func_addr(advapi32, "RegOpenKeyExW");
  RegHooks::CreateProcessW_addr = get_func_addr(kernel32, "CreateProcessW");


  std::cout << "imports resolved\npreparing to hook" << std::endl;

  // reg hooks
  //
#if 0
  DetourHelper::perf_hook((PVOID*)&RegHooks::regdeletekeyw_addr, RegHooks::hk_RegDeleteKeyW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::regdeletevaluew_addr, RegHooks::hk_RegDeleteValueW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::regenumvaluew_addr, RegHooks::hk_RegEnumValueW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::regsetvalue_addr, RegHooks::hk_RegSetValueExW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::RegCreateKeyExW_addr, RegHooks::hk_RegCreateKeyExW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::RegConnectRegistryW_addr, RegHooks::hk_RegConnectRegistryW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::RegEnumKeyExW_addr, RegHooks::hk_RegEnumKeyExW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::RegQueryValueExW_addr, RegHooks::hk_RegQueryValueExW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::RegOpenKeyExW_addr, RegHooks::hk_RegOpenKeyExW);
#endif

  DetourHelper::perf_hook((PVOID*)&RegHooks::CreateProcessW_addr, RegHooks::hk_CreateProcessW);


  // native hooks
  // 
#if 0
  RegHooks::enable_def_help_addr = (uintptr_t)GetModuleHandleA(0) + 0x6AB70;
  DetourHelper::perf_hook((PVOID*)&RegHooks::enable_def_help_addr, RegHooks::hk_enable_def);

  RegHooks::disable_def_addr = (uintptr_t)GetModuleHandleA(0) + 0x6AEAF;
  DetourHelper::perf_hook((PVOID*)&RegHooks::disable_def_addr, RegHooks::hk_disable_def);

  RegHooks::wmic_helper_addr = (uintptr_t)GetModuleHandleA(0) + 0x7A999;
  DetourHelper::perf_hook((PVOID*)&RegHooks::wmic_helper_addr, RegHooks::hk_wmic_helper);

  RegHooks::wmic_1_addr = (uintptr_t)GetModuleHandleA(0) + 0x6CDA0;
  DetourHelper::perf_hook((PVOID*)&RegHooks::wmic_1_addr, RegHooks::hk_wmic_1);

  RegHooks::wmic_2_addr = (uintptr_t)GetModuleHandleA(0) + 0x75ACA;
  DetourHelper::perf_hook((PVOID*)&RegHooks::wmic_2_addr, RegHooks::hk_wmic_2);

  RegHooks::ControlTable_addr = (uintptr_t)GetModuleHandleA(0) + 0x45E0;
  DetourHelper::perf_hook((PVOID*)&RegHooks::ControlTable_addr, RegHooks::hk_ControlTable);
#endif

  RegHooks::alt_start_proc_addr = (uintptr_t)GetModuleHandleA(0) + 0x464DC;
  DetourHelper::perf_hook((PVOID*)&RegHooks::alt_start_proc_addr, RegHooks::hk_alt_start_proc);

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

