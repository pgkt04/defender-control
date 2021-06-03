// this is to poc for dumping out registry files as part 2 of the reversal
//
// TO-DO:
// add 32 bit support + retargetting [done?]
// import detours, will need to recompile 32 bit [done]
// write hook functions [working on it]
// inject and write findings
// list of functions to hook:
// all imported from ADVAPI32
// RegEnumValueW [done]
// RegDeleteValueW [done]
// RegDeleteKeyW [done]
// RegSetValueExW
// RegCreateKeyExW
// RegConnectRegistryW
// RegEnumKeyExW
// RegCloseKey
// RegQueryValueExW
// RegOpenKeyExW
// reformat printing if succesfully hooked.
// use wide cout format [done]

#include "pch.h"

namespace RegHooks
{
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
    std::wcout << "[RegEnumValueW]" << std::endl;
    //std::wcout << "lpValueName: " << lpValueName << std::endl;

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
    auto original = (reinterpret_cast<regdeletevaluew_t>(regdeletevaluew_addr))(hKey, lpValueName);

    std::wcout << "RegDeleteValueW(" << hKey << ", " << lpValueName << ");" << std::endl;

    return original;
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
    auto original = (reinterpret_cast<regdeletekeyw_t>(regdeletekeyw_addr))(hKey, lpSubKey);
    std::wcout << "RegDeleteValueW(" << hKey << ", " << lpSubKey << ");" << std::endl;
    return original;
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
    std::wcout << "failed to get " << name << std::endl;

  std::wcout << "obtained " << name << " from " << mod << std::endl;

  return ret;
}

void thread_main()
{
  // setup console
  //
  AllocConsole();
  freopen("CONIN$", "r", stdin);
  freopen("CONOUT$", "w", stdout);
  freopen("CONOUT$", "w", stderr);
  SetConsoleTitleA("Log");

  // setup hooks
  //
  auto advapi32 = GetModuleHandleA("Advapi32.dll");

  if (!advapi32)
  {
    std::wcout << "advapi32.dll not found" << std::endl;
    return;
  }

  RegHooks::regdeletekeyw_addr = get_func_addr(advapi32, "RegDeleteKeyW");
  RegHooks::regdeletevaluew_addr = get_func_addr(advapi32, "RegDeleteValueW");
  RegHooks::regenumvaluew_addr = get_func_addr(advapi32, "RegEnumValueW");

  std::wcout << "imports resolved\npreparing to hook" << std::endl;

  DetourHelper::perf_hook((PVOID*)&RegHooks::regdeletekeyw_addr, RegHooks::hk_RegDeleteKeyW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::regdeletevaluew_addr, RegHooks::hk_RegDeleteValueW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::regenumvaluew_addr, RegHooks::hk_RegEnumValueW);
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

