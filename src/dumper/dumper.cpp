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
// implement wstring

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
    std::cout << "[RegEnumValueW]" << std::endl;

    if (lpValueName)
      std::cout << "lpValueName: " << wide_to_string(lpValueName).c_str() << std::endl;

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

    return (reinterpret_cast<regdeletekeyw_t>(regdeletekeyw_addr))(hKey, lpSubKey);;
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
  freopen("CONIN$", "r", stdin);
  freopen("CONOUT$", "w", stdout);
  freopen("CONOUT$", "w", stderr);
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

  std::cout << "imports resolved\npreparing to hook" << std::endl;

  // reg hooks
  //
  DetourHelper::perf_hook((PVOID*)&RegHooks::regdeletekeyw_addr, RegHooks::hk_RegDeleteKeyW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::regdeletevaluew_addr, RegHooks::hk_RegDeleteValueW);
  DetourHelper::perf_hook((PVOID*)&RegHooks::regenumvaluew_addr, RegHooks::hk_RegEnumValueW);

  // activation hooks
  // 
  RegHooks::enable_def_help_addr = (uintptr_t)GetModuleHandleA(0) + 0x6AB70;
  DetourHelper::perf_hook((PVOID*)&RegHooks::enable_def_help_addr, RegHooks::enable_def_helper);
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

