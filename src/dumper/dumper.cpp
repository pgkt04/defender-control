// this is to poc for dumping out registry files as part 2 of the reversal
//
// TO-DO:
// import detours, will need to recompile 32 bit	
// write hook functions
// inject and write findings
// list of functions to hook:
// all imported from ADVAPI32
// RegEnumValueW [done]
// RegDeleteValueW
// RegDeleteKeyW
// RegSetValueExW
// RegCreateKeyExW
// RegConnectRegistryW
// RegEnumKeyExW
// RegCloseKey
// RegQueryValueExW
// RegOpenKeyExW

#include "pch.h"

namespace RegHooks
{
	using reg_enum_value_t = LSTATUS(*)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
	uint64_t reg_enum_valuew_addr;

	// hook for RegEnumValueW
	// ms docs: https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluew
	//
	LSTATUS hk_reg_enum_valuew(
		HKEY    hKey,
		DWORD   dwIndex,
		LPWSTR  lpValueName,
		LPDWORD lpcchValueName,
		LPDWORD lpReserved,
		LPDWORD lpType,
		LPBYTE  lpData,
		LPDWORD lpcbData
	)
	{
		auto original = reinterpret_cast<reg_enum_value_t>(reg_enum_valuew_addr)
			(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData);

		std::cout << "hk_reg_enum_valuew(" << hKey << ", " << dwIndex << ", " << lpValueName << ", "
			<< ", " << lpcchValueName << ", " << lpReserved << ", " << lpType << ", " <<
			", " << lpData << ", " << lpcbData << ");" << std::endl;

		return original;
	}

}

namespace DetourExample
{
	using LoadStr_t = int(*)(HINSTANCE, UINT, LPSTR, int);
	uint64_t loadstr_addr;

	int __stdcall hk_loadstr(HINSTANCE hInstance, UINT uID, LPSTR lpBuffer, int cchBufferMax)
	{
		auto original = ((LoadStr_t)(loadstr_addr))(hInstance, uID, lpBuffer, cchBufferMax);
		return original;
	}

	// only to serve as a temp example, do not call
	void example_hook()
	{
		// perform hooking
		loadstr_addr = (uint64_t)GetProcAddress(GetModuleHandleA("User32.dll"), "LoadStringA");
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)loadstr_addr, hk_loadstr);
		DetourTransactionCommit();
	}
}

namespace DetourHelper
{
	// places a hook 
	void perf_hook()
	{
		// example code from last ctf
		// will add code base for x64 and x32 support, as well as setup empty 
		// project to do this stuff quicky?
	}

	// removes a hook
	void undo_hook()
	{

	}
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

