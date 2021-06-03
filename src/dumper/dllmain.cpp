// this is to poc for dumping out registry files as part 2 of the reversal
//
// TO-DO:
// import detours, will need to recompile 32 bit	
// write hook functions
// inject and write findings
// list of functions to hook:
// all imported from ADVAPI32
// RegEnumValueW
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

void perf_hook()
{
	// example code from last ctf
	// will add code base for x64 and x32 support, as well as setup empty 
	// project to do this stuff quicky?
#if 0
	using LoadStr_t = int(*)(HINSTANCE, UINT, LPSTR, int);
	uint64_t loadstr_addr;

	// perform hooking
	loadstr_addr = (uint64_t)GetProcAddress(GetModuleHandleA("User32.dll"), "LoadStringA");

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)loadstr_addr, hk_loadstr);
	DetourTransactionCommit();
#endif
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

