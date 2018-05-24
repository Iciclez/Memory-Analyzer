#include <windows.h>
#include "dllmain.hpp"
#include "memory_analyzer.hpp"

#include <thread>
#include <iostream>



dllmain::dllmain()
{
}

dllmain::~dllmain() noexcept
{
}

void dllmain::on_attach()
{
	AllocConsole();

	_iobuf * file = 0;
	freopen_s(&file, "CON", "r", stdin);
	freopen_s(&file, "CON", "w", stdout);
	freopen_s(&file, "CON", "w", stderr);

	memory_analyzer().begin_analysis_work();
}

void dllmain::on_detach()
{
	FreeConsole();
}


BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(lpvReserved);

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hinstDLL);
		dllmain::on_attach();
		break;

	case DLL_PROCESS_DETACH:
		dllmain::on_detach();
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;
	}

	return TRUE;
}
