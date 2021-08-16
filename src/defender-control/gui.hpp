#pragma once
#include <Windows.h>
#include <imgui_impl_win32.h>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
  HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace gui
{

}
