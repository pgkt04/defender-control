#include "gui.hpp"

namespace gui
{
  LRESULT CALLBACK window_proc(const HWND hwnd, const UINT msg,
    const WPARAM wParam, const LPARAM lParam)
  {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam))
      return true;

    // TODO:
    switch (msg)
    {
    case WM_SIZE:
      return 0;
    case WM_SYSCOMMAND:
      return 0;
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
    }

    return DefWindowProcA(hwnd, msg, wParam, lParam);
  }

  int main()
  {
    WNDCLASSEXW wc{
      sizeof(WNDCLASSEXW), CS_CLASSDC, window_proc, 0L, 0L,
      GetModuleHandle(0), NULL, NULL, NULL, NULL, L"dx", NULL
    };

    RegisterClassExW(&wc);

    auto hwnd = CreateWindowExW(
      0, wc.lpszClassName, L"dx", WS_OVERLAPPEDWINDOW, 0, 0, 1920, 1080, 0, 0, wc.hInstance, 0
    );

    // TODO:
    //

    return EXIT_SUCCESS;
  }

  void render()
  {

  }
}
