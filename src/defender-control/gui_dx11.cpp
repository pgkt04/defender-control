#include "gui_dx11.hpp"

namespace gui::dx11
{
  static ID3D11Device* g_device = NULL;
  static ID3D11DeviceContext* g_context = NULL;
  static IDXGISwapChain* g_swapchain = NULL;
  static ID3D11RenderTargetView* g_render_target = NULL;

  bool create_device(HWND hwnd)
  {
    // create swapchain
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = {
      D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, 
    };

    if (D3D11CreateDeviceAndSwapChain(
      NULL, D3D_DRIVER_TYPE_HARDWARE, NULL,0, featureLevelArray,
      2, D3D11_SDK_VERSION, &sd, &g_swapchain, &g_device, &featureLevel, &g_context) != S_OK)
      return false;

    // create render target
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_swapchain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));

    if (!pBackBuffer)
      return false;

    g_device->CreateRenderTargetView(pBackBuffer, NULL, &g_render_target);
    pBackBuffer->Release();

    return true;
  }

  void cleanup()
  {
  }

  void setup(HWND hwnd)
  {
  }

  void start()
  {
  }

  void end()
  {
  }

  void resize()
  {
  }
}