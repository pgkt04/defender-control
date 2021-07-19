// WMIC controls for windows defender module (cmdlet)
//
#include "wmic.hpp"

namespace wmic
{
  // function to test getting data
  //
  bool test_get()
  {
    HRESULT hres;

    // Setup COM library
    //
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);

    if (FAILED(hres))
    {
      std::cout << "Failed to initialize COM. Error code = 0x"
        << std::hex << hres << std::endl;
      return false;
    }


    // Setup general security levels
    //
    hres = CoInitializeSecurity(
      NULL,
      -1,                          // COM authentication
      NULL,                        // Authentication services
      NULL,                        // Reserved
      RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
      RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
      NULL,                        // Authentication info
      EOAC_NONE,                   // Additional capabilities 
      NULL                         // Reserved
    );

    if (FAILED(hres))
    {
      std::cout << "Failed to initialize security. Error code = 0x"
        << std::hex << hres << std::endl;
      CoUninitialize();
      return false;
    }

    // Obtain locator for wmi
    //
    IWbemLocator* loc_ptr = nullptr;

    hres = CoCreateInstance(CLSID_WbemLocator, 0,
      CLSCTX_INPROC_SERVER,
      IID_IWbemLocator, (LPVOID*)&loc_ptr);

    if (FAILED(hres))
    {
      std::cout << "Failed to create IWbemLocator object."
        << " Err code = 0x"
        << std::hex << hres << std::endl;
      CoUninitialize();
      return false;
    }

    // Connect to wmi with IbwemLocator::ConnectServer
    //
    IWbemServices* service_ptr = nullptr;

    hres = loc_ptr->ConnectServer(
      _bstr_t("ROOT\\CIMV2"),
      0, 0, 0, 0, 0, 0, &service_ptr
    );

    if (FAILED(hres))
    {
      std::cout << "Could not connect. Error code = 0x"
        << std::hex << hres << std::endl;
      loc_ptr->Release();
      CoUninitialize();
      return false;
    }

    std::cout << "Connected to ROOT\\CIMV2 WMI namespace" << std::endl;

    // Set security levels for the proxy 
   //

    hres = CoSetProxyBlanket(
      service_ptr,                        // Indicates the proxy to set
      RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
      RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
      NULL,                        // Server principal name 
      RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
      RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
      NULL,                        // client identity
      EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
      std::cout << "Could not set proxy blanket. Error code = 0x"
        << std::hex << hres << std::endl;
      service_ptr->Release();
      loc_ptr->Release();
      CoUninitialize();
      return false;
    }

    // Make requests to the WMI
    //
    BSTR method_name = SysAllocString(L"Create");
    BSTR class_name = SysAllocString(L"Win32_Process");




    return true;
  }
}