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




    return true;
  }
}