// WMIC controls for windows defender module (cmdlet)
// mppreference: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mppreference
// wmi: https://docs.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer
// 
#include "wmic.hpp"

namespace wmic
{
  helper::helper(std::string wnamespace, std::string wclass, std::string wmethod)
  {
    // Initialize 
    //
    last_error = 0;
    hres = 0;
    loc_ptr = nullptr;
    service_ptr = nullptr;
    class_ptr = nullptr;
    param_def_ptr = nullptr;
    class_inst_ptr = nullptr;

    method_name = SysAllocString(util::string_to_wide(wmethod).c_str());
    class_name = SysAllocString(util::string_to_wide(wclass).c_str());

    class_name_s = wclass;

    // Setup COM library
    //
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);

    if (FAILED(hres))
    {
      last_error = 1;
      return;
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
      last_error = 2;
      CoUninitialize();
      return;
    }

    // Obtain locator for wmi
    //
    hres = CoCreateInstance(CLSID_WbemLocator, 0,
      CLSCTX_INPROC_SERVER,
      IID_IWbemLocator, (LPVOID*)&loc_ptr);

    if (FAILED(hres))
    {
      last_error = 3;
      CoUninitialize();
      return;
    }

    // Connect to wmi with IbwemLocator::ConnectServer
    //
    hres = loc_ptr->ConnectServer(
      _bstr_t(wnamespace.c_str()),
      0, 0, 0, 0, 0, 0, &service_ptr
    );

    if (FAILED(hres))
    {
      last_error = 4;
      loc_ptr->Release();
      CoUninitialize();
      return;
    }

    // Set security levels for the proxy 
    //
    hres = CoSetProxyBlanket(
      service_ptr,                 // Indicates the proxy to set
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
      last_error = 5;
      service_ptr->Release();
      loc_ptr->Release();
      CoUninitialize();
      return;
    }

    // Setup WMI request
    //
    hres = service_ptr->GetObjectA(class_name, 0, 0, &class_ptr, 0);
    hres = class_ptr->GetMethod(method_name, 0, &param_def_ptr, 0);
    hres = param_def_ptr->SpawnInstance(0, &class_inst_ptr);
  }

  helper::~helper()
  {
    SysFreeString(class_name);
    SysFreeString(method_name);

    if (class_ptr)
      class_ptr->Release();

    if (class_inst_ptr)
      class_inst_ptr->Release();

    if (param_def_ptr)
      param_def_ptr->Release();

    if (loc_ptr)
      loc_ptr->Release();

    if (service_ptr)
      service_ptr->Release();

    CoUninitialize();
  }

  // Return the last error
  //
  int helper::get_last_error()
  {
    return last_error;
  }
}
