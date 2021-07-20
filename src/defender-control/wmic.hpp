#pragma once
#include <iostream>
#include <Windows.h>

#define _WIN32_DCOM
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

#include "util.hpp"

namespace wmic
{
  enum class variant_type : int
  {
    t_bool,
    t_bstr,
    t_uint8,
    t_uint32
  };

  class helper
  {
    int last_error;
    HRESULT hres;

    IWbemServices* service_ptr;
    IWbemLocator* loc_ptr;

    IWbemClassObject* class_ptr;
    IWbemClassObject* param_def_ptr;
    IWbemClassObject* class_inst_ptr;

    BSTR method_name;
    BSTR class_name;

  public:

    helper(std::string wnamespace, std::string wclass, std::string wmethod);
    ~helper();

    // Return the last error
    //
    int get_last_error();


    void execute(std::string variable, std::string value)
    {
      VARIANT var_cmd;
      var_cmd.vt = VT_BSTR;
      var_cmd.bstrVal = _bstr_t(util::string_to_wide(value).c_str());

      // Store the value for the parameters
      //
      hres = class_inst_ptr->Put(util::string_to_wide(variable).c_str(), 0, &var_cmd, 0);

      // Execute 
      //
      IWbemClassObject* pOutParams = nullptr;
      hres = service_ptr->ExecMethod(class_name, method_name, 0,
        0, class_inst_ptr, &pOutParams, 0);

      if (FAILED(hres))
      {
        last_error = 7;
        std::cout << "error executing" << std::endl;
      }

      // Cleanup
      //
      VariantClear(&var_cmd);

      if (pOutParams)
        pOutParams->Release();
    }


    // Execute WMI set function
    //
    template<typename T>
    void execute(std::string variable, variant_type type, T value)
    {
      // Create values for in parameter
      //
      VARIANT var_cmd;

      switch (type)
      {
      case variant_type::t_bool:
        var_cmd.vt = VT_BOOL;
        var_cmd.boolVal = value;
        break;

      case variant_type::t_uint8:
        var_cmd.vt = VT_UI1;
        var_cmd.uintVal = value;
        break;

      case variant_type::t_uint32:
        var_cmd.vt = VT_UI4;
        var_cmd.uintVal = value;

      default:
        last_error = 6;
        return;
      }

      // Store the value for the parameters
      //
      hres = class_inst_ptr->Put(util::string_to_wide(variable).c_str(), 0, &var_cmd, 0);

      // Execute 
      //
      IWbemClassObject* pOutParams = nullptr;
      hres = service_ptr->ExecMethod(class_name, method_name, 0,
        0, class_inst_ptr, &pOutParams, 0);

      if (FAILED(hres))
      {
        last_error = 7;
        std::cout << "error executing" << std::endl;
      }

      // Cleanup
      //
      VariantClear(&var_cmd);

      if (pOutParams)
        pOutParams->Release();
    }
  };
}

