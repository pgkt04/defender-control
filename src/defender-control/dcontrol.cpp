#include "dcontrol.hpp"

namespace DCONTROL
{
  // disables window defender
  //
  bool disable_defender()
  {
    if (!util::sub_43604B())
    {
      std::cout << "permission error" << std::endl;
      return false;
    }

    util::set_privilege(SE_DEBUG_NAME, TRUE);

    HKEY hkey;

    // DisableAntiSpyware
    {
      if (!REG::create_registry(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", hkey))
      {
        std::cout << "failed to access Policies" << std::endl;
        return false;
      }

      if (!REG::set_keyval(hkey, L"DisableAntiSpyware", 1))
      {
        std::cout << "failed to write to DisableAntiSpyware" << std::endl;
        return false;
      }

#if 0
      if (!REG::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender", hkey))
      {
        std::cout << "failed to access Windows Defender" << std::endl;
        return false;
      }

      if (!REG::set_keyval(hkey, L"DisableAntiSpyware", 1))
      {
        std::cout << "failed to write to DisableAntiSpyware" << std::endl;
        return false;
      }
#endif
    }

    // Start (3 off) (2 on)
    {
      if (!REG::create_registry(L"SYSTEM\\CurrentControlSet\\Services\\WinDefend", hkey))
      {
        std::cout << "failed to access CurrentControlSet" << std::endl;
        return false;
      }

      if (!REG::set_keyval(hkey, L"Start", 3))
      {
        std::cout << "failed to write to Start" << std::endl;
        return false;
      }
    }

    std::cout << "Wrote to Start" << std::endl;


    // SecurityHealth
    {
      if (!REG::create_registry(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run", hkey))
      {
        std::cout << "failed to access CurrentVersion" << std::endl;
        return false;
      }

      if (!REG::set_keyval_bin(hkey, L"SecurityHealth", 3))
      {
        std::cout << "failed to write to SecurityHealth" << std::endl;
        return false;
      }
    }

    std::cout << "Wrote to SecurityHealth" << std::endl;


#if 0
    // DisableRealtimeMonitoring
    {
      if (!REG::create_registry(L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", hkey))
      {
        std::cout << "failed to access registry" << std::endl;
        return false;
      }
      if (!REG::set_keyval(hkey, L"DisableRealtimeMonitoring", 1))
      {
        std::cout << "failed to disable DisableRealtimeMonitoring" << std::endl;
        return false;
  }
}
#endif

    return true;
  }

  // Checks whether Real-Time Protection is activated on windows
  //
  bool check_defender(uint32_t flags)
  {
    return REG::read_key(
      L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
      L"DisableRealtimeMonitoring") == 0;
  }
}