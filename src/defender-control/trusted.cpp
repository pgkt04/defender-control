#include "trusted.hpp"

namespace trusted
{
  // Enable prvileges
  //
  void enable_privilege()
  {
  }

  // Get target process id
  //
  DWORD get_pid()
  {
    return 0;
  }

  // Give system permissions
  //
  bool impersonate_system()
  {
    return true;
  }

  // Start the trusted installer service
  //
  bool start_trusted()
  {
    return true;
  }

  // Run process with trusted installer privilleges
  //
  bool create_process()
  {
  }
}