#pragma once
#include <iostream>
#include <Windows.h>

#define _WIN32_DCOM
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

namespace wmic
{
  // function to test getting data
  //
  bool test_get();
}
