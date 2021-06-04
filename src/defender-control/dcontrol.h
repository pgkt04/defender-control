#pragma once

#include <Windows.h>
#include <iostream>

#define DBG_MSG (1 << 0)

namespace DCONTROL
{
  bool check_defender(uint32_t flags = 0);
}