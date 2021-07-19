#pragma once

#include <Windows.h>
#include <iostream>

#include "settings.hpp"
#include "reg.hpp"
#include "util.hpp"

namespace DCONTROL
{
  bool disable_defender();
  bool check_defender(uint32_t flags = 0);
}