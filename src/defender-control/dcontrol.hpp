#pragma once

#include <Windows.h>
#include <iostream>

#include "settings.hpp"
#include "reg.hpp"
#include "util.hpp"
#include "wmic.hpp"

namespace dcontrol
{
  bool disable_defender();
  bool enable_defender();
  bool check_defender(uint32_t flags = 0);
}