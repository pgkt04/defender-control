#pragma once

#include <Windows.h>
#include <iostream>

#define DBG_MSG (1 << 0)

namespace REG
{
  DWORD read_key(const wchar_t* root_name, const wchar_t* value_name, uint32_t flags = 0);
}

namespace DCONTROL
{
  bool check_defender(uint32_t flags = 0);
}