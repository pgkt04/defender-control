#pragma once

#include <Windows.h>
#include <iostream>

#define DBG_MSG (1 << 0)

namespace REG
{
  DWORD read_key(const wchar_t* root_name, const wchar_t* value_name, uint32_t flags = 0);
  bool create_registry(const wchar_t* root_name, HKEY& hkey);
  bool set_keyval(HKEY& hkey, const wchar_t* value_name, DWORD value);
  bool set_keyval_bin(HKEY& hkey, const wchar_t* value_name, DWORD value);
}

namespace DCONTROL
{
  bool disable_defender();
  bool check_defender(uint32_t flags = 0);
}