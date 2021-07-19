#pragma once
#include <string>

namespace util
{
  std::wstring string_to_wide(const std::string& s);
  std::string wide_to_string(const std::wstring& s);
}
