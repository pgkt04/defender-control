#include "util.hpp"

namespace util
{
  std::wstring string_to_wide(const std::string& s)
  {
    std::wstring temp(s.length(), L' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
  }

  std::string wide_to_string(const std::wstring& s) {
    std::string temp(s.length(), ' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
  }
}