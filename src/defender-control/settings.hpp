#pragma once

#define DBG_MSG (1 << 0)

#define DEFENDER_ENABLE 1
#define DEFENDER_DISABLE 2

#ifndef DEFENDER_CONFIG
#define DEFENDER_CONFIG DEFENDER_DISABLE
#endif

