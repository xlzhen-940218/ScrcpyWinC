#ifndef SC_LOG_H
#define SC_LOG_H

#include "../common.h"

#include <SDL_log.h>

#include "../options.h"

#define LOG_STR_IMPL_(x) # x
#define LOG_STR(x) LOG_STR_IMPL_(x)

#define LOGV(...) SDL_LogVerbose(SDL_LOG_CATEGORY_APPLICATION, __VA_ARGS__)
#define LOGD(...) SDL_LogDebug(SDL_LOG_CATEGORY_APPLICATION, __VA_ARGS__)
#define LOGI(...) SDL_LogInfo(SDL_LOG_CATEGORY_APPLICATION, __VA_ARGS__)
#define LOGW(...) SDL_LogWarn(SDL_LOG_CATEGORY_APPLICATION, __VA_ARGS__)
#define LOGE(...) SDL_LogError(SDL_LOG_CATEGORY_APPLICATION, __VA_ARGS__)
#define LOGC(...) SDL_LogCritical(SDL_LOG_CATEGORY_APPLICATION, __VA_ARGS__)

#define LOG_OOM() \
    LOGC("OOM: %s:%d %s()", __FILE__, __LINE__, __func__)

void
sc_set_log_level(enum sc_log_level level);

enum sc_log_level
sc_get_log_level(void);

#endif
