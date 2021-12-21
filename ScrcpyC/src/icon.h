#ifndef ICON_H
#define ICON_H

#include "common.h"

#include <stdbool.h>
#include <SDL.h>
#include <libavformat/avformat.h>

SDL_Surface *
scrcpy_icon_load(void);

void
scrcpy_icon_destroy(SDL_Surface *icon);

#endif
