#ifndef TINYXPM_H
#define TINYXPM_H

#include <SDL.h>

#include "util/config.h"

SDL_Surface *
read_xpm(char *xpm[]);

#endif
