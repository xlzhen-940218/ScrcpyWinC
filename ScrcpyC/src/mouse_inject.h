#ifndef SC_MOUSE_INJECT_H
#define SC_MOUSE_INJECT_H

#include "common.h"

#include <stdbool.h>

#include "controller.h"
#include "screen.h"
#include "trait/mouse_processor.h"

struct sc_mouse_inject {
    struct sc_mouse_processor mouse_processor; // mouse processor trait

    struct controller *controller;
    struct screen *screen;
};

void
sc_mouse_inject_init(struct sc_mouse_inject *mi, struct controller *controller,
                     struct screen *screen);

#endif
