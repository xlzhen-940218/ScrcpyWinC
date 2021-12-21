#ifndef SC_KEY_PROCESSOR_H
#define SC_KEY_PROCESSOR_H

#include "common.h"

#include <assert.h>
#include <stdbool.h>

#include <SDL_events.h>

/**
 * Key processor trait.
 *
 * Component able to process and inject keys should implement this trait.
 */
struct sc_key_processor {
    /**
     * Set by the implementation to indicate that it must explicitly wait for
     * the clipboard to be set on the device before injecting Ctrl+v to avoid
     * race conditions. If it is set, the input_manager will pass a valid
     * ack_to_wait to process_key() in case of clipboard synchronization
     * resulting of the key event.
     */
    bool async_paste;

    const struct sc_key_processor_ops *ops;
};

struct sc_key_processor_ops {

    /**
     * Process the keyboard event
     *
     * The `sequence` number (if different from `SC_SEQUENCE_INVALID`) indicates
     * the acknowledgement number to wait for before injecting this event.
     * This allows to ensure that the device clipboard is set before injecting
     * Ctrl+v on the device.
     */
    void
    (*process_key)(struct sc_key_processor *kp, const SDL_KeyboardEvent *event,
                   uint64_t ack_to_wait);

    void
    (*process_text)(struct sc_key_processor *kp,
                    const SDL_TextInputEvent *event);
};

#endif
