#include "controller.h"

#include <assert.h>

#include "util/config.h"
#include "util/lock.h"
#include "util/log.h"

bool
controller_init(struct controller* controller, socket_t control_socket) {
	cbuf_init(&controller->queue);

	if (!receiver_init(&controller->receiver, control_socket)) {
		return false;
	}

	if (!(controller->mutex = SDL_CreateMutex())) {
		receiver_destroy(&controller->receiver);
		return false;
	}

	if (!(controller->msg_cond = SDL_CreateCond())) {
		receiver_destroy(&controller->receiver);
		SDL_DestroyMutex(controller->mutex);
		return false;
	}

	controller->control_socket = control_socket;
	controller->stopped = false;

	return true;
}

bool controller_cbuf_take_fix(struct control_msg_queue* queue
	, struct control_msg* msg) {
	bool ok = !cbuf_is_empty(queue);
	if (ok) {

		*(msg) = (queue)->data[(queue)->tail];
		(queue)->tail = ((queue)->tail + 1) % cbuf_size_(queue);
	}
	return ok;
}

bool controller_cbuf_push_fix(struct control_msg_queue* queue
	, struct control_msg* msg) {
	bool ok = !cbuf_is_full(queue);
	if (ok) {

		(queue)->data[(queue)->head] = (*msg);
		(queue)->head = ((queue)->head + 1) % cbuf_size_(queue);
	}
	return	ok;
}

void
controller_destroy(struct controller* controller) {
	SDL_DestroyCond(controller->msg_cond);
	SDL_DestroyMutex(controller->mutex);

	struct control_msg msg;

	while (controller_cbuf_take_fix(&controller->queue, &msg)) {
		control_msg_destroy(&msg);
	}

	receiver_destroy(&controller->receiver);
}



bool
controller_push_msg(struct controller* controller,
	const struct control_msg* msg) {
	mutex_lock(controller->mutex);
	bool was_empty = cbuf_is_empty(&controller->queue);
	bool res = controller_cbuf_push_fix(&controller->queue, msg);
	if (was_empty) {
		cond_signal(controller->msg_cond);
	}
	mutex_unlock(controller->mutex);
	return res;
}



static bool
process_msg(struct controller* controller,
	const struct control_msg* msg) {
	static unsigned char serialized_msg[CONTROL_MSG_MAX_SIZE];
	int length = control_msg_serialize(msg, serialized_msg);
	if (!length) {
		return false;
	}
	int w = net_send_all(controller->control_socket, serialized_msg, length);
	return w == length;
}

static int
run_controller(void* data) {
	struct controller* controller = data;

	for (;;) {
		mutex_lock(controller->mutex);
		while (!controller->stopped && cbuf_is_empty(&controller->queue)) {
			cond_wait(controller->msg_cond, controller->mutex);
		}
		if (controller->stopped) {
			// stop immediately, do not process further msgs
			mutex_unlock(controller->mutex);
			break;
		}
		struct control_msg msg;
		bool non_empty = controller_cbuf_take_fix(&controller->queue, &msg);
		assert(non_empty);
		(void)non_empty;
		mutex_unlock(controller->mutex);

		bool ok = process_msg(controller, &msg);
		control_msg_destroy(&msg);
		if (!ok) {
			LOGD("Could not write msg to socket");
			break;
		}
	}
	return 0;
}

bool
controller_start(struct controller* controller) {
	LOGD("Starting controller thread");

	controller->thread = SDL_CreateThread(run_controller, "controller",
		controller);
	if (!controller->thread) {
		LOGC("Could not start controller thread");
		return false;
	}

	if (!receiver_start(&controller->receiver)) {
		controller_stop(controller);
		SDL_WaitThread(controller->thread, NULL);
		return false;
	}

	return true;
}

void
controller_stop(struct controller* controller) {
	mutex_lock(controller->mutex);
	controller->stopped = true;
	cond_signal(controller->msg_cond);
	mutex_unlock(controller->mutex);
}

void
controller_join(struct controller* controller) {
	SDL_WaitThread(controller->thread, NULL);
	receiver_join(&controller->receiver);
}
