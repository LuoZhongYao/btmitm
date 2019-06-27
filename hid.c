#include "conn.h"
#include <unistd.h>
#include <stdlib.h>

static void ctrl_connect_cfm(struct l2c_conn *l2c, int status);
static void ctrl_disconnect_cfm(struct l2c_conn *l2c, int status);
static  void ctrl_data(struct l2c_conn *l2c, void *data, uint16_t size);
static void intr_connect_cfm(struct l2c_conn *l2c, int status);
static void intr_disconnect_cfm(struct l2c_conn *l2c, int status);
static  void intr_data(struct l2c_conn *l2c, void *data, uint16_t size);

#define HID_OUTGOING	0x0001
#define HID_INCOMMING	0x0002
#define HID_DIR_MASK	0x00ff
#define HID_STATUS_MASK	0xff00
#define HID_CONNECTED	0x0100

struct
{
	int status;
	int tick;
	struct task task;
	struct l2c_conn control;
	struct l2c_conn interrupt;
} hid = {
	.status = 0,
	.control = {.psm = 0x11, NULL, ctrl_connect_cfm, ctrl_disconnect_cfm, ctrl_data},
	.interrupt = {.psm = 0x13, NULL, intr_connect_cfm, intr_disconnect_cfm, intr_data},
};

static void ctrl_connect_cfm(struct l2c_conn *ctrl, int status)
{
	printf("hid control connected\n");
	if (status == 0 && hid.status == HID_OUTGOING) {
		l2cap_connect_req(l2cap_get_conn(ctrl->l2c), &hid.interrupt);
	}
}

static void ctrl_disconnect_cfm(struct l2c_conn *ctrl, int status)
{
	printf("hid control disconnected\n");
}

static void ctrl_data(struct l2c_conn *ctrl, void *data, uint16_t size)
{
}

static void intr_disconnect_cfm(struct l2c_conn *intr, int status)
{
	printf("hid interrupt disconnected\n");
}

static void intr_destory(struct task *task)
{
}

static PT_THREAD(intr_handler(struct task *task))
{
	PT_BEGIN(&task->pt);

	PT_WAIT_UNTIL(&task->pt, (hid.status & HID_STATUS_MASK));


	while (1) {
		PT_WAIT_UNTIL(&task->pt, ++hid.tick >= 10);
		hid.tick = 0;

		if ((hid.status & HID_DIR_MASK) == HID_OUTGOING) {
			uint8_t data[] = {
				0xa2, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00};

			l2cap_write(hid.interrupt.l2c, data, sizeof(data));
		} else {
			uint8_t data [] = {
				0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x7f, 0x81, 0x7f, 0x7f, 0x0f, 0x00, 0xc0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,
				0x00, 0x00, 0x00, 0x00, 0xd8, 0x70, 0x02, 0x00, 0x07, 0x00, 0xf7, 0xff, 0x4b, 0xfe, 0xfd, 0x1f,
				0x6f, 0x01
			};
			l2cap_write(hid.interrupt.l2c, data, sizeof(data));
		}
	}
	PT_END(&task->pt);
}


static void intr_connect_cfm(struct l2c_conn *intr, int status)
{
	printf("hid interrupt connected\n");
	hid.status |= HID_CONNECTED;

	hid.task.destroy = intr_destory;
	hid.task.handler = intr_handler;
	task_add(&hid.task);
}

static void intr_data(struct l2c_conn *ctrl, void *data, uint16_t size)
{
}

struct l2c_conn *get_hid_ctrl(void)
{
	return &hid.control;
}

struct l2c_conn *get_hid_intr(void)
{
	return &hid.interrupt;
}

void hid_connect_req(struct conn *conn)
{
	hid.status = HID_OUTGOING;
	l2cap_connect_req(conn, &hid.control);
}
