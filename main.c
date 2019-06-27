#include <sys/uio.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "conn.h"
#include "task_sched.h"

static void usage(void)
{
	printf("Usage: btmitm -C {index,bdaddr} -D {index,bdaddr} -c\n");
}

#define CONNECT_SLAVE 0x01

int main(int argc, char **argv)
{
	int rsize, c;
	int flags = 0;
	char bstr[20];

	struct conn *ctrl, *adapter;

	ctrl = conn_get_control();
	adapter = conn_get_adapter();

	while (-1 != (c = getopt(argc, argv, "C:D:c"))) {
		switch (c) {
		case 'C':
			sscanf(optarg, "%d,%s", &ctrl->adapter, bstr);
			if (str2ba(bstr, &ctrl->bdaddr)) {
				usage();
				return EXIT_FAILURE;
			}
			printf("control(%d) address: %s\n", ctrl->adapter, batostr(&ctrl->bdaddr));
		break;

		case 'c':
			flags = CONNECT_SLAVE;
		break;

		case 'D':
			sscanf(optarg, "%d,%s", &adapter->adapter, bstr);
			if (str2ba(bstr, &adapter->bdaddr)) {
				usage();
				return EXIT_FAILURE;
			}
			printf("adapter(%d) address: %s\n", adapter->adapter, batostr(&adapter->bdaddr));
		break;
		default:
			usage();
			return EXIT_FAILURE;
		break;
		}
	}


	conn_init(ctrl, false);
	conn_init(adapter, true);
	link_key_load();

	if (flags & CONNECT_SLAVE)
		conn_connect_device(ctrl);

	while (true) {
		int rv, max;
		fd_set set;
		struct timeval tv;

		tv.tv_sec = 0;
		tv.tv_usec = 1 * 10;

		FD_ZERO(&set);
		FD_SET(ctrl->dd, &set);
		FD_SET(adapter->dd, &set);

		max = (ctrl->dd > adapter->dd ? ctrl->dd : adapter->dd) + 1;

		rv = select(max, &set, NULL, NULL, &tv);

		if (rv > 0) {

			if (FD_ISSET(ctrl->dd, &set)) {
				conn_hci_handler(ctrl);
			}

			if (FD_ISSET(adapter->dd, &set)) {
				conn_hci_handler(adapter);
			}
		}

		task_sched();
	}

	return EXIT_SUCCESS;
}
