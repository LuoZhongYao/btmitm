#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <linux/types.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define __packed __attribute__((packed))
/* HCI data types */                                                 
#define HCI_COMMAND_PKT     0x01            
#define HCI_ACLDATA_PKT     0x02
#define HCI_SCODATA_PKT     0x03
#define HCI_EVENT_PKT       0x04
#define HCI_DIAG_PKT        0xf0
#define HCI_VENDOR_PKT      0xff

struct hci_command_hdr {
	__le16  opcode;     /* OCF & OGF */         
	__u8    plen;                                     
} __packed;     

struct hci_event_hdr {                      
	__u8    evt;                                      
	__u8    plen;
} __packed;

struct hci_acl_hdr {
	__le16  handle;     /* Handle & Flags(PB, BC) */
	__le16  dlen;  
} __packed;

struct hci_sco_hdr {                                    
	__le16  handle;
	__u8    dlen;
} __packed;

static int open_channel(uint16_t index)
{
	int fd;
	int on = 1;
	struct sockaddr_hci addr;

	printf("Opening user channel for hci%u\n", index);

	fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
	if (fd < 0) {
		perror("Failed to open Bluetooth socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = index;
	addr.hci_channel = HCI_CHANNEL_RAW;//HCI_CHANNEL_USER;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		close(fd);
		perror("setsockopt");
		return -1;
	}

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(fd);
		perror("Failed to bind Bluetooth socket");
		return -1;
	}

	return fd;
}

static void hci_event_packet(struct hci_event_hdr *hdr)
{
	switch (hdr->evt) {
	default:
		printf("unhandle evt: %x, %d\n", hdr->evt, hdr->plen);
	break;
	}
}

static void hci_acldata_packet(struct hci_acl_hdr *hdr)
{
}

static void hci_scodata_packet(struct hci_sco_hdr *hdr)
{
}

static void hci_init(int fd)
{
	static const uint8_t eir[] = {
		0x05,0x03,0x24,0x11,0x00,0x12,0x1f,0x09,
		0x57,0x69,0x72,0x65,0x6c,0x65,0x73,0x73,
		0x20,0x63,0x6f,0x6e,0x74,0x72,0x6f,0x6c,
		0x6c,0x65,0x72,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x09,0x10,
		0x02,0x00,0x2c,0x2e,0x06,0x00,0x00,0x01,
		0x2d,0xe0,0xa1,0x17,0xdd,0x03,0xa8,0x00,
		0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x53,
		0x2d,0xe0,0xa1,0x02,0x00,0x00,0x00,0x1c,
		0x01,0xc0,0xa1,0x04,0xa8,0xa1,0x25,0xff,
		0xff,0xbf,0x1d,0x02,0x00,0x00,0x00,0x1c,
		0x01,0xc0,0xa1,0x01,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	};

	hci_write_class_of_dev(fd, 0x002508, 2000);
	hci_write_local_name(fd, "Wireless controller", 2000);
	hci_write_inquiry_mode(fd, 2, 2000);
	hci_write_ext_inquiry_response(fd, 1, (uint8_t*)eir, 2000);
	hci_send_cmd(fd, OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE, 1, (uint8_t [1]){3});
}

int main(void)
{
	int fd;
	int rsize;
	uint8_t buf[1024];

	fd = open_channel(0);
	if(fd < 0)
		return EXIT_FAILURE;

	hci_init(fd);

	while (true) {
		rsize = read(fd, buf, sizeof(buf));

		if(rsize < 0)
			return EXIT_FAILURE;

		switch (buf[0]) {
		case HCI_EVENT_PKT:
			if(rsize < sizeof(struct hci_event_hdr))
				return EXIT_FAILURE;
			hci_event_packet((struct hci_event_hdr *)(buf + 1));
		break;
		case HCI_ACLDATA_PKT:
			if(rsize < sizeof(struct hci_acl_hdr))
				return EXIT_FAILURE;
			hci_acldata_packet((struct hci_acl_hdr*)(buf + 1));
		break;
		case HCI_SCODATA_PKT:
			if(rsize < sizeof(struct hci_sco_hdr))
				return EXIT_FAILURE;
			hci_scodata_packet((struct hci_sco_hdr*)(buf + 1));
		break;

		default:
		break;
		}
	}

	close(fd);

	return EXIT_SUCCESS;
}
