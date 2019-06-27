#include <getopt.h>
#include <unistd.h>
#include <pthread.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <sys/uio.h>
#include "mgmt.h"

static int adapter_index = 0;
static struct mgmt_cp_load_link_keys link_keys[8];

static void mgmt_send(int sk,
	uint16_t opcode, uint16_t index,
	void *params, uint16_t plen)
{
	struct iovec iv[2];
	struct mgmt_hdr hdr = {
		.opcode = htobs(opcode),
		.index = htobs(index),
		.len = htobs(plen),
	};

	iv[0].iov_base = &hdr;
	iv[0].iov_len = MGMT_HDR_SIZE;
	iv[1].iov_base = params;
	iv[1].iov_len = plen;
	writev(sk, iv, 2);
}

static void mgmt_load_link_keys(int sk)
{
	struct mgmt_cp_load_link_keys *cp = link_keys;
	uint16_t key_count = btohs(cp->key_count);
	mgmt_send(sk, MGMT_OP_LOAD_LINK_KEYS, adapter_index,
		cp, sizeof(*cp) + sizeof(struct mgmt_link_key_info) * key_count);
}

static void mgmt_clear_uuids(int sk)
{
	struct mgmt_cp_remove_uuid cp;

	memset(&cp, 0, sizeof(cp));

	mgmt_send(sk, MGMT_OP_REMOVE_UUID, adapter_index, &cp, sizeof(cp));
}

static void mgmt_clear_auto_connect_list(int sk)
{
	struct mgmt_cp_remove_device cp;

	memset(&cp, 0, sizeof(cp));

	mgmt_send(sk, MGMT_OP_REMOVE_DEVICE, adapter_index, &cp, sizeof(cp));
}

static void mgmt_set_io_capability(int sk)
{
	struct mgmt_cp_set_io_capability cp;

	memset(&cp, 0, sizeof(cp));
	cp.io_capability = 0x03;

	mgmt_send(sk, MGMT_OP_SET_IO_CAPABILITY, adapter_index, &cp, sizeof(cp));
}



static int mksock(bdaddr_t *ba, uint16_t psm)
{
	int fd;
	int lm = L2CAP_LM_AUTH | L2CAP_LM_ENCRYPT;// | L2CAP_LM_SECURE;
	socklen_t len;
	struct bt_security sec;
	struct sockaddr_l2 addr;
	struct l2cap_options l2o;

	memset(&l2o, 0, sizeof(l2o));
	memset(&addr, 0, sizeof(addr));
	memset(&sec, 0, sizeof(sec));
	len = sizeof(l2o);

	addr.l2_family = AF_BLUETOOTH;
	addr.l2_psm = htobs(psm);
	bacpy(&addr.l2_bdaddr, ba);
	addr.l2_bdaddr_type = BDADDR_BREDR;
	fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);

	bind(fd, (struct sockaddr*)&addr, sizeof(addr));

	getsockopt(fd, SOL_L2CAP, L2CAP_OPTIONS, &l2o, &len);
	l2o.imtu = 64;
	l2o.omtu = 64;
	l2o.mode = L2CAP_MODE_BASIC;
	setsockopt(fd, SOL_L2CAP, L2CAP_OPTIONS, &l2o, sizeof(l2o));

	sec.level = BT_SECURITY_MEDIUM;
	setsockopt(fd, SOL_BLUETOOTH, BT_SECURITY, &sec, sizeof(sec));
	setsockopt(fd, SOL_L2CAP, L2CAP_LM, &lm, sizeof(lm));

	return fd;
}

static int l2cp_connect(bdaddr_t *ba, uint16_t psm)
{
	int fd, sock;
	struct sockaddr_l2 addr;

	memset(&addr, 0, sizeof(addr));

	addr.l2_family = AF_BLUETOOTH;
	addr.l2_psm = htobs(psm);
	bacpy(&addr.l2_bdaddr, ba);
	addr.l2_bdaddr_type = BDADDR_BREDR;

	sock = mksock(BDADDR_ANY, 0);


	return connect(sock, (struct sockaddr*)&addr, sizeof(addr));
}

static void mgmt_set_mode(int sk, uint16_t opcode, uint8_t mode)
{
	struct mgmt_mode cp;

	memset(&cp, 0, sizeof(cp));
	cp.val = mode;

	mgmt_send(sk, opcode, adapter_index, &cp, sizeof(cp));
}

static void mgmt_set_discoverable(int sk, uint8_t mode,
	uint16_t timeout)
{
	struct mgmt_cp_set_discoverable cp;

	memset(&cp, 0, sizeof(cp));
	cp.val = mode;
	cp.timeout = htobs(timeout);

	mgmt_send(sk, MGMT_OP_SET_DISCOVERABLE, adapter_index, &cp, sizeof(cp));
}

static int mgmt_read_info_complete(int sk, uint8_t status, uint16_t plen, const void *param)
{
	uint32_t missing_settings, supported_settings, current_settings;
	const struct mgmt_rp_read_info *rp = param;

	supported_settings = rp->supported_settings;
	current_settings = rp->current_settings;

	mgmt_clear_uuids(sk);
	mgmt_clear_auto_connect_list(sk);

	mgmt_set_io_capability(sk);
	//mgmt_set_device_id(sk);
	missing_settings = current_settings ^ supported_settings;

	//if(missing_settings & MGMT_SETTING_LE)
	//	mgmt_set_mode(sk, MGMT_OP_SET_LE, 0x01);

	if(missing_settings & MGMT_SETTING_BREDR)
		mgmt_set_mode(sk, MGMT_OP_SET_BREDR, 0x01);

	if(missing_settings & MGMT_SETTING_SECURE_CONN)
		mgmt_set_mode(sk, MGMT_OP_SET_SECURE_CONN, 0x01);

	if (missing_settings & MGMT_SETTING_SSP)
		mgmt_set_mode(sk, MGMT_OP_SET_SSP, 0x01);

	if (missing_settings & MGMT_SETTING_BONDABLE)
		mgmt_set_mode(sk, MGMT_OP_SET_BONDABLE, 0x01);

	if (missing_settings & MGMT_SETTING_CONNECTABLE)
		mgmt_set_mode(sk, MGMT_OP_SET_CONNECTABLE, 0x01);

	if (missing_settings & MGMT_SETTING_DISCOVERABLE)
		mgmt_set_discoverable(sk, 0x01, 0x00);

	if(missing_settings & MGMT_SETTING_POWERED)
		mgmt_set_mode(sk, MGMT_OP_SET_POWERED, 0x01);

	mgmt_load_link_keys(sk);
	return 0;
}

static void mgmt_read_index_list_complete(int sk, uint8_t status, uint16_t length, const void *param)
{
	int num;
	const struct mgmt_rp_read_index_list *rp = param;

	num = btohs(rp->num_controllers);

	mgmt_send(sk, MGMT_OP_READ_INFO, btohs(rp->index[0]), NULL, 0);
}


static void request_complete(int sk, uint8_t status,
	uint16_t opcode, uint16_t index,
	uint16_t length, const void *param)
{
	switch(opcode) {
	case MGMT_OP_READ_VERSION: 
	case MGMT_SETTING_DISCOVERABLE:
	case MGMT_OP_SET_CONNECTABLE:
	case MGMT_OP_LOAD_LINK_KEYS: {
	} break;

	case MGMT_OP_SET_LOCAL_NAME: {
	} break;

	case MGMT_OP_SET_DEV_CLASS: {
	} break;

	case MGMT_OP_READ_INDEX_LIST: {
		mgmt_read_index_list_complete(sk, status, length, param);
	} break;

	case MGMT_OP_READ_INFO: {
		mgmt_read_info_complete(sk, status, length, param);
	} break;

	}
}


static void *mgmt_handler(void *arg)
{
	int sk, rs;
	uint16_t opcode,index;
	struct mgmt_ev_cmd_complete *cc;
	struct mgmt_ev_cmd_status *cs;
	uint8_t buf [1024];
	struct mgmt_hdr *hdr;
	union {
		struct sockaddr common;
		struct sockaddr_hci hci;
	} addr;

	sk = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
	if (sk < 0)
		return NULL;

	memset(&addr, 0, sizeof(addr));
	addr.hci.hci_family = AF_BLUETOOTH;
	addr.hci.hci_dev = HCI_DEV_NONE;
	addr.hci.hci_channel = HCI_CHANNEL_CONTROL;

	bind(sk, &addr.common, sizeof(addr.hci));

	mgmt_send(sk, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, NULL, 0);

	while (1) {
		rs = read(sk, buf, sizeof(buf));
		hdr = (void*)buf;
		switch (btohs(hdr->opcode)) {
		case MGMT_EV_CMD_COMPLETE:
			cc = (void*)buf + MGMT_HDR_SIZE;
			opcode = btohs(cc->opcode);

			request_complete(sk, cc->status, opcode, index, rs - 3, buf + MGMT_HDR_SIZE + 3);
		break;

		case MGMT_EV_CMD_STATUS:
			cs = (void*)buf + MGMT_HDR_SIZE;
			opcode = btohs(cs->opcode);

			request_complete(sk, cs->status, opcode, index, 0, NULL);
		break;


		}

	}

	return NULL;
}

int main(int argc, char **argv)
{
	int c;
	bdaddr_t ba;
	int ctrl, intr;
	pthread_t pid;

	while (-1 != (c = getopt(argc, argv, "b:"))) {
		switch (c) {
		case 'b': str2ba(optarg, &ba); break;
		}
	}

	pthread_create(&pid, NULL, mgmt_handler, NULL);

	while (0 > (ctrl = l2cp_connect(&ba, 0x11)));
	while (0 > (intr = l2cp_connect(&ba, 0x13)));

	while (1);

	return 0;
}
