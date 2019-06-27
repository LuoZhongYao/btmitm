#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <errno.h>
#include "conn.h"
#include "task_sched.h"
#include <bluetooth/hci_lib.h>

struct acl
{
	uint16_t size;
	struct list_head list;
	uint8_t buf[0];
};

static void conn_destroy(struct task *task)
{
}

static struct conn conns[] = { {0}, {0} };

struct conn* conn_get_adapter(void)
{
	return conns;
}

struct conn* conn_get_control(void)
{
	return conns + 1;
}

static void hci_init(struct conn *conn, bool dongle)
{
	int fd = conn->dd;
	socklen_t olen;
	struct hci_filter nf, of;
	unsigned char buf[256];
	read_buffer_size_rp *rp;

	write_ext_inquiry_response_cp eir = {
		0, 
		{
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
		}
	};

#define _(fd, ogf, ocf, ...) do {\
	do { \
		hci_send_cmd(fd, ogf, ocf, sizeof(*(__VA_ARGS__)), __VA_ARGS__); \
		if(0 > read_hci_event(fd, buf, sizeof(buf), 500)) { \
			printf("Failed to read response %s, %s:%d\n", strerror(errno), __func__, __LINE__); \
			return; \
		} \
	} while(buf[0] != 0x04 || (cmd_opcode_pack(ogf, ocf) != bt_get_le16(buf + 4)));\
} while (0)
#define NOP (struct {uint8_t _[0];}*)NULL
#define BYTE(n, ...)	(uint8_t [n]){__VA_ARGS__}


	_(fd, OGF_HOST_CTL, OCF_RESET, NOP);

	_(fd, OGF_INFO_PARAM, OCF_READ_BUFFER_SIZE, NOP);
	rp = (void*)buf + 1 + sizeof(hci_event_hdr) + sizeof(evt_cmd_complete);
	conn->acl_mtu = rp->acl_mtu;
	conn->acl_cnt = rp->acl_max_pkt;

	_(fd, OGF_HOST_CTL, OCF_HOST_BUFFER_SIZE, &(host_buffer_size_cp) {1024, 64, 10, 8});
	_(fd, OGF_INFO_PARAM, OCF_READ_LOCAL_VERSION, NOP);
	_(fd, OGF_INFO_PARAM, OCF_READ_BD_ADDR, NOP);
	_(fd, OGF_INFO_PARAM, OCF_READ_LOCAL_FEATURES, NOP);
	_(fd, OGF_INFO_PARAM, OCF_READ_LOCAL_EXT_FEATURES, BYTE(1, 0));
	_(fd, OGF_HOST_CTL, OCF_WRITE_PAGE_TIMEOUT, &(write_page_timeout_cp){0x2000});

	_(fd, OGF_HOST_CTL, OCF_WRITE_SIMPLE_PAIRING_MODE, &(write_simple_pairing_mode_cp) {1});
	_(fd, OGF_HOST_CTL, OCF_SET_EVENT_MASK, &(set_event_mask_cp){0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0x3d});

	_(fd, OGF_HOST_CTL, OCF_WRITE_CLASS_OF_DEV, &(write_class_of_dev_cp){0x08, 0x25, 0x00});

	if (dongle) {
#define  __(s) s, sizeof(s)
		memcpy(eir.data + 8, __("Dongle controller"));
#undef __
		eir.data[9] = 'D';
		_(fd, OGF_HOST_CTL, OCF_CHANGE_LOCAL_NAME, &(change_local_name_cp){"Dongle controller"});
	} else {
		_(fd, OGF_HOST_CTL, OCF_CHANGE_LOCAL_NAME, &(change_local_name_cp){"Wireless controller"});
	}

	_(fd, OGF_HOST_CTL, OCF_WRITE_EXT_INQUIRY_RESPONSE, &eir);
	_(fd, OGF_HOST_CTL, OCF_WRITE_INQUIRY_MODE, &(write_inquiry_mode_cp){2});
	_(fd, OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE, (uint8_t [1]){3});
	_(fd, OGF_HOST_CTL, OCF_WRITE_PAGE_ACTIVITY, &(write_page_activity_cp) {0x200, 0x100});
	_(fd, OGF_HOST_CTL, OCF_WRITE_PAGE_SCAN_TYPE, &(uint8_t [1]){PAGE_SCAN_TYPE_STANDARD});
	_(fd, OGF_LINK_POLICY, OCF_WRITE_DEFAULT_LINK_POLICY, &(uint16_t[1]) {0x7});
	_(fd, OGF_HOST_CTL, OCF_DELETE_STORED_LINK_KEY, &(delete_stored_link_key_cp) {{0}, 1});
	_(fd, OGF_HOST_CTL, OCF_WRITE_AUTH_ENABLE, &(uint8_t[1]){AUTH_ENABLED});
	/*_(fd, OGF_HOST_CTL, 0x7A, &(uint8_t[1]){AUTH_ENABLED}); */

#undef _

	if (getsockopt(fd, SOL_HCI, HCI_FILTER, &of, &olen) < 0)
		return;

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT,  &nf);
	hci_filter_all_events(&nf);
	if (setsockopt(fd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
		return;
}

struct conn *conn_lookup_by_bdaddr(bdaddr_t *ba)
{
	if (!bacmp(ba, &conns[0].bdaddr))
		return conns + 0;

	if (!bacmp(ba, &conns[1].bdaddr))
		return conns + 1;

	return NULL;
}

struct conn *conn_lookup_by_handle(uint16_t handle)
{
	if (handle == conns[0].handle)
		return conns + 0;

	if (handle == conns[1].handle)
		return conns + 1;
	return NULL;
}

struct conn *conn_lookup_pair(struct conn *conn)
{
	return conn == conns ? conns + 1 : conns;
}

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
	addr.hci_channel = HCI_CHANNEL_USER;

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

void conn_connect_device(struct conn *conn)
{
	create_conn_cp cp = {
		.bdaddr = conn->bdaddr,
		.pkt_type = 0xcc18,//ACL_PTYPE_MASK,
		.pscan_rep_mode = 0x01,
		.pscan_mode = 0,
		.clock_offset = 0x0,
		.role_switch = 0,
	};
	hci_send_cmd(conn->dd, OGF_LINK_CTL, OCF_CREATE_CONN, sizeof(cp), &cp);
}

static PT_THREAD(conn_tx_work(struct task *task))
{
	uint16_t *handle;
	struct conn *conn = container_of(task, struct conn, task);

	PT_BEGIN(&task->pt);

	PT_WAIT_UNTIL(&task->pt, conn->state == conn_state_connected);

	printf("%s conn connected\n", batostr(&conn->bdaddr));
	while (1) {
		PT_WAIT_UNTIL(&task->pt, !list_empty(&conn->wlist));

		list_for_each_entry_safe(conn->wpos, conn->wnext, &conn->wlist, list) {

			//if (conn->acl_credit <= 0)
			//	printf("%s conn->acl_credit = %d\n", batostr(&conn->bdaddr), conn->acl_credit);

			PT_WAIT_UNTIL(&task->pt, conn->acl_cnt > 0);

			handle = ((void*)conn->wpos->buf) + 1;
			*handle &= 0xf000;
			*handle |= conn->handle;

			write(conn->dd, conn->wpos->buf, conn->wpos->size);

			conn->acl_cnt--;
			list_del(&conn->wpos->list);
			free(conn->wpos);
			//PT_YIELD(&task->pt);
		}
	}

	PT_END(&task->pt);
}

int read_timeout(int fd, unsigned char *buf, int size, long ms)
{
    int rv;
    fd_set set;
    struct timeval tv;

    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;

    do {
        FD_ZERO(&set);
        FD_SET(fd, &set);

        rv = select(fd + 1, &set, NULL, NULL, &tv);
    } while(rv <= 0 && errno == EINTR);
    return rv <= 0 ? -1 : read(fd, buf, size);
}

int read_hci_event(int fd, unsigned char* buf, int size, long ms)
{
	int remain, r;
	int count = 0;

	if (size <= 0)
		return -1;

	return read_timeout(fd, buf, size, ms);
}

void conn_acl_put(struct conn *conn, struct iovec iovec[], uint16_t number)
{
	int i = 0;
	size_t max = 0;
	void *p;
	struct acl *acl;
	for (i = 0;i < number;i++)
		max += iovec[i].iov_len;

	acl = malloc(sizeof(*acl) + max);

	acl->size = max;
	p =  acl->buf;
	for (i = 0;i < number;i++) {
		memcpy(p, iovec[i].iov_base, iovec[i].iov_len);
		p += iovec[i].iov_len;
	}
	list_add_tail(&acl->list, &conn->wlist);
}

static void hci_conn_request_evt(int dd, evt_conn_request *evt)
{
	uint16_t ocf;
	size_t cpsize;
	struct conn *conn;
	struct conn *other;
	bdaddr_t *ba, *bs = &evt->bdaddr;

	union {
		reject_conn_req_cp reject;
		accept_conn_req_cp accpet;
	} cmd;

	printf("%02x:%02x:%02x:%02x:%02x:%02x, link_type %d\n", 
		evt->bdaddr.b[5],
		evt->bdaddr.b[4],
		evt->bdaddr.b[3],
		evt->bdaddr.b[2],
		evt->bdaddr.b[1],
		evt->bdaddr.b[0],
		evt->link_type);

	conn = conn_lookup_by_bdaddr(&evt->bdaddr);

	if (conn == NULL) {
		ba = &cmd.reject.bdaddr;
		ocf = OCF_REJECT_CONN_REQ;
		cpsize = sizeof(reject_conn_req_cp);
	} else {
		other = conn_lookup_pair(conn);
		conn->state = conn_state_incomming;
		ocf = OCF_ACCEPT_CONN_REQ;
		cpsize = sizeof(accept_conn_req_cp);
		ba = &cmd.accpet.bdaddr;
	}

	bacpy(ba, bs);
	hci_send_cmd(dd, OGF_LINK_CTL, ocf, cpsize, &cmd);
}

static void hci_conn_complete_evt(int dd, evt_conn_complete *evt)
{
	struct conn *conn, *other;
	conn = conn_lookup_by_bdaddr(&evt->bdaddr);
	if (conn) {

		other = conn_lookup_pair(conn);

		if (evt->status != 0) {
			conn_connect_device(conn);
			return ;
		}

		conn->handle = evt->handle;
		if (conn->state == conn_state_outgoing) {
			hid_connect_req(conn);
		} else if (conn->state == conn_state_incomming) {
			if (other->state == conn_state_idle)
				conn_connect_device(other);
			hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_LINK_SUPERVISION_TIMEOUT,
				sizeof(write_link_supervision_timeout_cp), &(write_link_supervision_timeout_cp) {evt->handle, 0xFFFF});
		}

		conn->state = conn_state_authent;

		hci_send_cmd(dd, OGF_LINK_CTL, OCF_READ_REMOTE_FEATURES,
			sizeof(read_remote_features_cp), &(read_remote_features_cp){evt->handle});

#if 0
		if (other->state == conn_state_wait_other_connect) {
			accept_conn_req_cp cp = { other->bdaddr, 0};
			hci_send_cmd(dd, OGF_LINK_CTL, OCF_ACCEPT_CONN_REQ, sizeof(cp), &cp);
		} else if (other->state == conn_state_idle) {
			connect_device(dd, &other->bdaddr);
		}
		printf("conn complete: handle = %d, other->state = %d\n", evt->handle, other->state);
#endif
	}
}

static void hci_disconn_complete_evt(int dd, evt_disconn_complete *hdr)
{
	struct conn *conn;
	conn = conn_lookup_by_handle(hdr->handle);

	printf("disconn complete: %d\n", hdr->handle);
	if (conn) {
		conn->state = conn_state_idle;
	}
}

static void hci_link_key_req_evt(int dd, evt_link_key_req *hdr)
{
	struct conn *conn;
	link_key_reply_cp cp;

	conn = conn_lookup_by_bdaddr(&hdr->bdaddr);

	if (conn) {

		if (0 && link_Key_match(&hdr->bdaddr, &cp))
			hci_send_cmd(dd, OGF_LINK_CTL, OCF_LINK_KEY_REPLY, sizeof(cp), &cp);
		else
			hci_send_cmd(dd, OGF_LINK_CTL, OCF_LINK_KEY_NEG_REPLY, 6,&hdr->bdaddr);
	}
}

static void hci_read_remote_features_complete_evt(int dd, evt_read_remote_features_complete *evt)
{
	hci_send_cmd(dd, OGF_LINK_CTL, OCF_AUTH_REQUESTED,
		sizeof(auth_requested_cp), &(auth_requested_cp){evt->handle});
}

static void hci_auth_complete_evt(int dd, evt_auth_complete *evt)
{
	struct conn *conn = conn_lookup_by_handle(evt->handle & 0xFFF);

	if (evt->status == 0x06) {
		link_key_del(&conn->bdaddr);
	}
	hci_send_cmd(dd, OGF_LINK_CTL, OCF_SET_CONN_ENCRYPT,
		sizeof(set_conn_encrypt_cp), &(set_conn_encrypt_cp) {evt->handle, 0x01});
}

static void hci_io_capability_request_evt(int dd, evt_io_capability_request *evt)
{
	struct conn *conn;
	conn = conn_lookup_by_bdaddr(&evt->bdaddr);

	if (conn) {
		io_capability_reply_cp cp = {
			.bdaddr = evt->bdaddr,
			.capability = 0x3,
			.oob_data = 0,
			.authentication = 0x4,
		};
		hci_send_cmd(dd, OGF_LINK_CTL, OCF_IO_CAPABILITY_REPLY, sizeof(cp), &cp);
	} else {
		hci_send_cmd(dd, OGF_LINK_CTL, OCF_IO_CAPABILITY_NEG_REPLY, 6, &evt->bdaddr);
	}
}

static void hci_user_confirm_request_evt(int dd, evt_user_confirm_request *evt)
{
	struct conn *conn;
	conn = conn_lookup_by_bdaddr(&evt->bdaddr);

	if (conn) {
		user_confirm_reply_cp cp = {evt->bdaddr};
		hci_send_cmd(dd, OGF_LINK_CTL, OCF_USER_CONFIRM_REPLY, sizeof(cp), &cp);
	} else {
		hci_send_cmd(dd, OGF_LINK_CTL, OCF_USER_CONFIRM_NEG_REPLY, 6, &evt->bdaddr);
	}
}

static void hci_num_comp_pkts_evt(struct conn *conn, evt_num_comp_pkts *evt)
{
	int i = 0;
	struct {uint16_t handle; uint16_t num;} __packed *n = (void*)(evt + 1);
	for (;i < evt->num_hndl;i++, n++) {
		//printf("%s conn->acl_credit = %d, num = %d\n", batostr(&conn->bdaddr), conn->acl_credit, n->num);
		conn->acl_cnt += n->num;
	}
}

static void hci_link_key_notify_evt(int dd, evt_link_key_notify *evt)
{
	link_key_store(evt);
}

static void hci_simple_pairing_complete_evt(int dd, evt_simple_pairing_complete *evt)
{
	struct conn *conn = conn_lookup_by_bdaddr(&evt->bdaddr);

	if (conn) {
		conn->state = conn_state_connected;
	}
}

static void hci_encrypt_change_evt(int dd, evt_encrypt_change *evt)
{
	struct conn *conn = conn_lookup_by_handle(evt->handle);
	conn->state = conn_state_connected;
	//hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_ENCRYPT_MODE, 1, &evt->encrypt);
}

static void hci_cmd_complete_evt(int dd, evt_cmd_complete *evt)
{
}

static void hci_event_packet(struct conn *conn, struct hci_event_hdr *hdr)
{
	int dd = conn->dd;
	switch (hdr->evt) {
	default:
		printf("unhandle evt: %x, %d\n", hdr->evt, hdr->plen);
	break;

	case EVT_CMD_COMPLETE:
		hci_cmd_complete_evt(dd, (evt_cmd_complete*)(hdr + 1));
	break;

	case EVT_CMD_STATUS:
	break;

	case EVT_CONN_REQUEST:
		hci_conn_request_evt(dd, (evt_conn_request*)(hdr + 1));
	break;

	case EVT_DISCONN_COMPLETE:
		hci_disconn_complete_evt(dd, (evt_disconn_complete*)(hdr + 1));
	break;

	case EVT_CONN_COMPLETE:
		hci_conn_complete_evt(dd, (evt_conn_complete*)(hdr + 1));
	break;

	case EVT_LINK_KEY_REQ:
		hci_link_key_req_evt(dd, (evt_link_key_req*)(hdr + 1));
	break;

	case EVT_READ_REMOTE_FEATURES_COMPLETE:
		hci_read_remote_features_complete_evt(dd, (evt_read_remote_features_complete*)(hdr + 1));
	break;

	case EVT_AUTH_COMPLETE:
		hci_auth_complete_evt(dd, (evt_auth_complete*)(hdr + 1));
	break;

	case EVT_IO_CAPABILITY_REQUEST:
		hci_io_capability_request_evt(dd, (evt_io_capability_request*)(hdr + 1));
	break;

	case EVT_USER_CONFIRM_REQUEST:
		hci_user_confirm_request_evt(dd, (evt_user_confirm_request*)(hdr + 1));
	break;

	case EVT_NUM_COMP_PKTS:
		hci_num_comp_pkts_evt(conn, (evt_num_comp_pkts*)(hdr + 1));
	break;

	case EVT_LINK_KEY_NOTIFY:
		hci_link_key_notify_evt(dd, (evt_link_key_notify*)(hdr + 1));
	break;

	case EVT_SIMPLE_PAIRING_COMPLETE:
		hci_simple_pairing_complete_evt(dd, (evt_simple_pairing_complete*)(hdr + 1));
	break;

	case EVT_ENCRYPT_CHANGE:
		hci_encrypt_change_evt(dd, (evt_encrypt_change*)(hdr + 1));
	break;

	}
}

#define MIN(a, b) a < b ? a : b
static void acl_put(struct conn *conn, struct hci_acl_hdr *hdr)
{
	struct conn *other;
	uint16_t sent = 0;
	uint16_t len = hdr->dlen;
	void *p = (void*)(hdr + 1);
	struct {
		uint8_t packet;
		struct hci_acl_hdr hdr;
	} __packed nhdr;

	other = conn_lookup_pair(conn);

	nhdr.packet = HCI_ACLDATA_PKT;
	nhdr.hdr.handle = 0x2000;

	while (len) {
		uint16_t count = MIN(len, other->acl_mtu);
		nhdr.hdr.dlen = count;

		conn_acl_put(other, (struct iovec[]){
			{.iov_base = &nhdr, .iov_len = sizeof(nhdr)},
			{.iov_base = p + sent, .iov_len = count},
		}, 2);

		nhdr.hdr.handle = 0x1000;
		len -= count;
		sent += count;
	}
}
#undef MIN

static void hci_acldata_packet(struct conn *conn, void *buf, uint16_t size)
{
	struct hci_acl_hdr *hdr = buf + 1;
	if (!conn || conn->state < conn_state_authent) {
		printf("can't handle acldata: handle = %d, conn->state = %x\n", hdr->handle & 0xFFF, conn ? conn->state : 0xFFFF);
		return ;
	}

	if (hdr->dlen > 300 || ((hdr->handle & 0xf000) == 0x1000)) {
		uint16_t len = hdr->dlen;
		if ((hdr->handle & 0xf000) == 0x2000)
			len -= 4;
		rate_display(&conn->dis, len, batostr(&conn->bdaddr), "Byte");
	}


#if 1
	acl_put(conn, hdr);
#else

	l2cap_packet(conn, (void*)(hdr + 1));
#endif
}

static void hci_scodata_packet(int dd, struct hci_sco_hdr *hdr)
{
}


void conn_hci_handler(struct conn *conn)
{
	int rs;
	uint8_t buf[1024];
	rs = read(conn->dd, buf, sizeof(buf));
	switch (buf[0]) {
	case HCI_EVENT_PKT:
		if(rs < sizeof(struct hci_event_hdr))
			break;
		hci_event_packet(conn, (struct hci_event_hdr *)(buf + 1));
	break;
	case HCI_ACLDATA_PKT:
		if(rs < sizeof(struct hci_acl_hdr))
			break;
		hci_acldata_packet(conn, buf, rs);
	break;
	case HCI_SCODATA_PKT:
		if(rs < sizeof(struct hci_sco_hdr))
			break;
		hci_scodata_packet(conn->dd, (struct hci_sco_hdr*)(buf + 1));
	break;

	default:
	break;
	}
}

void conn_init(struct conn *conn, bool dongle)
{
	conn->dd = open_channel(conn->adapter);

	if (conn->dd < 0)
		exit(1);

	memset(&conn->dis, 0, sizeof(conn->dis));
	hci_init(conn, dongle);

	printf("%s acl_max_pkt = %d, acl_mtu = %d\n", batostr(&conn->bdaddr), conn->acl_cnt, conn->acl_mtu);

	conn->task.destroy = conn_destroy;
	conn->task.handler = conn_tx_work;
	INIT_LIST_HEAD(&conn->wlist);
	task_add(&conn->task);
}
