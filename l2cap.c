#include <sys/uio.h>
#include <stdlib.h>

#include "conn.h"
#include "list.h"
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

LIST_HEAD(l2c_list);

typedef struct
{
	uint16_t did;
	uint16_t sid;
	uint16_t result;
	uint16_t status;
} __packed sig_conn_rsp;

typedef struct 
{
	uint16_t psm;
	uint16_t sid;
} __packed sig_conn_req;

typedef struct
{
	uint16_t sid;
	uint16_t continu;
	uint16_t result;
} __packed sig_conf_rsp;

typedef struct
{
	uint16_t did;
	uint16_t continu;
} __packed sig_conf_req;

typedef struct
{
	uint8_t code;
	uint8_t ident;
	uint16_t len;
} __packed l2cap_cmd_hdr ;

typedef struct
{
	uint16_t dlen;
	uint16_t cid;
} __packed l2cap_hdr;

struct l2cap
{
	uint16_t did;
	uint16_t sid;
	uint16_t psm;
	struct conn *conn;
	struct l2c_conn *l2c;
	struct list_head list;
};

static struct l2cap *l2cap_new(struct conn *conn, uint16_t psm, uint16_t did);
void l2cap_sig_write(struct conn *conn, uint8_t code, uint8_t ident, void *buf, uint16_t len);

struct conn *l2cap_get_conn(struct l2cap *l)
{
	return l->conn;
}

struct l2cap *l2cap_connect_req(struct conn *conn, struct l2c_conn *l2c)
{
	struct l2cap *l = l2cap_new(conn, l2c->psm, 0);
	l->l2c = l2c;
	l2c->l2c = l;
	sig_conn_req req = { l2c->psm, l->sid}; 
	l2cap_sig_write(conn, 0x02, 0, (void*)&req, sizeof(req));
	return l;
}

static struct l2cap *l2cap_new(struct conn *conn, uint16_t psm, uint16_t did)
{
	static uint64_t __cid = -1LL; 
	struct l2cap *l = calloc(sizeof(*l), 1);

	l->did = did; /* remote channel id*/
	l->conn = conn;
	l->psm = psm;

	l->sid = ffs(__cid) + 0x3F;
	__cid &= ~(1L << (l->sid - 0x40));
	list_add(&l->list, &l2c_list);
	return l;
}

static struct l2cap *l2cap_lookup_by_did(uint16_t did)
{
	struct l2cap *l;
	list_for_each_entry(l, &l2c_list, list) {
		if (l->did == did)
			return l;
	}

	return NULL;
}

static struct l2cap *l2cap_lookup_by_sid(uint16_t sid)
{
	struct l2cap *l;
	list_for_each_entry(l, &l2c_list, list) {
		if (l->sid == sid)
			return l;
	}

	return NULL;
}

void l2cap_write(struct l2cap *l, void *buf, uint16_t bsize)
{
	l2cap_hdr hdr = {bsize, l->did};
	struct hci_acl_hdr acl = { 0x2000 | l->conn->handle, sizeof(hdr) + bsize};
	struct iovec iov[] = {
		{(uint8_t[]){HCI_ACLDATA_PKT}, 1},
		{&acl, sizeof(acl)},
		{&hdr, sizeof(hdr)},
		{buf, bsize}
	};
	conn_acl_put(l->conn, iov, ARRAY_SIZE(iov));
}

void l2cap_sig_write(struct conn *conn, uint8_t code, uint8_t ident, void *buf, uint16_t len)
{
	l2cap_cmd_hdr cmd = {code, ident, len};
	l2cap_hdr l2c = {sizeof(cmd) + len, 1};
	struct hci_acl_hdr acl = {0x2000 | conn->handle, sizeof(cmd) + sizeof(l2c) + len};

	struct iovec iov[] = {
		{(uint8_t[]){HCI_ACLDATA_PKT}, 1},
		{&acl, sizeof(acl)},
		{&l2c, sizeof(l2c)},
		{&cmd, sizeof(cmd)},
		{buf, len}
	};
	conn_acl_put(conn, iov, ARRAY_SIZE(iov));
}

void l2cap_sig_conf_req(struct l2cap *l2c)
{
	struct {
		sig_conf_req req;
//		uint8_t opt[4];
	} __packed req = {
		{ l2c->did, 0x0000},
//		{ 0x01, 0x02, 0xa0, 0x02}
	};
	l2cap_sig_write(l2c->conn, 0x04, 0x02, &req, sizeof(req));
}

void l2cap_sig_conf_rsp(struct l2cap *l2c, uint8_t ident, void *option, uint16_t optsize)
{
	struct {
		sig_conf_rsp rsp;
		uint8_t opt[125];
	} __packed r = {
		{.sid = l2c->did, .continu = 0, .result = 0},
		{0x01, 0x02, 0xa0, 0x02},
	};

	if (optsize) {
		memcpy(r.opt, option, optsize);
	} else {
		optsize = 0;
	}

	l2cap_sig_write(l2c->conn, 0x05, ident, &r, sizeof(r.rsp) + optsize);
}

static void handle_l2cap_signal(struct conn *conn, l2cap_hdr *hdr)
{
	struct l2cap *l;
	l2cap_cmd_hdr *cmd = (void*)(hdr + 1);

	switch (cmd->code) {
	case 0x02: {/* connect requeset */
		sig_conn_rsp rsp;
		sig_conn_req *req = (void*)(cmd + 1);

		l = l2cap_new(conn, req->psm, req->sid);

		if (req->psm == 0x11)
			l->l2c = get_hid_ctrl();

		if (req->psm == 0x13)
			l->l2c = get_hid_intr();

		l->l2c->l2c = l;

		rsp.did = l->sid;
		rsp.sid = req->sid;
		rsp.result = 0;
		rsp.status = 0;

		l2cap_sig_write(conn, 0x03, cmd->ident, &rsp, sizeof(rsp));
		l2cap_sig_conf_req(l);
	} break;

	case 0x03: { /* connect respone */
		sig_conn_rsp *rsp = (void*)(cmd + 1);
		sig_conf_req req;
		l = l2cap_lookup_by_sid(rsp->sid);

		l->did = rsp->did;

		l2cap_sig_conf_req(l);
	} break;

	case 0x04: {	/* config request */
		sig_conf_req *req = (void*)(cmd + 1);
		l = l2cap_lookup_by_sid(req->did);
		l2cap_sig_conf_rsp(l, cmd->ident, (void*)(req + 1), cmd->len - sizeof(*req));
	} break;

	case 0x05: { /* config respone */
		sig_conf_rsp *rsp = (void*)(cmd + 1);
		l = l2cap_lookup_by_sid(rsp->sid);
		l->l2c->connect_cfm(l->l2c, 0);
		//hci_send_cmd(l->conn->dd, OGF_LINK_CTL, OCF_AUTH_REQUESTED,
		//	sizeof(auth_requested_cp), &(auth_requested_cp) {l->conn->handle});
	} break;

	case 0x06: /* disconnect request */
	break;

	case 0x07: /* disconnect respone */
	break;

	}
}

bool is_hid_interrupt(void *buf, uint16_t size)
{
	l2cap_hdr *l2c = buf + 5;
	if (l2c->cid == 0x00001) {
		l2cap_cmd_hdr *cmd = buf + 5 + sizeof(*l2c);
		if (cmd->code == 0x02) {
			sig_conn_req *req = buf + 5 + sizeof(*l2c) + sizeof(*cmd);
			return req->psm == 0x13;
		}
	}

	return false;
}

void l2cap_packet(struct conn *conn, void *buf)
{
	l2cap_hdr *l2c = buf;

	switch (l2c->cid) {
	case 0x0001:
		handle_l2cap_signal(conn, l2c);
	break;

	default: {
		struct l2cap *l = l2cap_lookup_by_sid(l2c->cid);
		l->l2c->data(l->l2c, buf + sizeof(*l2c), l2c->dlen);
	} break;
	}
}
