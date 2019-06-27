/*************************************************
 * Anthor  : LuoZhongYao@gmail.com
 * Modified: 2019/05/31
 ************************************************/
#ifndef __CONN_H__
#define __CONN_H__
#include "sys/uio.h"
#include "task_sched.h"
#include "rate_display.h"
#include <stdint.h>
#include <stdbool.h>
#include <linux/types.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

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

int read_hci_event(int fd, unsigned char* buf, int size, long ms);

typedef enum {
	conn_state_idle,
	conn_state_incomming,
	conn_state_outgoing,
	conn_state_authent,
	conn_state_connected,
} conn_state;

struct acl;
struct conn
{
	int dd, adapter;
	bdaddr_t bdaddr;
	uint16_t handle;
	uint16_t acl_mtu;
	uint16_t acl_cnt;
	conn_state state;
	struct rate_display dis;

	struct task task;

	struct acl *wpos;
	struct acl *wnext;
	struct list_head wlist;
};

struct l2cap;

struct l2c_conn
{
	uint16_t psm;
	struct l2cap *l2c;
	void (*connect_cfm)(struct l2c_conn *conn, int status);
	void (*disconnect_cfm)(struct l2c_conn *conn, int status);
	void (*data)(struct l2c_conn *conn, void *data, uint16_t size);
};

extern volatile uint16_t acl_credit;

struct l2cap *l2cap_connect_req(struct conn *conn, struct l2c_conn *l2c);
struct conn *l2cap_get_conn(struct l2cap *l2cap);
void l2cap_write(struct l2cap *l, void *buf, uint16_t bsize);

void hid_connect_req(struct conn *conn);
void hid_num_comp_pkts_evt(uint8_t num);

struct l2c_conn *get_hid_ctrl(void);
struct l2c_conn *get_hid_intr(void);

int read_timeout(int fd, unsigned char *buf, int size, long ms);
int read_hci_event(int fd, unsigned char* buf, int size, long ms);

void conn_init(struct conn *conn, bool dongle);
struct conn *conn_lookup_by_bdaddr(bdaddr_t *ba);
struct conn *conn_lookup_by_handle(uint16_t handle);
struct conn *conn_lookup_pair(struct conn *conn);
struct conn *conn_get_control(void);
struct conn *conn_get_adapter(void);
void conn_hci_handler(struct conn *conn);
void conn_connect_device(struct conn *conn);
void conn_acl_put(struct conn *conn, struct iovec iovec[], uint16_t number);

void link_key_load(void);
void link_key_del(bdaddr_t *ba);
int link_key_store(evt_link_key_notify *key);
bool link_Key_match(bdaddr_t *ba, link_key_reply_cp *cp);
bool is_hid_interrupt(void *buf, uint16_t size);

#endif /* __CONN_H__*/

