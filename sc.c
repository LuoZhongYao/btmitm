#include "defs.h"
#include "conn.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

static evt_link_key_notify link_keys[8];

static int file_store(const char *file)
{
	int fd = open(file, O_CREAT | O_WRONLY, 0666);

	if (fd < 0) {
		perror(file);
		return -1;
	}

	write(fd, link_keys, sizeof(link_keys));
	close(fd);
	return 0;
}

int link_key_store(evt_link_key_notify *key)
{
	int i = 0;
	evt_link_key_notify *pos = link_keys;
	for (i = 0;i < ARRAY_SIZE(link_keys);i++) {
		if (!bacmp(&key->bdaddr, &link_keys[i].bdaddr))
			pos = link_keys + i;
	}

	memcpy(pos, key, sizeof(*key));
	return file_store("/tmp/sc_db");
}

void link_key_del(bdaddr_t *ba)
{
	int i = 0;
	for (i = 0;i < ARRAY_SIZE(link_keys);i++) {
		if (!bacmp(ba, &link_keys[i].bdaddr)) {
			memset(link_keys + i, 0, sizeof(link_keys[0]));
		}
	}
}

void link_key_load(void)
{
	int fd;

	memset(link_keys, 0, sizeof(link_keys));
	fd = open("/tmp/sc_db", O_RDONLY);
	if (fd < 0) {
		perror("/tmp/sc_db");
		return ;
	}

	read(fd, link_keys, sizeof(link_keys));
	close(fd);
}

bool link_Key_match(bdaddr_t *ba, link_key_reply_cp *cp)
{
	int i = 0;
	for (i = 0;i < ARRAY_SIZE(link_keys);i++) {
		if (!bacmp(ba, &link_keys[i].bdaddr)) {
			cp->bdaddr = link_keys[i].bdaddr;
			memcpy(cp->link_key, link_keys[i].link_key, sizeof(cp->link_key));
			return true;
		}
	}
	return false;
}
