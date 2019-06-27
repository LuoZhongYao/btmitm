/*************************************************
 * Anthor  : LuoZhongYao@gmail.com
 * Modified: 2019/06/10
 ************************************************/
#ifndef __DEFS_H__
#define __DEFS_H__
#include <stddef.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#ifndef container_of
# define container_of(ptr, type, member) ({ \
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define __packed __attribute__((packed))


#endif /* __DEFS_H__*/

