/*************************************************
 * Anthor  : LuoZhongYao@gmail.com
 * Modified: 2019/06/10
 ************************************************/
#ifndef __TASK_SCHED_H__
#define __TASK_SCHED_H__

#include "defs.h"
#include "list.h"
#include "pt-1.4/pt.h"

struct task
{
	struct pt pt;
	struct list_head list;
	void (*destroy)(struct task *task);
	PT_THREAD((*handler)(struct task *task));
};

void task_sched(void);
void task_add(struct task *task);
void task_del(struct task *task);

#endif /* __TASK_SCHED_H__*/

