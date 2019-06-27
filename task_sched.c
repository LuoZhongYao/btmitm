#include "defs.h"
#include "task_sched.h"

static LIST_HEAD(task_list);

void task_sched(void)
{
	struct task *task, *next;
	list_for_each_entry_safe(task, next, &task_list, list) {
		if (!PT_SCHEDULE(task->handler(task))) {
			list_del(&task->list);
			task->destroy(task);
		}
	}
}

void task_add(struct task *task)
{
	PT_INIT(&task->pt);
	list_add(&task->list, &task_list);
}

void task_del(struct task *task)
{
	list_del(&task->list);
	task->destroy(task);
}
