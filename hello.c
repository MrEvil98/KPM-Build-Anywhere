#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/list.h>

KPM_NAME("Zenfone-PID-Finder");
KPM_VERSION("4.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_LICENSE("GPL v2");

static int find_pid_by_name(const char *name)
{
    struct task_struct *task = current;
    struct task_struct *start = task;

    do {
        if (strcmp(task->comm, name) == 0)
            return task->pid;

        task = list_next_entry(task, tasks);

    } while (task != start);

    return -1;
}

static long pidfinder_init(const char *args,
                           const char *event,
                           void *__user reserved)
{
    int pid;

    pid = find_pid_by_name("zygote");

    return 0;
}

static long pidfinder_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
