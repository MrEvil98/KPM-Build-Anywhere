#include <compiler.h>
#include <kpmodule.h>
#include <linux/kallsyms.h>
#include <linux/string.h>

KPM_NAME("Zenfone-PID-Finder");
KPM_VERSION("SAFE_FINAL");
KPM_AUTHOR("ZenfoneDev");
KPM_LICENSE("GPL v2");

#define COMM_OFFSET 0x5c0   // temporary, we verify later

struct pid;
struct task_struct;

static struct pid *(*_find_get_pid)(int nr);
static struct task_struct *(*_get_pid_task)(struct pid *, int type);

static int find_pid_by_name(const char *target)
{
    int i;

    for (i = 1; i < 32768; i++) {

        struct pid *pid_struct;
        struct task_struct *task;

        pid_struct = _find_get_pid(i);
        if (!pid_struct)
            continue;

        task = _get_pid_task(pid_struct, 0); // PIDTYPE_PID = 0
        if (!task)
            continue;

        char *comm = (char *)task + COMM_OFFSET;

        if (strcmp(comm, target) == 0)
            return i;
    }

    return -1;
}

static long pidfinder_init(const char *args,
                           const char *event,
                           void *__user reserved)
{
    _find_get_pid = (void *)kallsyms_lookup_name("find_get_pid");
    _get_pid_task = (void *)kallsyms_lookup_name("get_pid_task");

    if (!_find_get_pid || !_get_pid_task)
        return -1;

    find_pid_by_name("zygote");

    return 0;
}

static long pidfinder_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
