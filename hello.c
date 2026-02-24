#include <compiler.h>
#include <kpmodule.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/string.h>

KPM_NAME("Zenfone-PID-Finder");
KPM_VERSION("SAFE");
KPM_AUTHOR("ZenfoneDev");
KPM_LICENSE("GPL v2");

#define COMM_OFFSET 0x5c0   // very common for 4.9 sdm845

static int find_pid_by_name(const char *target)
{
    int i;

    for (i = 1; i < 32768; i++) {

        struct pid *pid_struct;
        struct task_struct *task;

        pid_struct = find_get_pid(i);
        if (!pid_struct)
            continue;

        task = get_pid_task(pid_struct, PIDTYPE_PID);
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
    find_pid_by_name("zygote");
    return 0;
}

static long pidfinder_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
