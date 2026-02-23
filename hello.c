#include <compiler.h>
#include <kpmodule.h>
#include <linux/kallsyms.h>
#include <linux/string.h>

KPM_NAME("Zenfone-PID-Finder");
KPM_VERSION("5.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_LICENSE("GPL v2");

/*
   These offsets MUST match your kernel.
   For 4.9.186 ARM64 (Qualcomm CAF typical layout)
   These are VERY COMMON values:
*/

#define TASKS_OFFSET  0x2e8
#define PID_OFFSET    0x358
#define COMM_OFFSET   0x5c0

static void *init_task_ptr;

static int find_pid_by_name(const char *name)
{
    void *task;
    void *next;

    task = init_task_ptr;

    do {

        char *comm = (char *)task + COMM_OFFSET;
        int pid = *(int *)((char *)task + PID_OFFSET);

        if (strcmp(comm, name) == 0)
            return pid;

        /* manually follow list */
        next = *(void **)((char *)task + TASKS_OFFSET);
        task = (char *)next - TASKS_OFFSET;

    } while (task != init_task_ptr);

    return -1;
}

static long pidfinder_init(const char *args,
                           const char *event,
                           void *__user reserved)
{
    unsigned long addr;

    addr = kallsyms_lookup_name("init_task");
    if (!addr)
        return -1;

    init_task_ptr = (void *)addr;

    find_pid_by_name("zygote");

    return 0;
}

static long pidfinder_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
