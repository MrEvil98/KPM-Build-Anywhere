#include <compiler.h>
#include <kpmodule.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/string.h>

KPM_NAME("Zenfone-PID-Finder");
KPM_VERSION("3.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_LICENSE("GPL v2");

static void *init_task_ptr;
static unsigned long tasks_offset;
static unsigned long pid_offset;
static unsigned long comm_offset;

static int detect_offsets(void)
{
    char *base = (char *)init_task_ptr;
    int i;

    // Find PID 0 inside init_task
    for (i = 0; i < 0x800; i += 4) {
        if (*(int *)(base + i) == 0) {
            pid_offset = i;
            break;
        }
    }

    if (!pid_offset)
        return -1;

    // Find "swapper" comm string
    for (i = 0; i < 0x1000; i++) {
        if (strcmp(base + i, "swapper") == 0) {
            comm_offset = i;
            break;
        }
    }

    if (!comm_offset)
        return -1;

    // Find tasks list (look for self-referencing list_head)
    for (i = 0; i < 0x800; i += 8) {
        struct list_head *lh = (struct list_head *)(base + i);
        if (lh->next == lh && lh->prev == lh) {
            tasks_offset = i;
            break;
        }
    }

    if (!tasks_offset)
        return -1;

    return 0;
}

static int find_pid_by_name(const char *name)
{
    struct list_head *head;
    struct list_head *pos;

    head = (struct list_head *)((char *)init_task_ptr + tasks_offset);

    list_for_each(pos, head) {

        void *task = (char *)pos - tasks_offset;
        char *comm = (char *)task + comm_offset;
        int pid = *(int *)((char *)task + pid_offset);

        if (strcmp(comm, name) == 0)
            return pid;
    }

    return -1;
}

static long pidfinder_init(const char *args,
                           const char *event,
                           void *__user reserved)
{
    unsigned long addr;
    int pid;

    addr = kallsyms_lookup_name("init_task");
    if (!addr)
        return -1;

    init_task_ptr = (void *)addr;

    if (detect_offsets())
        return -1;

    pid = find_pid_by_name("zygote");

    printk("PID result = %d\n", pid);

    return 0;
}

static long pidfinder_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
