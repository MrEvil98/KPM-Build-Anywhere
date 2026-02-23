#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/list.h>

// Module Info
KPM_NAME("Zenfone-PID-Finder");
KPM_VERSION("1.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Find PID by process name (KP v4 compatible)");
KPM_LICENSE("GPL v2");

static struct task_struct *init_task_ptr;

// Simple PID finder
static int find_pid_by_name(const char *name)
{
    struct task_struct *task;
    struct list_head *pos;

    task = init_task_ptr;

    list_for_each(pos, &task->tasks) {
        struct task_struct *t =
            list_entry(pos, struct task_struct, tasks);

        if (strcmp(t->comm, name) == 0) {
            return t->pid;
        }
    }

    return -1;
}

static long pidfinder_init(const char *args,
                           const char *event,
                           void *__user reserved)
{
    unsigned long addr;
    int pid;

    // Resolve init_task dynamically
    addr = kallsyms_lookup_name("init_task");
    if (!addr)
        return -1;

    init_task_ptr = (struct task_struct *)addr;

    // Change target process name here
    pid = find_pid_by_name("zygote");

    if (pid > 0)
        printk("PID Finder: Found PID = %d\n", pid);
    else
        printk("PID Finder: Process not found\n");

    return 0;
}

static long pidfinder_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
