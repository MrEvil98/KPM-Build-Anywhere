#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/list.h>

// Module Info
KPM_NAME("Zenfone-PID-Finder");
KPM_VERSION("1.0.1");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("PID finder (KP v4 raw compatible)");
KPM_LICENSE("GPL v2");

// Minimal task_struct layout (Android 4.9/4.14 safe region)
struct task_struct {
    struct list_head tasks;
    pid_t pid;
    char comm[16];
};

static struct task_struct *init_task_ptr;

static int find_pid_by_name(const char *name)
{
    struct task_struct *task;
    struct list_head *pos;

    task = init_task_ptr;

    list_for_each(pos, &task->tasks) {
        struct task_struct *t =
            list_entry(pos, struct task_struct, tasks);

        if (strcmp(t->comm, name) == 0)
            return t->pid;
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

    init_task_ptr = (struct task_struct *)addr;

    pid = find_pid_by_name("zygote");

    if (pid > 0)
        printk("PID Finder: Found PID = %d\n", pid);
    else
        printk("PID Finder: Not found\n");

    return 0;
}

static long pidfinder_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
