#include <compiler.h>
#include <kpmodule.h>

#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>

// KPM Metadata
KPM_NAME("Zenfone-PIDFinder");
KPM_VERSION("1.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("PID finder via /proc interface");
KPM_LICENSE("GPL v2");

#define PROC_NAME "pidfinder"

static struct proc_dir_entry *proc_entry;
static char target_name[16] = "init";

/* Find PID by name */
static int find_pid_by_name(void)
{
    struct task_struct *task;

    for_each_process(task) {
        if (strcmp(task->comm, target_name) == 0)
            return task->pid;
    }

    return -1;
}

/* /proc read */
static int pidfinder_show(struct seq_file *m, void *v)
{
    int pid = find_pid_by_name();
    seq_printf(m, "%d\n", pid);
    return 0;
}

static int pidfinder_open(struct inode *inode, struct file *file)
{
    return single_open(file, pidfinder_show, NULL);
}

static const struct file_operations pidfinder_fops = {
    .owner   = THIS_MODULE,
    .open    = pidfinder_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

/* KPM Init */
static long pidfinder_init(const char *args,
                           const char *event,
                           void *__user reserved)
{
    if (args && strlen(args) > 0) {
        strscpy(target_name, args, sizeof(target_name));
    }

    proc_entry = proc_create(PROC_NAME, 0444, NULL, &pidfinder_fops);
    if (!proc_entry)
        return -1;

    return 0;
}

/* KPM Exit */
static long pidfinder_exit(void *__user reserved)
{
    if (proc_entry)
        remove_proc_entry(PROC_NAME, NULL);

    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
