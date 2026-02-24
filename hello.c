#include <compiler.h>
#include <kpmodule.h>
#include <linux/kallsyms.h>
#include <linux/string.h>

KPM_NAME("Zenfone-PID-Finder");
KPM_VERSION("VISIBLE");
KPM_AUTHOR("ZenfoneDev");
KPM_LICENSE("GPL v2");

#define COMM_OFFSET 0x5c0   // may adjust later

struct pid;
struct task_struct;

/* UTS structures (you already used this successfully) */
struct new_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct uts_namespace {
    struct {
        int counter;
    } kref;
    struct new_utsname name;
};

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

        task = _get_pid_task(pid_struct, 0); // PIDTYPE_PID
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
    unsigned long uts_addr;
    struct uts_namespace *uts;
    int pid;
    char buffer[64];

    _find_get_pid = (void *)kallsyms_lookup_name("find_get_pid");
    _get_pid_task = (void *)kallsyms_lookup_name("get_pid_task");

    if (!_find_get_pid || !_get_pid_task)
        return -1;

    pid = find_pid_by_name("zygote");

    /* resolve uts namespace */
    uts_addr = kallsyms_lookup_name("init_uts_ns");
    if (!uts_addr)
        return -1;

    uts = (struct uts_namespace *)uts_addr;

    /* write PID into uname release */
    snprintf(buffer, sizeof(buffer), "PID:%d", pid);
    strscpy(uts->name.release, buffer, sizeof(uts->name.release));

    return 0;
}

static long pidfinder_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
