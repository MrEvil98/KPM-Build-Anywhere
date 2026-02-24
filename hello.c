#include <compiler.h>
#include <kpmodule.h>
#include <linux/kallsyms.h>
#include <linux/string.h>

KPM_NAME("Zenfone-PID-Finder");
KPM_VERSION("VISIBLE_FINAL");
KPM_AUTHOR("ZenfoneDev");
KPM_LICENSE("GPL v2");

#define COMM_OFFSET 0x5d8   // If PID prints -1, we adjust this safely

struct pid;
struct task_struct;

/* UTS structures (same layout you used before successfully) */
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
    char *p;
    int tmp;
    int digits[10];
    int dcount = 0;
    int i;

    /* Resolve kernel symbols */
    _find_get_pid = (void *)kallsyms_lookup_name("find_get_pid");
    _get_pid_task = (void *)kallsyms_lookup_name("get_pid_task");

    if (!_find_get_pid || !_get_pid_task)
        return -1;

    pid = find_pid_by_name("zygote");

    /* Resolve init_uts_ns */
    uts_addr = kallsyms_lookup_name("init_uts_ns");
    if (!uts_addr)
        return -1;

    uts = (struct uts_namespace *)uts_addr;

    /* Build string "PID:xxxx" safely */
    strscpy(buffer, "PID:", sizeof(buffer));
    p = buffer + 4;

    tmp = pid;

    if (tmp == 0) {
        *p++ = '0';
    } else {

        if (tmp < 0) {
            *p++ = '-';
            tmp = -tmp;
        }

        while (tmp > 0) {
            digits[dcount++] = tmp % 10;
            tmp /= 10;
        }

        for (i = dcount - 1; i >= 0; i--)
            *p++ = '0' + digits[i];
    }

    *p = '\0';

    /* Write into uname release */
    strscpy(uts->name.release, buffer, sizeof(uts->name.release));

    return 0;
}

static long pidfinder_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
