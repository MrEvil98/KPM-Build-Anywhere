#include <compiler.h>
#include <kpmodule.h>
#include <linux/kallsyms.h>
#include <linux/string.h>

KPM_NAME("Zenfone-Comm-Scanner");
KPM_VERSION("SCAN_COMM");
KPM_AUTHOR("ZenfoneDev");
KPM_LICENSE("GPL v2");

struct pid;
struct task_struct;

struct new_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct uts_namespace {
    struct { int counter; } kref;
    struct new_utsname name;
};

static struct pid *(*_find_get_pid)(int nr);
static struct task_struct *(*_get_pid_task)(struct pid *, int type);

static long scanner_init(const char *args,
                         const char *event,
                         void *__user reserved)
{
    unsigned long uts_addr;
    struct uts_namespace *uts;
    struct pid *pid_struct;
    struct task_struct *task;
    unsigned long i;
    char *base;
    char buffer[64];
    char *p;

    _find_get_pid = (void *)kallsyms_lookup_name("find_get_pid");
    _get_pid_task = (void *)kallsyms_lookup_name("get_pid_task");

    if (!_find_get_pid || !_get_pid_task)
        return -1;

    /* Use known PID 1418 */
    pid_struct = _find_get_pid(1418);
    if (!pid_struct)
        return -1;

    task = _get_pid_task(pid_struct, 0);
    if (!task)
        return -1;

    base = (char *)task;

    /* Scan first 0x1000 bytes for "zygote" */
    for (i = 0; i < 0x1000; i++) {
        if (strcmp(base + i, "zygote") == 0)
            break;
    }

    uts_addr = kallsyms_lookup_name("init_uts_ns");
    if (!uts_addr)
        return -1;

    uts = (struct uts_namespace *)uts_addr;

    strscpy(buffer, "FOUND_OFF:", sizeof(buffer));
    p = buffer + 10;

    if (i < 0x1000) {
        unsigned long off = i;
        int shift;

        for (shift = 28; shift >= 0; shift -= 4) {
            int digit = (off >> shift) & 0xF;
            if (digit || shift == 0)
                *p++ = digit < 10 ? '0' + digit : 'A' + digit - 10;
        }
    } else {
        strscpy(p, "NOTFOUND", sizeof(buffer) - (p - buffer));
        p += 8;
    }

    *p = '\0';

    strscpy(uts->name.release, buffer, sizeof(uts->name.release));

    return 0;
}

static long scanner_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(scanner_init);
KPM_EXIT(scanner_exit);
