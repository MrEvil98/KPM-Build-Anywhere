#include <compiler.h>
#include <kpmodule.h>
#include <linux/kallsyms.h>
#include <linux/string.h>

KPM_NAME("Zenfone-PID-Finder");
KPM_VERSION("AUTO_OFFSET");
KPM_AUTHOR("ZenfoneDev");
KPM_LICENSE("GPL v2");

struct pid;
struct task_struct;

/* UTS layout (working already) */
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

/* Common 4.9 ARM64 offsets */
static unsigned long offsets[] = {
    0x5a0, 0x5b0, 0x5c0, 0x5d0, 0x5d8,
    0x5e0, 0x5f0, 0x600, 0x610, 0x618,
    0x620, 0x630, 0x640
};

static int find_pid_with_offset(const char *target, unsigned long off)
{
    int i;

    for (i = 1; i < 32768; i++) {

        struct pid *pid_struct;
        struct task_struct *task;

        pid_struct = _find_get_pid(i);
        if (!pid_struct)
            continue;

        task = _get_pid_task(pid_struct, 0);
        if (!task)
            continue;

        char *comm = (char *)task + off;

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
    int pid = -1;
    int i;
    char buffer[64];
    char *p;

    _find_get_pid = (void *)kallsyms_lookup_name("find_get_pid");
    _get_pid_task = (void *)kallsyms_lookup_name("get_pid_task");

    if (!_find_get_pid || !_get_pid_task)
        return -1;

    /* Try all offsets */
    for (i = 0; i < sizeof(offsets)/sizeof(offsets[0]); i++) {

        pid = find_pid_with_offset("zygote", offsets[i]);

        if (pid > 0)
            break;
    }

    uts_addr = kallsyms_lookup_name("init_uts_ns");
    if (!uts_addr)
        return -1;

    uts = (struct uts_namespace *)uts_addr;

    /* Build result string */
    strscpy(buffer, "OFF:", sizeof(buffer));
    p = buffer + 4;

    /* Write offset in hex */
    {
        unsigned long off = (pid > 0) ? offsets[i] : 0;
        int shift;

        for (shift = 28; shift >= 0; shift -= 4) {
            int digit = (off >> shift) & 0xF;
            if (digit || shift == 0)
                *p++ = digit < 10 ? '0' + digit : 'A' + digit - 10;
        }
    }

    strscpy(p, " PID:", sizeof(buffer) - (p - buffer));
    p += 5;

    if (pid > 0) {
        int tmp = pid;
        int digits[10], dcount = 0;

        while (tmp > 0) {
            digits[dcount++] = tmp % 10;
            tmp /= 10;
        }

        while (dcount--)
            *p++ = '0' + digits[dcount];
    } else {
        *p++ = '0';
    }

    *p = '\0';

    strscpy(uts->name.release, buffer, sizeof(uts->name.release));

    return 0;
}

static long pidfinder_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
