#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>

// Metadata
KPM_NAME("Zenfone-KP-PIDFinder");
KPM_VERSION("1.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("KernelPatch-style PID finder");
KPM_LICENSE("GPL v2");

// UTS structs (same as your spoofer)
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

static struct uts_namespace *target_ns;
static char original_release[65];

// Function pointer types
typedef void *(*next_task_t)(void *);
typedef void (*get_task_comm_t)(char *, void *);

static long pidfinder_init(const char *args,
                           const char *event,
                           void *__user reserved)
{
    unsigned long uts_addr;
    unsigned long init_task_addr;
    unsigned long next_task_addr;
    unsigned long get_task_comm_addr;

    next_task_t next_task;
    get_task_comm_t get_task_comm;

    void *task;
    void *init_task;
    int found = -1;
    char comm[16];
    char output[65];

    if (!args || strlen(args) == 0)
        return -1;

    // Resolve required symbols
    uts_addr = kallsyms_lookup_name("init_uts_ns");
    init_task_addr = kallsyms_lookup_name("init_task");
    next_task_addr = kallsyms_lookup_name("next_task");
    get_task_comm_addr = kallsyms_lookup_name("get_task_comm");

    if (!uts_addr || !init_task_addr ||
        !next_task_addr || !get_task_comm_addr)
        return -1;

    target_ns = (struct uts_namespace *)uts_addr;

    next_task = (next_task_t)next_task_addr;
    get_task_comm = (get_task_comm_t)get_task_comm_addr;

    init_task = (void *)init_task_addr;
    task = init_task;

    // Backup original release
    strscpy(original_release,
            target_ns->name.release,
            sizeof(original_release));

    // Walk task list safely using function pointers
    do {
        get_task_comm(comm, task);

        if (strcmp(comm, args) == 0) {
            // pid is first int in task_struct on 4.9 (safe shortcut)
            found = *(int *)task;
            break;
        }

        task = next_task(task);

    } while (task != init_task);

    if (found >= 0)
        snprintf(output, sizeof(output), "PID:%d", found);
    else
        strscpy(output, "PID:-1", sizeof(output));

    strscpy(target_ns->name.release,
            output,
            sizeof(target_ns->name.release));

    return 0;
}

static long pidfinder_exit(void *__user reserved)
{
    if (!target_ns)
        return -1;

    strscpy(target_ns->name.release,
            original_release,
            sizeof(target_ns->name.release));

    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
