#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>

KPM_NAME("Zenfone-KP-PIDFinder");
KPM_VERSION("3.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("KernelPatch PID finder (no offsets)");
KPM_LICENSE("GPL v2");

// UTS structures (same as your spoofer)
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
typedef void *(*find_vpid_t)(int);
typedef void *(*pid_task_t)(void *, int);
typedef void (*get_task_comm_t)(char *, void *);

static long pidfinder_init(const char *args,
                           const char *event,
                           void *__user reserved)
{
    unsigned long uts_addr;
    unsigned long find_vpid_addr;
    unsigned long pid_task_addr;
    unsigned long get_task_comm_addr;

    find_vpid_t find_vpid;
    pid_task_t pid_task;
    get_task_comm_t get_task_comm;

    int pid;
    int found = -1;
    char comm[16];
    char output[65];

    if (!args || strlen(args) == 0)
        return -1;

    // Resolve required symbols
    uts_addr = kallsyms_lookup_name("init_uts_ns");
    find_vpid_addr = kallsyms_lookup_name("find_vpid");
    pid_task_addr = kallsyms_lookup_name("pid_task");
    get_task_comm_addr = kallsyms_lookup_name("get_task_comm");

    if (!uts_addr || !find_vpid_addr ||
        !pid_task_addr || !get_task_comm_addr)
        return -1;

    target_ns = (struct uts_namespace *)uts_addr;

    find_vpid = (find_vpid_t)find_vpid_addr;
    pid_task = (pid_task_t)pid_task_addr;
    get_task_comm = (get_task_comm_t)get_task_comm_addr;

    // Backup original kernel version
    strscpy(original_release,
            target_ns->name.release,
            sizeof(original_release));

    // Scan PID range
    for (pid = 1; pid < 32768; pid++) {

        void *pid_struct = find_vpid(pid);
        if (!pid_struct)
            continue;

        void *task = pid_task(pid_struct, 0);
        if (!task)
            continue;

        get_task_comm(comm, task);

        if (strcmp(comm, args) == 0) {
            found = pid;
            break;
        }
    }

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
            sizeof(original_release));

    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
