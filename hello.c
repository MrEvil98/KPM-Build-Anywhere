#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>

// KPM Metadata
KPM_NAME("Zenfone-PIDFinder");
KPM_VERSION("1.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Minimal PID finder using UTS release output");
KPM_LICENSE("GPL v2");

// Recreate required kernel structs (like your spoofer)
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

static long pidfinder_init(const char *args,
                           const char *event,
                           void *__user reserved)
{
    unsigned long uts_addr;
    struct task_struct *task;
    int found_pid = -1;
    char output[65];

    if (!args || strlen(args) == 0)
        return -1;

    // Resolve init_uts_ns
    uts_addr = kallsyms_lookup_name("init_uts_ns");
    if (!uts_addr)
        return -1;

    target_ns = (struct uts_namespace *)uts_addr;

    // Backup original release
    strscpy(original_release,
            target_ns->name.release,
            sizeof(original_release));

    // Find PID
    for_each_process(task) {
        if (strcmp(task->comm, args) == 0) {
            found_pid = task->pid;
            break;
        }
    }

    // Prepare output string
    if (found_pid >= 0)
        snprintf(output, sizeof(output), "PID:%d", found_pid);
    else
        strscpy(output, "PID:-1", sizeof(output));

    // Write to uname -r
    strscpy(target_ns->name.release,
            output,
            sizeof(target_ns->name.release));

    return 0;
}

static long pidfinder_exit(void *__user reserved)
{
    if (!target_ns)
        return -1;

    // Restore original kernel release
    strscpy(target_ns->name.release,
            original_release,
            sizeof(target_ns->name.release));

    return 0;
}

KPM_INIT(pidfinder_init);
KPM_EXIT(pidfinder_exit);
