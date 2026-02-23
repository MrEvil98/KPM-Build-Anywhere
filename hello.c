#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <linux/sched.h> // This one we know is safe!

KPM_NAME("Zenfone-PID-Scanner");
KPM_VERSION("4.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("On-Demand BGMI PID Scanner");
KPM_LICENSE("GPL v2");

struct new_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct uts_namespace {
    int kref; 
    struct new_utsname name;
};

// Your exact Zenfone memory address
#define UTS_NS_ADDR 0xffffff966fa20fc0

static char original_release[65];

static long pid_hunter_init(const char *args, const char *event, void *__user reserved)
{
    struct task_struct *task;
    struct uts_namespace *target_ns = (struct uts_namespace *)UTS_NS_ADDR;
    int found_pid = -1;

    // Backup the real kernel version
    strncpy(original_release, target_ns->name.release, 65);

    // 1. Scan memory ONCE when you tap "Load"
    rcu_read_lock();
    for_each_process(task) {
        // Strict 15-character check to avoid false positives
        if (strcmp(task->comm, "com.pubg.imobil") == 0) {
            found_pid = task->pid;
            break; // Found it, stop scanning!
        }
    }
    rcu_read_unlock();

    // 2. Lock the result into uname
    if (found_pid != -1) {
        snprintf(target_ns->name.release, 65, "BGMI-PID-%d", found_pid);
    } else {
        strncpy(target_ns->name.release, "BGMI-NOT-FOUND", 65);
    }
    
    return 0;
}

static long pid_hunter_exit(void *__user reserved)
{
    struct uts_namespace *target_ns = (struct uts_namespace *)UTS_NS_ADDR;
    
    // Put the real kernel version back when you Unload
    strncpy(target_ns->name.release, original_release, 65);
    return 0;
}

KPM_INIT(pid_hunter_init);
KPM_EXIT(pid_hunter_exit);
