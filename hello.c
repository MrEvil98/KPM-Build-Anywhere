#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/timer.h> // The ultimate lightweight background tool
#include <linux/jiffies.h>

KPM_NAME("Zenfone-PID-Scanner");
KPM_VERSION("3.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Timer-based background scanner for BGMI PID");
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
static struct timer_list bgmi_timer; // Our background radar

// 1. The Radar Logic (Fires every 2 seconds)
static void bgmi_timer_func(unsigned long data)
{
    struct task_struct *task;
    struct uts_namespace *target_ns = (struct uts_namespace *)UTS_NS_ADDR;
    int found_pid = -1;

    // Scan every active process in the kernel
    rcu_read_lock();
    for_each_process(task) {
        if (strcmp(task->comm, "com.pubg.imobil") == 0) {
            found_pid = task->pid;
            break;
        }
    }
    rcu_read_unlock();

    // Update live memory
    if (found_pid != -1) {
        snprintf(target_ns->name.release, 65, "BGMI-PID-%d", found_pid);
    } else {
        strncpy(target_ns->name.release, "WAITING-FOR-BGMI", 65);
    }
    
    // Re-arm the stopwatch for 2000 milliseconds (2 seconds)
    mod_timer(&bgmi_timer, jiffies + msecs_to_jiffies(2000));
}

// 2. Start the radar when Loaded
static long pid_hunter_init(const char *args, const char *event, void *__user reserved)
{
    struct uts_namespace *target_ns = (struct uts_namespace *)UTS_NS_ADDR;
    
    // Backup the real kernel version
    strncpy(original_release, target_ns->name.release, 65);

    // Setup and start the timer (This is native to Linux 4.9)
    setup_timer(&bgmi_timer, bgmi_timer_func, 0);
    mod_timer(&bgmi_timer, jiffies + msecs_to_jiffies(2000));
    
    return 0;
}

// 3. Kill the radar when Unloaded
static long pid_hunter_exit(void *__user reserved)
{
    struct uts_namespace *target_ns = (struct uts_namespace *)UTS_NS_ADDR;
    
    // Safely defuse and destroy the timer so it stops scanning
    del_timer_sync(&bgmi_timer);

    // Put the real kernel version back
    strncpy(target_ns->name.release, original_release, 65);
    return 0;
}

KPM_INIT(pid_hunter_init);
KPM_EXIT(pid_hunter_exit);
