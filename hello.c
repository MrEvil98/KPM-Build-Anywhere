#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/kthread.h> // For background threads
#include <linux/delay.h>   // For msleep()

KPM_NAME("Zenfone-PID-Scanner");
KPM_VERSION("2.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Live background scanner for BGMI PID");
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
static struct task_struct *hunter_thread = NULL;

// 1. The Background Thread (The Radar)
static int hunter_thread_fn(void *data)
{
    struct task_struct *task;
    struct uts_namespace *target_ns = (struct uts_namespace *)UTS_NS_ADDR;
    int found_pid;

    // Keep running continuously until we tap "Unload" in APatch
    while (!kthread_should_stop()) {
        found_pid = -1;
        
        rcu_read_lock();
        // Scan every active process in the kernel
        for_each_process(task) {
            // Looking for the exact 15-character truncated package name
            if (strcmp(task->comm, "com.pubg.imobil") == 0) {
                found_pid = task->pid;
                break; // Stop searching this cycle
            }
        }
        rcu_read_unlock();

        // Update the live memory
        if (found_pid != -1) {
            snprintf(target_ns->name.release, 65, "BGMI-PID-%d", found_pid);
        } else {
            strncpy(target_ns->name.release, "WAITING-FOR-BGMI", 65);
        }
        
        // Go to sleep for 2 seconds to save battery, then scan again
        msleep(2000); 
    }
    
    return 0;
}

// 2. Start the scanner when Loaded
static long pid_hunter_init(const char *args, const char *event, void *__user reserved)
{
    struct uts_namespace *target_ns = (struct uts_namespace *)UTS_NS_ADDR;
    
    // Backup the real kernel version
    strncpy(original_release, target_ns->name.release, 65);

    // Spawn the background radar thread!
    hunter_thread = kthread_run(hunter_thread_fn, NULL, "kpm_bgmi_radar");
    
    return 0;
}

// 3. Kill the scanner and clean up when Unloaded
static long pid_hunter_exit(void *__user reserved)
{
    struct uts_namespace *target_ns = (struct uts_namespace *)UTS_NS_ADDR;
    
    // Safely stop the background thread
    if (hunter_thread) {
        kthread_stop(hunter_thread);
    }

    // Put the real kernel version back
    strncpy(target_ns->name.release, original_release, 65);
    return 0;
}

KPM_INIT(pid_hunter_init);
KPM_EXIT(pid_hunter_exit);
