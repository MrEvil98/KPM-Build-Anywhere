#include <compiler.h>
#include <kpmodule.h>
#include <linux/utsname.h>
#include <linux/string.h>

// 1. Module Info
KPM_NAME("Zenfone-Spoofer");
KPM_VERSION("1.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Spoofs uname -r to prove KPM is working");
KPM_LICENSE("GPL v2");

// 2. A place to store your real kernel version so we can restore it later
static char original_release[65];

// 3. What happens when you tap "Load"
static long spoofer_init(const char *args, const char *event, void *__user reserved)
{
    // Save the real kernel version (4.9.186-perf+) into our backup variable
    strncpy(original_release, init_uts_ns.name.release, 65);
    
    // Overwrite the live kernel memory with our custom hacked string
    strncpy(init_uts_ns.name.release, "4.9.186-HACKED-BY-KPM", 65);
    
    return 0;
}

// 4. What happens when you tap "Unload"
static long spoofer_exit(void *__user reserved)
{
    // Put the original kernel version back so nothing breaks
    strncpy(init_uts_ns.name.release, original_release, 65);
    
    return 0;
}

// 5. Register the functions
KPM_INIT(spoofer_init);
KPM_EXIT(spoofer_exit);
