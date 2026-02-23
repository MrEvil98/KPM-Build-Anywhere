#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>

// 1. Module Info
KPM_NAME("Zenfone-Spoofer");
KPM_VERSION("1.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Spoofs uname -r");
KPM_LICENSE("GPL v2");

// 2. Manually teach the compiler the shape of the kernel's memory
struct new_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct uts_namespace {
    int kref; // Padding for the kernel reference counter
    struct new_utsname name;
};

// 3. Tell the compiler to look for this variable in the live kernel
extern struct uts_namespace init_uts_ns;

// 4. Backup variable
static char original_release[65];

// 5. Code to run on Load
static long spoofer_init(const char *args, const char *event, void *__user reserved)
{
    // Backup the real version (4.9.186-perf+)
    strncpy(original_release, init_uts_ns.name.release, 65);
    
    // Inject the fake version directly into memory
    strncpy(init_uts_ns.name.release, "4.9.186-HACKED", 65);
    
    return 0;
}

// 6. Code to run on Unload
static long spoofer_exit(void *__user reserved)
{
    // Restore the real version so nothing crashes when we leave
    strncpy(init_uts_ns.name.release, original_release, 65);
    
    return 0;
}

KPM_INIT(spoofer_init);
KPM_EXIT(spoofer_exit);
