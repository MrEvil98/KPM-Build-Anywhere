#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>

// 1. Module Info
KPM_NAME("Zenfone-Spoofer");
KPM_VERSION("1.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Direct memory injection spoofer");
KPM_LICENSE("GPL v2");

// 2. Map out the memory shape
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

// 3. YOUR EXACT KERNEL MEMORY ADDRESS
#define UTS_NS_ADDR 0xffffff966fa20fc0

static char original_release[65];

// 4. Inject the string on Load
static long spoofer_init(const char *args, const char *event, void *__user reserved)
{
    // Cast the raw address into a usable pointer
    struct uts_namespace *target_ns = (struct uts_namespace *)UTS_NS_ADDR;
    
    // Backup the real version
    strncpy(original_release, target_ns->name.release, 65);
    
    // OVERWRITE MEMORY!
    strncpy(target_ns->name.release, "4.9.186-HACKED", 65);
    
    return 0;
}

// 5. Restore the string on Unload
static long spoofer_exit(void *__user reserved)
{
    struct uts_namespace *target_ns = (struct uts_namespace *)UTS_NS_ADDR;
    
    // Restore memory so nothing crashes
    strncpy(target_ns->name.release, original_release, 65);
    
    return 0;
}

KPM_INIT(spoofer_init);
KPM_EXIT(spoofer_exit);
