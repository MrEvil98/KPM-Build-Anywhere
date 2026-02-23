#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>

KPM_NAME("Zenfone-Spoofer");
KPM_VERSION("1.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Direct memory injection spoofer");
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

static char original_release[65];
static struct uts_namespace *target_ns = NULL;

static long spoofer_init(const char *args, const char *event, void *__user reserved)
{
    /* Resolve the real address at runtime — survives every reboot */
    target_ns = (struct uts_namespace *)kallsyms_lookup_name("init_uts_ns");
    if (!target_ns) return -1;

    /* Sanity check: sysname should start with 'L' for "Linux"
     * If kref padding is off by 4 bytes, adjust the pointer      */
    if (target_ns->name.sysname[0] != 'L') {
        target_ns = (struct uts_namespace *)((char *)target_ns - 4);
        if (target_ns->name.sysname[0] != 'L') return -1;
    }

    strncpy(original_release, target_ns->name.release, 65);
    strncpy(target_ns->name.release, "4.9.186-HACKED", 65);

    return 0;
}

static long spoofer_exit(void *__user reserved)
{
    if (target_ns)
        strncpy(target_ns->name.release, original_release, 65);
    return 0;
}

KPM_INIT(spoofer_init);
KPM_EXIT(spoofer_exit);
