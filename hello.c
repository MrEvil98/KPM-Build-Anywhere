#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <linux/kallsyms.h>

// Module Info
KPM_NAME("Zenfone-Spoofer");
KPM_VERSION("1.1.1");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Dynamic UTS release spoofer");
KPM_LICENSE("GPL v2");

// Recreate required kernel structs manually
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

static long spoofer_init(const char *args, const char *event, void *__user reserved)
{
    unsigned long uts_addr;

    uts_addr = kallsyms_lookup_name("init_uts_ns");
    if (!uts_addr)
        return -1;

    target_ns = (struct uts_namespace *)uts_addr;

    strscpy(original_release,
            target_ns->name.release,
            sizeof(original_release));

    strscpy(target_ns->name.release,
            "4.9.186-HACKED",
            sizeof(target_ns->name.release));

    return 0;
}

static long spoofer_exit(void *__user reserved)
{
    if (!target_ns)
        return -1;

    strscpy(target_ns->name.release,
            original_release,
            sizeof(target_ns->name.release));

    return 0;
}

KPM_INIT(spoofer_init);
KPM_EXIT(spoofer_exit);
