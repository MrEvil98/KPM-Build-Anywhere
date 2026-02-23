#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/utsname.h>

// 1. Module Info
KPM_NAME("Zenfone-Spoofer");
KPM_VERSION("1.1.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Dynamic UTS release spoofer");
KPM_LICENSE("GPL v2");

static struct uts_namespace *target_ns;
static char original_release[__NEW_UTS_LEN + 1];

// 2. Load
static long spoofer_init(const char *args, const char *event, void *__user reserved)
{
    unsigned long uts_addr;

    // Resolve init_uts_ns dynamically
    uts_addr = kallsyms_lookup_name("init_uts_ns");
    if (!uts_addr)
        return -1;

    target_ns = (struct uts_namespace *)uts_addr;

    // Backup original release
    strscpy(original_release,
            target_ns->name.release,
            sizeof(original_release));

    // Spoof kernel version
    strscpy(target_ns->name.release,
            "4.9.186-HACKED",
            sizeof(target_ns->name.release));

    return 0;
}

// 3. Unload
static long spoofer_exit(void *__user reserved)
{
    if (!target_ns)
        return -1;

    // Restore original value
    strscpy(target_ns->name.release,
            original_release,
            sizeof(target_ns->name.release));

    return 0;
}

KPM_INIT(spoofer_init);
KPM_EXIT(spoofer_exit);
