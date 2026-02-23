#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>

KPM_NAME("Zenfone-Test-KPM");
KPM_VERSION("1.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Testing Emergency Logs");
KPM_LICENSE("GPL v2");

static long custom_init(const char *args, const char *event, void *__user reserved)
{
    // pr_emerg is "Kernel Emergency". The system CANNOT hide this.
    pr_emerg("[ZENFONE_TEST] =======================================\n");
    pr_emerg("[ZENFONE_TEST] EMERGENCY OVERRIDE: KPM LOADED!\n");
    pr_emerg("[ZENFONE_TEST] =======================================\n");
    return 0;
}

static long custom_exit(void *__user reserved)
{
    pr_emerg("[ZENFONE_TEST] EMERGENCY OVERRIDE: KPM UNLOADED!\n");
    return 0;
}

KPM_INIT(custom_init);
KPM_EXIT(custom_exit);
