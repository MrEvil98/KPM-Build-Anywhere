#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>

// 1. Set your custom module details
KPM_NAME("Zenfone-Test-KPM");
KPM_VERSION("1.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("My first custom kernel module via GitHub Actions");
KPM_LICENSE("GPL v2");

// 2. What happens when APatch LOADS the module
static long custom_init(const char *args, const char *event, void *__user reserved)
{
    // We use pr_info to print directly to the kernel's dmesg log.
    // The [ZENFONE_TEST] tag makes it super easy to search for later.
    pr_info("[ZENFONE_TEST] =======================================\n");
    pr_info("[ZENFONE_TEST] SUCCESS: Custom KPM Loaded!\n");
    pr_info("[ZENFONE_TEST] Hello from inside the Zenfone 5Z Kernel\n");
    pr_info("[ZENFONE_TEST] =======================================\n");
    
    return 0; // Return 0 means "Loaded successfully"
}

// 3. What happens when APatch UNLOADS the module
static long custom_exit(void *__user reserved)
{
    pr_info("[ZENFONE_TEST] Custom KPM has been unloaded. Goodbye!\n");
    return 0;
}

// 4. Register the functions with the KernelPatch engine
KPM_INIT(custom_init);
KPM_EXIT(custom_exit);
