/*
 * BGMI Base Address Finder KPM for Asus Zenfone 5Z
 * Takes a PID as argument and returns the base address of libUE4.so
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <kpmodule.h>

KPM_NAME("bgmi_base_finder");
KPM_VERSION("1.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Find base address of libUE4.so for a given PID");
KPM_LICENSE("GPL v2");

static long bgmi_base_finder_init(const char *args, const char *event, void *__user reserved)
{
    pid_t pid;
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long base_addr = 0;
    char *path_buf;
    int ret;

    // Validate and parse the PID argument
    if (!args || strlen(args) == 0) {
        pr_err("bgmi_base_finder: no PID provided\n");
        return -EINVAL;
    }

    ret = kstrtoint(args, 10, &pid);
    if (ret < 0) {
        pr_err("bgmi_base_finder: invalid PID format: '%s'\n", args);
        return ret;
    }

    pr_info("bgmi_base_finder: searching for PID %d\n", pid);

    // Get the pid structure
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        pr_err("bgmi_base_finder: PID %d not found\n", pid);
        return -ESRCH;
    }

    // Get the task structure
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);  // release the pid reference
    if (!task) {
        pr_err("bgmi_base_finder: task for PID %d is gone\n", pid);
        return -ESRCH;
    }

    // Get the memory descriptor (mm) of the task
    mm = get_task_mm(task);
    put_task_struct(task);  // done with task
    if (!mm) {
        pr_err("bgmi_base_finder: PID %d has no memory (kernel thread?)\n", pid);
        return -EINVAL;
    }

    // Allocate a buffer for the file path (PATH_MAX is 4096)
    path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!path_buf) {
        mmput(mm);
        return -ENOMEM;
    }

    // Lock the mmap for reading while walking the VMA list
    down_read(&mm->mmap_sem);

    // Walk through all VMAs of the process
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        struct file *file = vma->vm_file;
        if (!file)
            continue;   // anonymous mapping, skip

        // Get the full path of the mapped file
        char *path = file_path(file, path_buf, PATH_MAX);
        if (IS_ERR(path))
            continue;   // path resolution failed, skip this VMA

        // Look for libUE4.so in the path (case‑sensitive)
        if (strstr(path, "libUE4.so")) {
            // The base address of the library is the VMA with file offset 0
            if (vma->vm_pgoff == 0) {
                base_addr = vma->vm_start;
                break;  // found the exact base, stop searching
            }
            // If we haven't found offset 0 yet, keep the smallest start as fallback
            if (base_addr == 0 || vma->vm_start < base_addr)
                base_addr = vma->vm_start;
        }
    }

    up_read(&mm->mmap_sem);
    mmput(mm);
    kfree(path_buf);

    // Check if we found anything
    if (base_addr == 0) {
        pr_err("bgmi_base_finder: libUE4.so not found in PID %d\n", pid);
        return -ENOENT;
    }

    // Print the result to kernel log (APatch can capture it)
    pr_info("bgmi_base_finder: base address of libUE4.so for PID %d = 0x%lx\n", pid, base_addr);

    // If APatch provides a userspace buffer via 'reserved', we can copy the result there
    // Uncomment the following block if needed.
    /*
    if (reserved) {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%lx", base_addr);
        if (copy_to_user(reserved, buf, strlen(buf) + 1)) {
            pr_err("bgmi_base_finder: failed to copy to userspace\n");
            return -EFAULT;
        }
    }
    */

    return 0;   // success
}

static long bgmi_base_finder_exit(void *__user reserved)
{
    // Nothing to clean up
    return 0;
}

KPM_INIT(bgmi_base_finder_init);
KPM_EXIT(bgmi_base_finder_exit);
