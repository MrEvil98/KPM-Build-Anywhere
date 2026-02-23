// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * pid_finder.c — KPM module
 *
 * Hooks sys_getpid: when the target app calls it, we save its PID.
 * Hooks sys_newuname: injects the saved PID into the 'release' field,
 * so `uname -r` shows it.
 *
 * Target app is identified by the first 15 chars of its process name
 * (task_struct->comm). Android truncates package names in comm to 15
 * chars — adjust TARGET_COMM below to match your app.
 *
 * Example:
 *   Package: com.example.myapp  →  comm is usually "m.example.myapp"
 *                                  (last 15 chars, set by Android at fork)
 *
 * Build: set TARGET_COMM to your app's comm value, then run make.
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/utsname.h>
#include <syscall.h>

KPM_NAME("pid-finder");
KPM_VERSION("1.0.0");
KPM_AUTHOR("kpm-build-anywhere");
KPM_DESCRIPTION("Shows target app PID via uname -r");
KPM_LICENSE("GPL v3");

/* ------------------------------------------------------------------ */
/*  CONFIG — change this to the first 15 chars of your app's comm     */
/*                                                                     */
/*  To find your app's comm, run on the device while app is running:  */
/*    adb shell cat /proc/$(pidof com.your.app)/comm                  */
/* ------------------------------------------------------------------ */
#define TARGET_COMM "MainThread-UE4"

/* ------------------------------------------------------------------ */
/*  State                                                              */
/* ------------------------------------------------------------------ */
static pid_t g_target_pid = 0;  /* 0 = not found yet */

/* Original syscall pointers — filled in by the hook framework */
static long (*orig_getpid)(void) = NULL;
static long (*orig_newuname)(struct new_utsname __user *name) = NULL;

/* ------------------------------------------------------------------ */
/*  Hook: sys_getpid                                                   */
/*                                                                     */
/*  Called by every process that invokes getpid(). We check if the    */
/*  caller's comm matches our target. If yes, save the PID.           */
/*  Then call through to the real syscall so the app still works.     */
/* ------------------------------------------------------------------ */
static long hook_getpid(void)
{
    /* current is the task_struct of the calling process — always valid
     * inside a syscall hook because we're in process context.        */
    if (strncmp(current->comm, TARGET_COMM, TASK_COMM_LEN) == 0) {
        pid_t pid = current->pid;
        if (g_target_pid != pid) {
            g_target_pid = pid;
            /* pr_info goes to kernel log — useful if you re-enable it later */
            pr_info("[pid-finder] found '%s' pid=%d\n", TARGET_COMM, pid);
        }
    }

    /* Always call the original so the app gets its real PID back */
    return orig_getpid();
}

/* ------------------------------------------------------------------ */
/*  Hook: sys_newuname                                                 */
/*                                                                     */
/*  Called when anything runs `uname -r`. We let the real syscall     */
/*  fill the struct first, then overwrite the 'release' field with    */
/*  our PID string (or a waiting message if not found yet).           */
/* ------------------------------------------------------------------ */
static long hook_newuname(struct new_utsname __user *buf)
{
    long ret;
    struct new_utsname kbuf;

    /* Let the real uname fill the buffer first */
    ret = orig_newuname(buf);
    if (ret != 0)
        return ret;

    /* Copy from userspace so we can inspect/overwrite */
    if (compat_copy_from_user(&kbuf, buf, sizeof(kbuf)) != 0)
        return ret;

    /* Overwrite the 'release' field — this is what uname -r shows */
    if (g_target_pid != 0) {
        kp_snprintf(kbuf.release, sizeof(kbuf.release),
                    "pid[%s]=%d", TARGET_COMM, (int)g_target_pid);
    } else {
        kp_snprintf(kbuf.release, sizeof(kbuf.release),
                    "pid[%s]=not_found_yet", TARGET_COMM);
    }

    /* Write modified buffer back to userspace */
    compat_copy_to_user(buf, &kbuf, sizeof(kbuf));

    return ret;
}

/* ------------------------------------------------------------------ */
/*  KPM lifecycle                                                      */
/* ------------------------------------------------------------------ */
static long pid_finder_init(const char *args, const char *event, void *__user reserved)
{
    long rc;

    pr_info("[pid-finder] loading, watching for comm='%s'\n", TARGET_COMM);

    /* Hook sys_getpid */
    rc = hook_wrap_syscall(__NR_getpid,
                           (void *)hook_getpid,
                           (void **)&orig_getpid);
    if (rc) {
        pr_err("[pid-finder] failed to hook sys_getpid: %ld\n", rc);
        return rc;
    }

    /* Hook sys_newuname */
    rc = hook_wrap_syscall(__NR_uname,
                           (void *)hook_newuname,
                           (void **)&orig_newuname);
    if (rc) {
        pr_err("[pid-finder] failed to hook sys_newuname: %ld\n", rc);
        /* Clean up the getpid hook we already installed */
        hook_unwrap_syscall(__NR_getpid, (void *)hook_getpid, NULL);
        return rc;
    }

    pr_info("[pid-finder] loaded — run your app then `uname -r`\n");
    return 0;
}

static long pid_finder_control(const char *args, const char *event, void *__user reserved)
{
    /* Optional: react to runtime control commands.
     * For example `kpatch -m pid-finder reset` could clear g_target_pid. */
    if (args && strncmp(args, "reset", 5) == 0) {
        g_target_pid = 0;
        pr_info("[pid-finder] PID reset\n");
    }
    return 0;
}

static long pid_finder_exit(void *__user reserved)
{
    hook_unwrap_syscall(__NR_getpid,  (void *)hook_getpid,   NULL);
    hook_unwrap_syscall(__NR_uname,   (void *)hook_newuname,  NULL);
    pr_info("[pid-finder] unloaded\n");
    return 0;
}

KPM_INIT(pid_finder_init);
KPM_CTL(pid_finder_control);
KPM_EXIT(pid_finder_exit);
