// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * pid_finder.c — KPM module
 *
 * Hooks sys_getpid: when the target app calls it, saves its PID.
 * Hooks sys_newuname: injects the saved PID into the 'release' field
 * so `uname -r` shows it.
 *
 * TARGET_COMM must be the first 15 chars of the app's process name.
 * For PUBG Mobile: comm is "MainThread-UE4"
 * Check yours with: adb shell cat /proc/$(pidof com.pubg.imobile)/comm
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/utsname.h>
#include <pgtable.h>
#include <syscall.h>

KPM_NAME("pid-finder");
KPM_VERSION("1.0.0");
KPM_AUTHOR("kpm-build-anywhere");
KPM_DESCRIPTION("Shows target app PID via uname -r");
KPM_LICENSE("GPL v3");

/* ------------------------------------------------------------------ */
/*  CONFIG                                                             */
/* ------------------------------------------------------------------ */
#define TARGET_COMM "MainThread-UE4"
#define TASK_COMM_LEN 16

/* ------------------------------------------------------------------ */
/*  Kernel function declarations via KernelPatch's kfunc system       */
/*  These are resolved at load time by KP against the live kernel     */
/* ------------------------------------------------------------------ */
kfunc_def(get_current);
kfunc_def(strncmp);
kfunc_def(sprintf);

/* ------------------------------------------------------------------ */
/*  State                                                              */
/* ------------------------------------------------------------------ */
static int g_target_pid = 0;

/* ------------------------------------------------------------------ */
/*  Helper: get task_struct* for current process                      */
/* ------------------------------------------------------------------ */
static inline struct task_struct *kpm_current(void)
{
    return (struct task_struct *)kfunc_call(get_current);
}

/* ------------------------------------------------------------------ */
/*  Hook: sys_getpid — before handler                                 */
/*                                                                     */
/*  Called every time any process calls getpid(). We check if the    */
/*  caller's comm matches TARGET_COMM. If yes, save its pid.         */
/*                                                                     */
/*  sys_getpid takes 0 args so we use hook_fargs0_t.                 */
/* ------------------------------------------------------------------ */
static void before_getpid(hook_fargs0_t *args, void *udata)
{
    struct task_struct *task = kpm_current();
    if (!task) return;

    if (kfunc_call(strncmp, task->comm, TARGET_COMM, TASK_COMM_LEN) == 0) {
        int pid = task->pid;
        if (g_target_pid != pid) {
            g_target_pid = pid;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Hook: sys_newuname — after handler                                */
/*                                                                     */
/*  sys_newuname takes 1 arg (struct new_utsname __user *buf).       */
/*  We run AFTER the real syscall so it fills the struct first,      */
/*  then we overwrite the 'release' field before it reaches userspace.*/
/* ------------------------------------------------------------------ */
static void after_uname(hook_fargs1_t *args, void *udata)
{
    /* Only modify on success */
    if ((long)args->ret != 0) return;

    struct new_utsname __user *buf =
        (struct new_utsname __user *)args->arg0;
    if (!buf) return;

    struct new_utsname kbuf;

    /* Pull the already-filled struct from userspace */
    if (compat_copy_from_user(&kbuf, buf, sizeof(kbuf)) != 0) return;

    /* Write our PID info into the release field */
    if (g_target_pid != 0) {
        kfunc_call(sprintf, kbuf.release,
                   "pid[" TARGET_COMM "]=%d", g_target_pid);
    } else {
        kfunc_call(sprintf, kbuf.release,
                   "pid[" TARGET_COMM "]=not_found");
    }

    /* Push modified struct back to userspace */
    compat_copy_to_user(buf, &kbuf, sizeof(kbuf));
}

/* ------------------------------------------------------------------ */
/*  KPM lifecycle                                                      */
/* ------------------------------------------------------------------ */
static long pid_finder_init(const char *args, const char *event,
                            void *__user reserved)
{
    /* Resolve kernel symbols at load time */
    kfunc_lookup_name(get_current);
    kfunc_lookup_name(strncmp);
    kfunc_lookup_name(sprintf);

    hook_err_t rc;

    /*
     * fp_wrap_syscalln(syscall_nr, nargs, is_compat, before, after, udata)
     *
     * getpid: 0 args, before-only hook
     */
    rc = fp_wrap_syscalln(__NR_getpid, 0, 0,
                          (void *)before_getpid, NULL, NULL);
    if (rc != HOOK_NO_ERR) return -1;

    /*
     * newuname: 1 arg, after-only hook
     */
    rc = fp_wrap_syscalln(__NR_uname, 1, 0,
                          NULL, (void *)after_uname, NULL);
    if (rc != HOOK_NO_ERR) {
        fp_unwrap_syscalln(__NR_getpid, 0, 0);
        return -1;
    }

    return 0;
}

static long pid_finder_control(const char *args, const char *event,
                               void *__user reserved)
{
    /* Send "reset" via kpatch to clear the saved PID */
    if (args && kfunc_call(strncmp, args, "reset", 5) == 0) {
        g_target_pid = 0;
    }
    return 0;
}

static long pid_finder_exit(void *__user reserved)
{
    fp_unwrap_syscalln(__NR_getpid, 0, 0);
    fp_unwrap_syscalln(__NR_uname,  1, 0);
    return 0;
}

KPM_INIT(pid_finder_init);
KPM_CTL0(pid_finder_control);
KPM_EXIT(pid_finder_exit);
