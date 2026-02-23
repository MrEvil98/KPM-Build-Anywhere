// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * pid_finder.c — KPM module
 *
 * Hooks sys_getpid: when the PUBG Mobile main thread calls it, saves its PID.
 * Hooks sys_newuname: injects the saved PID into the 'release' field
 * so `uname -r` shows it.
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <linux/utsname.h>
#include <syscall.h>

KPM_NAME("pid-finder");
KPM_VERSION("1.0.0");
KPM_AUTHOR("kpm-build-anywhere");
KPM_DESCRIPTION("Shows PUBG Mobile PID via uname -r");
KPM_LICENSE("GPL v3");

/* ------------------------------------------------------------------ */
/*  CONFIG                                                             */
/* ------------------------------------------------------------------ */
#define TARGET_COMM "MainThread-UE4"
#define TASK_COMM_LEN 16

/* ------------------------------------------------------------------ */
/*  kfunc_def requires full C function pointer type declarations.     */
/*  The macro expands to: <returntype> (*kf_funcname)(args)           */
/*  We must provide the full prototype.                               */
/* ------------------------------------------------------------------ */
struct task_struct *(*kf_get_current)(void) = NULL;
int (*kf_strncmp)(const char *s1, const char *s2, long n) = NULL;
int (*kf_sprintf)(char *buf, const char *fmt, ...) = NULL;

/* ------------------------------------------------------------------ */
/*  State                                                              */
/* ------------------------------------------------------------------ */
static int g_target_pid = 0;

/* ------------------------------------------------------------------ */
/*  Hook: sys_getpid — before handler                                 */
/*                                                                     */
/*  sys_getpid takes 0 args → hook_fargs0_t                          */
/* ------------------------------------------------------------------ */
static void before_getpid(hook_fargs0_t *args, void *udata)
{
    if (!kf_get_current || !kf_strncmp) return;

    struct task_struct *task = kf_get_current();
    if (!task) return;

    /* strncmp returns 0 on match */
    int match = kf_strncmp(task->comm, TARGET_COMM, TASK_COMM_LEN);
    if (match == 0) {
        int pid = task->pid;
        if (g_target_pid != pid) {
            g_target_pid = pid;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Hook: sys_newuname — after handler                                */
/*                                                                     */
/*  sys_newuname takes 1 arg → hook_fargs1_t                         */
/*  args->arg0 = struct new_utsname __user *                         */
/*  We run after the real syscall, then overwrite release field.      */
/*                                                                     */
/*  compat_copy_from_user does NOT exist in KP headers.              */
/*  We use a stack buffer and copy field-by-field via our own bytes.  */
/*  Since we only WRITE (not read) the userspace buffer, we build    */
/*  the release string locally and copy just that field back.         */
/* ------------------------------------------------------------------ */
static void after_uname(hook_fargs1_t *args, void *udata)
{
    if (!kf_sprintf) return;

    /* Only act on successful syscall */
    if ((long)args->ret != 0) return;

    struct new_utsname __user *buf =
        (struct new_utsname __user *)args->arg0;
    if (!buf) return;

    /* Build our release string in a local buffer */
    char release[65]; /* __NEW_UTS_LEN + 1 = 65 */
    if (g_target_pid != 0) {
        kf_sprintf(release, "pid[" TARGET_COMM "]=%d", g_target_pid);
    } else {
        kf_sprintf(release, "pid[" TARGET_COMM "]=not_found");
    }

    /*
     * compat_copy_to_user(to, from, n)
     * We only overwrite the 'release' member of new_utsname.
     * release is the 2nd field: offset = sizeof(utsname.sysname) = 65
     */
    compat_copy_to_user(buf->release, release, sizeof(release));
}

/* ------------------------------------------------------------------ */
/*  KPM lifecycle                                                      */
/* ------------------------------------------------------------------ */
static long pid_finder_init(const char *args, const char *event,
                            void *__user reserved)
{
    /* Resolve kernel symbols by name against live kernel kallsyms */
    kf_get_current = (struct task_struct *(*)(void))
                     kallsyms_lookup_name("__this_cpu_read_current");
    if (!kf_get_current) {
        /* fallback name used on most arm64 kernels */
        kf_get_current = (struct task_struct *(*)(void))
                         kallsyms_lookup_name("get_current");
    }

    kf_strncmp = (int (*)(const char *, const char *, long))
                 kallsyms_lookup_name("strncmp");

    kf_sprintf  = (int (*)(char *, const char *, ...))
                  kallsyms_lookup_name("sprintf");

    hook_err_t rc;

    /*
     * fp_wrap_syscalln(nr, narg, is_compat, before, after, udata)
     * sys_getpid: 0 args, not compat, before-only
     */
    rc = fp_wrap_syscalln(__NR_getpid, 0, 0,
                          (void *)before_getpid, NULL, NULL);
    if (rc != HOOK_NO_ERR) return -1;

    /*
     * sys_newuname: 1 arg, not compat, after-only
     */
    rc = fp_wrap_syscalln(__NR_uname, 1, 0,
                          NULL, (void *)after_uname, NULL);
    if (rc != HOOK_NO_ERR) {
        /* clean up first hook */
        fp_unwrap_syscalln(__NR_getpid, 0,
                           (void *)before_getpid, NULL);
        return -1;
    }

    return 0;
}

/*
 * KPM_CTL0 callback signature (from kpmodule.h):
 *   long fn(const char *args, char *__user out_buf, int out_buf_size)
 */
static long pid_finder_control(const char *args, char *__user out_buf,
                               int out_buf_size)
{
    if (!args) return 0;

    /* Manual strcmp for "reset" — avoids kfunc_call in condition */
    int is_reset = (args[0] == 'r' && args[1] == 'e' &&
                    args[2] == 's' && args[3] == 'e' &&
                    args[4] == 't' && args[5] == '\0');
    if (is_reset) {
        g_target_pid = 0;
    }
    return 0;
}

static long pid_finder_exit(void *__user reserved)
{
    /*
     * fp_unwrap_syscalln(nr, is_compat, before, after)  ← 4 args
     */
    fp_unwrap_syscalln(__NR_getpid, 0, (void *)before_getpid, NULL);
    fp_unwrap_syscalln(__NR_uname,  0, NULL, (void *)after_uname);
    return 0;
}

KPM_INIT(pid_finder_init);
KPM_CTL0(pid_finder_control);
KPM_EXIT(pid_finder_exit);
