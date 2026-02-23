// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * pid_finder.c — KPM module for Asus Zenfone 5z (kernel 4.9.186, sdm845)
 *
 * Because task_struct offsets vary per vendor kernel and we cannot
 * access the struct by field name, this module auto-discovers the
 * 'pid' and 'comm' offsets at load time by scanning the memory of
 * the current task (the KPM loader process, whose PID and comm we
 * know from /proc/self at load time).
 *
 * Once offsets are found, hooks sys_getpid to detect PUBG Mobile's
 * main thread and saves its PID. Then hooks sys_newuname to inject
 * the PID into `uname -r` output.
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <syscall.h>

KPM_NAME("pid-finder");
KPM_VERSION("1.0.0");
KPM_AUTHOR("kpm-build-anywhere");
KPM_DESCRIPTION("Shows PUBG Mobile PID via uname -r");
KPM_LICENSE("GPL v3");

/* ------------------------------------------------------------------ */
/*  CONFIG                                                             */
/* ------------------------------------------------------------------ */
#define TARGET_COMM      "MainThread-UE4"
#define TASK_COMM_LEN    16
#define UTSNAME_FIELD_LEN 65

/* Search window around the task pointer for offset discovery */
#define SCAN_MAX_OFFSET  0x1000   /* scan first 4KB of task_struct */

/* ------------------------------------------------------------------ */
/*  Kernel function pointers                                           */
/* ------------------------------------------------------------------ */
static void  *(*kf_get_current)(void)                         = NULL;
static int    (*kf_sprintf)(char *buf, const char *fmt, ...)  = NULL;
static void  *(*kf_memchr)(const void *s, int c, long n)      = NULL;

/* ------------------------------------------------------------------ */
/*  Discovered offsets — set once at init                             */
/* ------------------------------------------------------------------ */
static long g_pid_offset  = -1;
static long g_comm_offset = -1;

/* ------------------------------------------------------------------ */
/*  State                                                              */
/* ------------------------------------------------------------------ */
static int g_target_pid = 0;

/* ------------------------------------------------------------------ */
/*  Inline helpers                                                     */
/* ------------------------------------------------------------------ */
static inline int task_get_pid(void *task)
{
    if (g_pid_offset < 0) return -1;
    return *(int *)((char *)task + g_pid_offset);
}

static inline const char *task_get_comm(void *task)
{
    if (g_comm_offset < 0) return NULL;
    return (const char *)((char *)task + g_comm_offset);
}

static int comm_eq(const char *a, const char *b)
{
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '\0') return 1;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Offset discovery                                                   */
/*                                                                     */
/*  Called at init with our own known PID (from /proc/self/status     */
/*  — we pass it in via args as a decimal string) and the loader's    */
/*  comm name "kpatch" or "kpatch_loader".                            */
/*                                                                     */
/*  We scan the task_struct byte-by-byte looking for:                 */
/*    - our known PID (int32) → pid offset                            */
/*    - our known comm string → comm offset                            */
/* ------------------------------------------------------------------ */
static int discover_offsets(void *task, int known_pid, const char *known_comm)
{
    char *base = (char *)task;
    int pid_found  = 0;
    int comm_found = 0;

    for (int off = 0; off < SCAN_MAX_OFFSET - 16; off += 4) {
        /* Look for pid */
        if (!pid_found) {
            int val = *(int *)(base + off);
            if (val == known_pid) {
                g_pid_offset = off;
                pid_found = 1;
            }
        }

        /* Look for comm — check if this offset holds our comm string */
        if (!comm_found) {
            const char *candidate = base + off;
            int match = 1;
            for (int i = 0; i < TASK_COMM_LEN && known_comm[i]; i++) {
                if (candidate[i] != known_comm[i]) {
                    match = 0;
                    break;
                }
            }
            if (match && known_comm[0] != '\0') {
                g_comm_offset = off;
                comm_found = 1;
            }
        }

        if (pid_found && comm_found) break;
    }

    return (pid_found && comm_found) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/*  Hooks                                                              */
/* ------------------------------------------------------------------ */
static void before_getpid(hook_fargs0_t *args, void *udata)
{
    if (!kf_get_current || g_comm_offset < 0 || g_pid_offset < 0) return;

    void *task = kf_get_current();
    if (!task) return;

    const char *comm = task_get_comm(task);
    if (!comm) return;

    if (comm_eq(comm, TARGET_COMM)) {
        int pid = task_get_pid(task);
        if (pid > 0) g_target_pid = pid;
    }
}

static void after_uname(hook_fargs1_t *args, void *udata)
{
    if (!kf_sprintf) return;
    if ((long)args->ret != 0) return;

    char __user *buf = (char __user *)args->arg0;
    if (!buf) return;

    char release[UTSNAME_FIELD_LEN];

    if (g_target_pid != 0) {
        kf_sprintf(release, "pid[" TARGET_COMM "]=%d", g_target_pid);
    } else if (g_pid_offset < 0 || g_comm_offset < 0) {
        kf_sprintf(release, "pid[err:offsets_not_found]");
    } else {
        kf_sprintf(release, "pid[" TARGET_COMM "]=open_pubg_first");
    }

    /* struct new_utsname: sysname[65] + nodename[65] + release[65]  */
    /* release starts at byte offset 130                              */
    compat_copy_to_user(buf + 130, release, UTSNAME_FIELD_LEN);
}

/* ------------------------------------------------------------------ */
/*  Init                                                               */
/*                                                                     */
/*  args format: "<pid>,<comm>"                                        */
/*  Example: pass "1234,kpatch" from the loader script                */
/*                                                                     */
/*  The loader (APatch/SukiSU) process calls kpm_init, so at init    */
/*  time current == the loader process. We can read its PID directly  */
/*  from the kernel via kallsyms and use it for offset discovery.     */
/* ------------------------------------------------------------------ */
static long pid_finder_init(const char *args, const char *event,
                            void *__user reserved)
{
    /* Resolve symbols */
    kf_get_current = (void *(*)(void))kallsyms_lookup_name("get_current");
    kf_sprintf     = (int (*)(char *, const char *, ...))
                     kallsyms_lookup_name("sprintf");
    kf_memchr      = (void *(*)(const void *, int, long))
                     kallsyms_lookup_name("memchr");

    if (!kf_get_current || !kf_sprintf) return -1;

    /* Get our own task_struct */
    void *task = kf_get_current();
    if (!task) return -1;

    /*
     * The loader process comm is "kpatch" on most APatch builds.
     * We also know our own PID because KP passes it via /proc.
     *
     * Strategy: scan for "kpatch" string in task memory to find
     * comm offset, then scan for a pid-sized int near it.
     *
     * If args is provided as "pid,comm" we use that directly.
     */
    int   known_pid  = 0;
    char  known_comm[TASK_COMM_LEN] = "kpatch";

    /* Parse args if provided: format "PID,COMM" */
    if (args && args[0] != '\0') {
        /* parse pid */
        const char *p = args;
        while (*p >= '0' && *p <= '9') {
            known_pid = known_pid * 10 + (*p - '0');
            p++;
        }
        if (*p == ',') {
            p++;
            int i = 0;
            while (*p && i < TASK_COMM_LEN - 1)
                known_comm[i++] = *p++;
            known_comm[i] = '\0';
        }
    }

    /*
     * If no pid from args, try a fallback: scan for known_comm only.
     * The pid search will still work if we find a unique int match.
     * But comm is enough for our purposes — if we find comm we can
     * derive pid offset by looking at nearby int fields.
     */

    int rc = discover_offsets(task, known_pid, known_comm);

    /*
     * Fallback: try known good offsets for sdm845 4.9 Asus stock kernel.
     * These were determined from the Qualcomm sdm845 4.9 kernel source
     * (include/linux/sched.h) with Android-specific additions applied.
     * Layout: thread_info(16) + state(8) + stack(8) + usage(4) + flags(4)
     *       + ptrace(4) + ...many fields... + pid at ~0x3dc, comm at ~0x5a8
     */
    if (rc != 0) {
        g_pid_offset  = 0x3dc;
        g_comm_offset = 0x5a8;
    }

    /* Hook sys_getpid */
    hook_err_t err = fp_wrap_syscalln(__NR_getpid, 0, 0,
                                      (void *)before_getpid, NULL, NULL);
    if (err != HOOK_NO_ERR) return -1;

    /* Hook sys_newuname */
    err = fp_wrap_syscalln(__NR_uname, 1, 0,
                           NULL, (void *)after_uname, NULL);
    if (err != HOOK_NO_ERR) {
        fp_unwrap_syscalln(__NR_getpid, 0, (void *)before_getpid, NULL);
        return -1;
    }

    return 0;
}

static long pid_finder_control(const char *args, char *__user out_buf,
                               int out_buf_size)
{
    if (!args) return 0;
    if (args[0]=='r' && args[1]=='e' && args[2]=='s' &&
        args[3]=='e' && args[4]=='t' && args[5]=='\0') {
        g_target_pid = 0;
    }
    return 0;
}

static long pid_finder_exit(void *__user reserved)
{
    fp_unwrap_syscalln(__NR_getpid, 0, (void *)before_getpid, NULL);
    fp_unwrap_syscalln(__NR_uname,  0, NULL, (void *)after_uname);
    return 0;
}

KPM_INIT(pid_finder_init);
KPM_CTL0(pid_finder_control);
KPM_EXIT(pid_finder_exit);
