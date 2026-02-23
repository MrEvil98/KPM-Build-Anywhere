// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * pid_finder.c — KPM module for Asus Zenfone 5z (kernel 4.9.186, sdm845)
 *
 * All addresses verified from /proc/kallsyms on this specific device.
 * UTS namespace is derived at runtime from init_nsproxy — survives reboots.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>

KPM_NAME("pid-finder");
KPM_VERSION("1.0.0");
KPM_AUTHOR("kpm-build-anywhere");
KPM_DESCRIPTION("Find PUBG PID and show via uname -r");
KPM_LICENSE("GPL v3");

/* ------------------------------------------------------------------ */
/*  VERIFIED ADDRESSES — Asus Zenfone 5z, kernel 4.9.186-perf+       */
/* ------------------------------------------------------------------ */
#define INIT_TASK_ADDR    0xffffff966fa21200UL
#define INIT_NSPROXY_ADDR 0xffffff966fa2f3b8UL

/*
 * struct nsproxy layout (kernel 4.9, arm64):
 *   +0x00  atomic_t count     (4 bytes)
 *   +0x04  padding            (4 bytes)
 *   +0x08  uts_namespace *    <-- we read this pointer
 *   +0x10  ipc_namespace *
 *   +0x18  mnt_namespace *
 *   +0x20  pid_namespace *
 *   +0x28  net *
 */
#define NSPROXY_UTS_OFFSET 0x08

/*
 * struct uts_namespace layout:
 *   +0x00  struct kref        (4 bytes)
 *   +0x04  padding            (4 bytes)
 *   +0x08  struct new_utsname name  <-- sysname[65], nodename[65], release[65]...
 *
 * release field is at: uts_namespace_ptr + 0x08 + 65 + 65 = uts_ptr + 0x8a
 */
#define UTS_NAME_OFFSET    0x08
#define UTS_RELEASE_OFFSET (0x08 + 65 + 65)  /* = 0x8a = 138 */
#define UTS_FIELD_LEN      65

#define TARGET_COMM        "MainThread-UE4"
#define TASK_COMM_LEN      16
#define SCAN_LIMIT         0x800

/* ------------------------------------------------------------------ */
/*  Structs                                                            */
/* ------------------------------------------------------------------ */
struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

/* ------------------------------------------------------------------ */
/*  Runtime-discovered task_struct offsets                            */
/* ------------------------------------------------------------------ */
static int g_pid_offset    = -1;
static int g_comm_offset   = -1;
static int g_tasks_offset  = -1;

/* Cached UTS release pointer — set once at init */
static char *g_release_ptr = NULL;

/* Found PID */
static int g_target_pid = 0;

/* ------------------------------------------------------------------ */
/*  Get UTS release field pointer from init_nsproxy                   */
/* ------------------------------------------------------------------ */
static char *get_uts_release_ptr(void)
{
    /* Read the uts_namespace pointer from nsproxy */
    void **nsproxy = (void **)INIT_NSPROXY_ADDR;
    void  *uts_ns  = *(void **)((char *)nsproxy + NSPROXY_UTS_OFFSET);

    if (!uts_ns || ((unsigned long)uts_ns >> 56) != 0xff)
        return NULL;

    return (char *)uts_ns + UTS_RELEASE_OFFSET;
}

/* ------------------------------------------------------------------ */
/*  Offset discovery using init_task (known: PID=1, comm="init")     */
/* ------------------------------------------------------------------ */
static void discover_offsets(void)
{
    char *base = (char *)INIT_TASK_ADDR;

    for (int off = 0; off < SCAN_LIMIT; off += 4) {

        /* pid: int == 1 */
        if (g_pid_offset == -1) {
            if (*(int *)(base + off) == 1)
                g_pid_offset = off;
        }

        /* comm: "init\0" */
        if (g_comm_offset == -1) {
            char *c = base + off;
            if (c[0]=='i' && c[1]=='n' && c[2]=='i' &&
                c[3]=='t' && c[4]=='\0')
                g_comm_offset = off;
        }

        /* tasks list_head: two consecutive kernel pointers */
        if (g_tasks_offset == -1) {
            struct list_head *lh = (struct list_head *)(base + off);
            unsigned long nx = (unsigned long)lh->next;
            unsigned long pv = (unsigned long)lh->prev;
            if ((nx >> 56) == 0xff && (pv >> 56) == 0xff &&
                nx != INIT_TASK_ADDR && pv != INIT_TASK_ADDR)
                g_tasks_offset = off;
        }

        if (g_pid_offset  != -1 && g_comm_offset != -1 &&
            g_tasks_offset != -1) break;
    }

    /* Fallback: known sdm845 4.9 offsets */
    if (g_pid_offset   == -1) g_pid_offset   = 0x3dc;
    if (g_comm_offset  == -1) g_comm_offset  = 0x5a8;
    if (g_tasks_offset == -1) g_tasks_offset = 0x298;
}

/* ------------------------------------------------------------------ */
/*  Task accessors                                                     */
/* ------------------------------------------------------------------ */
static inline int task_get_pid(void *task)
{
    return *(int *)((char *)task + g_pid_offset);
}

static inline const char *task_get_comm(void *task)
{
    return (const char *)((char *)task + g_comm_offset);
}

static inline struct list_head *task_get_tasks(void *task)
{
    return (struct list_head *)((char *)task + g_tasks_offset);
}

static inline void *task_from_tasks(struct list_head *node)
{
    return (void *)((char *)node - g_tasks_offset);
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
/*  Walk task list                                                     */
/* ------------------------------------------------------------------ */
static int find_target_pid(void)
{
    void *init = (void *)INIT_TASK_ADDR;
    struct list_head *start = task_get_tasks(init);
    struct list_head *cur   = start->next;
    int limit = 2048;

    while (cur != start && limit-- > 0) {
        if (((unsigned long)cur >> 56) != 0xff) break;
        void *task = task_from_tasks(cur);
        if (comm_eq(task_get_comm(task), TARGET_COMM))
            return task_get_pid(task);
        cur = cur->next;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  itoa                                                               */
/* ------------------------------------------------------------------ */
static void itoa(int n, char *out, int out_sz)
{
    if (n <= 0) { out[0]='0'; out[1]='\0'; return; }
    char tmp[12]; int i = 0;
    while (n > 0) { tmp[i++] = '0' + (n % 10); n /= 10; }
    for (int a=0,b=i-1; a<b; a++,b--)
        { char t=tmp[a]; tmp[a]=tmp[b]; tmp[b]=t; }
    tmp[i] = '\0';
    strncpy(out, tmp, out_sz);
}

/* ------------------------------------------------------------------ */
/*  Write result to uname release field                               */
/* ------------------------------------------------------------------ */
static void write_result(int pid)
{
    if (!g_release_ptr) return;

    char buf[UTS_FIELD_LEN];
    char num[12];

    if (pid > 0) {
        itoa(pid, num, sizeof(num));
        strncpy(buf, "pid[" TARGET_COMM "]=", UTS_FIELD_LEN - 1);
        strncat(buf, num, UTS_FIELD_LEN - strlen(buf) - 1);
    } else {
        strncpy(buf, "pid[" TARGET_COMM "]=open_pubg_first",
                UTS_FIELD_LEN - 1);
    }
    buf[UTS_FIELD_LEN - 1] = '\0';

    strncpy(g_release_ptr, buf, UTS_FIELD_LEN);
}

/* ------------------------------------------------------------------ */
/*  KPM lifecycle                                                      */
/* ------------------------------------------------------------------ */
static long pid_finder_init(const char *args, const char *event,
                            void *__user reserved)
{
    /* 1. Find UTS release pointer via nsproxy */
    g_release_ptr = get_uts_release_ptr();
    if (!g_release_ptr) {
        /* nsproxy read failed — fall back to hardcoded UTS address */
        /* release = uts_ns_base + 0x8a */
        g_release_ptr = (char *)(0xffffff966fa20fc0UL + UTS_RELEASE_OFFSET);
    }

    /* 2. Discover task_struct offsets from init_task */
    discover_offsets();

    /* 3. Verify offsets — init_task must read PID=1, comm starts with 'i' */
    void *init = (void *)INIT_TASK_ADDR;
    if (task_get_pid(init) != 1 || task_get_comm(init)[0] != 'i') {
        strncpy(g_release_ptr, "pid[err:bad_offsets]", UTS_FIELD_LEN);
        return 0;
    }

    /* 4. Try to find PUBG right now (probably not running at load time) */
    int pid = find_target_pid();
    write_result(pid);

    return 0;
}

/* kpatch -c pid-finder refresh  — call after opening PUBG */
static long pid_finder_control(const char *args, char *__user out_buf,
                               int out_buf_size)
{
    int pid = find_target_pid();
    write_result(pid);
    return 0;
}

static long pid_finder_exit(void *__user reserved)
{
    if (g_release_ptr)
        strncpy(g_release_ptr, "4.9.186-perf+", UTS_FIELD_LEN);
    return 0;
}

KPM_INIT(pid_finder_init);
KPM_CTL0(pid_finder_control);
KPM_EXIT(pid_finder_exit);
