// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * pid_finder.c — KPM module for Asus Zenfone 5z (kernel 4.9.186, sdm845)
 *
 * Approach: scan a wide range of kernel memory around the known UTS area
 * for the string "4.9.186-perf+" to find the exact release field pointer.
 * Then scan init_task memory for PID=1 and "init\0" to find offsets.
 * Uses the circular list property to find tasks offset reliably.
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
/*  VERIFIED ADDRESSES                                                 */
/* ------------------------------------------------------------------ */
#define INIT_TASK_ADDR  0xffffff966fa21200UL

/*
 * Scan a 64KB window around the known UTS area for "4.9.186-perf+"
 * Wide enough to catch it regardless of exact struct padding.
 */
#define UTS_SCAN_BASE   0xffffff966fa10000UL
#define UTS_SCAN_SIZE   0x20000UL            /* 128KB scan window */

#define TARGET_COMM     "MainThread-UE4"
#define TASK_COMM_LEN   16
#define TASK_SCAN_LIMIT 0xC00               /* scan 3KB of task_struct */
#define UTS_FIELD_LEN   65

/* ------------------------------------------------------------------ */
/*  State                                                              */
/* ------------------------------------------------------------------ */
static int   g_pid_offset   = -1;
static int   g_comm_offset  = -1;
static int   g_tasks_offset = -1;
static char *g_release_ptr  = NULL;
static int   g_target_pid   = 0;

/* ------------------------------------------------------------------ */
/*  Step 1: Find UTS release field                                    */
/*  Scan wide kernel memory window for the known release string.      */
/*  This bypasses all struct layout uncertainty completely.           */
/* ------------------------------------------------------------------ */
static char *find_release_field(void)
{
    const char needle[] = "4.9.186-perf+";
    const int  nlen     = sizeof(needle) - 1;
    char *base = (char *)UTS_SCAN_BASE;

    for (unsigned long i = 0; i < UTS_SCAN_SIZE - nlen; i++) {
        /* Quick first-char check before full compare */
        if (base[i] != '4') continue;
        int ok = 1;
        for (int j = 1; j < nlen; j++) {
            if (base[i+j] != needle[j]) { ok = 0; break; }
        }
        if (ok) return base + i;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Step 2: Discover task_struct offsets from init_task               */
/*  init_task is known: PID=1, comm="init"                           */
/* ------------------------------------------------------------------ */
static void discover_offsets(void)
{
    char *base = (char *)INIT_TASK_ADDR;
    int   pid_candidates[8];
    int   pid_count = 0;

    /*
     * First pass: collect ALL offsets where int==1 appears.
     * We'll cross-reference with comm to pick the right one.
     */
    for (int off = 0; off < TASK_SCAN_LIMIT && pid_count < 8; off += 4) {
        if (*(int *)(base + off) == 1)
            pid_candidates[pid_count++] = off;
    }

    /* Second pass: find comm "init\0" */
    for (int off = 0; off < TASK_SCAN_LIMIT; off += 1) {
        char *c = base + off;
        if (c[0]=='i' && c[1]=='n' && c[2]=='i' &&
            c[3]=='t' && c[4]=='\0') {
            g_comm_offset = off;
            break;
        }
    }

    /*
     * Pick pid_offset: the one that is closest to comm_offset
     * but BEFORE it — pid typically comes before comm in task_struct.
     * On 4.9 arm64: pid is at a lower offset than comm.
     */
    if (g_comm_offset > 0 && pid_count > 0) {
        int best = -1;
        int best_dist = 0x10000;
        for (int i = 0; i < pid_count; i++) {
            int dist = g_comm_offset - pid_candidates[i];
            if (dist > 0 && dist < best_dist) {
                best_dist = dist;
                best = pid_candidates[i];
            }
        }
        if (best >= 0) g_pid_offset = best;
        else g_pid_offset = pid_candidates[0]; /* fallback: first match */
    } else if (pid_count > 0) {
        g_pid_offset = pid_candidates[0];
    }

    /*
     * Find tasks list_head using circular list property:
     * lh->next->prev == lh
     * Scan only at 8-byte aligned offsets (pointer size on arm64).
     */
    for (int off = 0; off < TASK_SCAN_LIMIT; off += 8) {
        struct list_head *lh = (struct list_head *)(base + off);
        unsigned long nx = (unsigned long)lh->next;

        /* Must be a kernel pointer */
        if ((nx >> 56) != 0xff) continue;

        /* Follow next, check its prev == lh */
        struct list_head *nxt = lh->next;
        unsigned long back = (unsigned long)nxt->prev;
        if (back == (unsigned long)lh) {
            g_tasks_offset = off;
            break;
        }
    }

    /* Hardcoded fallbacks for sdm845 4.9 Asus stock */
    if (g_pid_offset   < 0) g_pid_offset   = 0x3d0;
    if (g_comm_offset  < 0) g_comm_offset  = 0x5b8;
    if (g_tasks_offset < 0) g_tasks_offset = 0x2c0;
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
/*  Walk task list to find TARGET_COMM                                */
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
static void itoa(int n, char *out, int sz)
{
    if (n <= 0) { out[0]='0'; out[1]='\0'; return; }
    char tmp[12]; int i = 0;
    while (n > 0) { tmp[i++]='0'+(n%10); n/=10; }
    for (int a=0,b=i-1; a<b; a++,b--)
        { char t=tmp[a]; tmp[a]=tmp[b]; tmp[b]=t; }
    tmp[i]='\0';
    strncpy(out, tmp, sz);
}

/* ------------------------------------------------------------------ */
/*  Write result to utsname release field                             */
/* ------------------------------------------------------------------ */
static void write_result(int pid)
{
    if (!g_release_ptr) return;
    char buf[UTS_FIELD_LEN];
    char num[12];

    if (pid > 0) {
        itoa(pid, num, sizeof(num));
        strncpy(buf, "pid[" TARGET_COMM "]=", UTS_FIELD_LEN-1);
        strncat(buf, num, UTS_FIELD_LEN - strlen(buf) - 1);
    } else {
        strncpy(buf, "pid[" TARGET_COMM "]=open_pubg", UTS_FIELD_LEN-1);
    }
    buf[UTS_FIELD_LEN-1] = '\0';
    strncpy(g_release_ptr, buf, UTS_FIELD_LEN);
}

/* ------------------------------------------------------------------ */
/*  KPM lifecycle                                                      */
/* ------------------------------------------------------------------ */
static long pid_finder_init(const char *args, const char *event,
                            void *__user reserved)
{
    /* 1. Find the exact UTS release field by string scan */
    g_release_ptr = find_release_field();
    if (!g_release_ptr) {
        /* Nothing we can do without a write target — bail silently */
        return 0;
    }

    /* 2. Discover task_struct offsets from init_task */
    discover_offsets();

    /* 3. Verify — read back PID and comm from init_task */
    void *init = (void *)INIT_TASK_ADDR;
    int   check_pid  = task_get_pid(init);
    const char *check_comm = task_get_comm(init);

    if (check_pid != 1) {
        strncpy(g_release_ptr, "pid[err:pid_off_wrong]", UTS_FIELD_LEN);
        return 0;
    }
    if (check_comm[0]!='i' || check_comm[1]!='n') {
        strncpy(g_release_ptr, "pid[err:comm_off_wrong]", UTS_FIELD_LEN);
        return 0;
    }
    if (g_tasks_offset < 0) {
        strncpy(g_release_ptr, "pid[err:tasks_not_found]", UTS_FIELD_LEN);
        return 0;
    }

    /* 4. Try to find PUBG now (open it first, then reload if not found) */
    int pid = find_target_pid();
    write_result(pid);
    return 0;
}

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
