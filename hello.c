#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>

KPM_NAME("pid-finder");
KPM_VERSION("1.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Find PUBG PID and show via uname -r");
KPM_LICENSE("GPL v2");

/* ── Same structs as working spoofer ─────────────────────────────── */
struct new_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct uts_namespace {
    int kref;
    struct new_utsname name;
};

/* ── State ───────────────────────────────────────────────────────── */
static struct uts_namespace *g_uts        = NULL;
static void                 *g_init_task  = NULL;
static int  g_pid_offset                  = -1;
static int  g_comm_offset                 = -1;
static int  g_tasks_offset                = -1;

#define TARGET_COMM    "MainThread-UE4"
#define TASK_COMM_LEN  16
#define SCAN_LIMIT     0xC00

/* ── Discover offsets from init_task (PID=1, comm="init") ────────── */
static void discover_offsets(void)
{
    char *base = (char *)g_init_task;

    for (int off = 0; off < SCAN_LIMIT; off += 4) {

        /* pid == 1 */
        if (g_pid_offset == -1 && *(int *)(base + off) == 1)
            g_pid_offset = off;

        /* comm == "init\0" — byte by byte, no alignment assumption */
        if (g_comm_offset == -1) {
            char *c = base + off;
            if (c[0]=='i' && c[1]=='n' && c[2]=='i' &&
                c[3]=='t' && c[4]=='\0')
                g_comm_offset = off;
        }

        /* tasks list_head at 8-byte aligned offsets only.
         * Verify circular list: lh->next->prev == lh             */
        if (g_tasks_offset == -1 && (off % 8) == 0) {
            struct list_head *lh = (struct list_head *)(base + off);
            unsigned long nx = (unsigned long)lh->next;
            if ((nx >> 56) == 0xff) {
                unsigned long back = (unsigned long)lh->next->prev;
                if (back == (unsigned long)lh)
                    g_tasks_offset = off;
            }
        }

        if (g_pid_offset  != -1 && g_comm_offset  != -1 &&
            g_tasks_offset != -1) break;
    }
}

/* ── Task accessors ──────────────────────────────────────────────── */
static inline int task_pid(void *task)
{
    return *(int *)((char *)task + g_pid_offset);
}

static inline const char *task_comm(void *task)
{
    return (const char *)((char *)task + g_comm_offset);
}

static inline struct list_head *task_tasks(void *task)
{
    return (struct list_head *)((char *)task + g_tasks_offset);
}

static inline void *task_from_tasks(struct list_head *node)
{
    return (void *)((char *)node - g_tasks_offset);
}

/* ── Comm comparison ─────────────────────────────────────────────── */
static int comm_eq(const char *a, const char *b)
{
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '\0') return 1;
    }
    return 1;
}

/* ── Walk task list ──────────────────────────────────────────────── */
static int find_pubg_pid(void)
{
    if (g_tasks_offset < 0 || g_pid_offset < 0 || g_comm_offset < 0)
        return 0;

    struct list_head *start = task_tasks(g_init_task);
    struct list_head *cur   = start->next;
    int limit = 2048;

    while (cur != start && limit-- > 0) {
        if (((unsigned long)cur >> 56) != 0xff) break;
        void *task = task_from_tasks(cur);
        if (comm_eq(task_comm(task), TARGET_COMM))
            return task_pid(task);
        cur = cur->next;
    }
    return 0;
}

/* ── itoa ────────────────────────────────────────────────────────── */
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

/* ── Write result ────────────────────────────────────────────────── */
static void write_result(int pid)
{
    if (!g_uts) return;
    char buf[65];
    char num[12];

    if (pid > 0) {
        itoa(pid, num, sizeof(num));
        strncpy(buf, "pubg_pid=", 64);
        strncat(buf, num, 64 - strlen(buf));
    } else if (g_tasks_offset < 0) {
        strncpy(buf, "pid[err:tasks_not_found]", 64);
    } else if (g_pid_offset < 0) {
        strncpy(buf, "pid[err:pid_off_bad]", 64);
    } else if (g_comm_offset < 0) {
        strncpy(buf, "pid[err:comm_off_bad]", 64);
    } else {
        strncpy(buf, "pubg_pid=open_pubg_first", 64);
    }
    buf[64] = '\0';
    strncpy(g_uts->name.release, buf, 65);
}

/* ── KPM lifecycle ───────────────────────────────────────────────── */
static long pid_finder_init(const char *args, const char *event,
                            void *__user reserved)
{
    /* 1. UTS — identical to working spoofer */
    g_uts = (struct uts_namespace *)kallsyms_lookup_name("init_uts_ns");
    if (!g_uts) return -1;
    if (g_uts->name.sysname[0] != 'L') {
        g_uts = (struct uts_namespace *)((char *)g_uts - 4);
        if (g_uts->name.sysname[0] != 'L') return -1;
    }

    /* 2. Get init_task */
    g_init_task = (void *)kallsyms_lookup_name("init_task");
    if (!g_init_task) {
        strncpy(g_uts->name.release, "pid[err:no_init_task]", 65);
        return 0;
    }

    /* 3. Discover offsets from init_task (PID=1, comm="init") */
    discover_offsets();

    /* 4. Verify — init_task must read back PID=1 */
    if (g_pid_offset >= 0 && task_pid(g_init_task) != 1) {
        g_pid_offset = -1; /* reject bad match */
    }

    /* 5. Find PUBG */
    int pid = find_pubg_pid();
    write_result(pid);
    return 0;
}

static long pid_finder_control(const char *args, char *__user out_buf,
                               int out_buf_size)
{
    int pid = find_pubg_pid();
    write_result(pid);
    return 0;
}

static long pid_finder_exit(void *__user reserved)
{
    if (g_uts)
        strncpy(g_uts->name.release, "4.9.186-perf+", 65);
    return 0;
}

KPM_INIT(pid_finder_init);
KPM_CTL0(pid_finder_control);
KPM_EXIT(pid_finder_exit);
