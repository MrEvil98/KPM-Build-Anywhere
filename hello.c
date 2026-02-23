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

/* ── Kernel function pointers ────────────────────────────────────── */
static struct task_struct *(*kf_find_task_by_vpid)(pid_t nr)        = NULL;
static void               *(*kf_get_task_mm)(struct task_struct *t) = NULL;
static void                (*kf_mmput)(void *mm)                    = NULL;

/* ── UTS namespace pointer ───────────────────────────────────────── */
static struct uts_namespace *g_uts = NULL;

/* ── mm_struct->arg_start offset on 4.9 arm64 ───────────────────── */
#define MM_ARG_START  0x1d8
#define MM_ARG_END    0x1e0

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

/* ── Read process cmdline from mm->arg_start ─────────────────────── */
static int read_cmdline(struct task_struct *task, char *buf, int sz)
{
    if (!kf_get_task_mm) return 0;
    void *mm = kf_get_task_mm(task);
    if (!mm) return 0;

    unsigned long arg_start = *(unsigned long *)((char *)mm + MM_ARG_START);
    unsigned long arg_end   = *(unsigned long *)((char *)mm + MM_ARG_END);

    if (!arg_start || arg_end <= arg_start) {
        if (kf_mmput) kf_mmput(mm);
        return 0;
    }

    int len = (int)(arg_end - arg_start);
    if (len >= sz) len = sz - 1;

    char *src = (char *)arg_start;
    int i;
    for (i = 0; i < len; i++) {
        buf[i] = src[i];
        if (src[i] == '\0') break;
    }
    buf[i] = '\0';

    if (kf_mmput) kf_mmput(mm);
    return i;
}

/* ── Find PUBG by iterating PIDs ─────────────────────────────────── */
static int find_pubg_pid(void)
{
    if (!kf_find_task_by_vpid) return 0;

    const char *pkg = "com.pubg.imobile";
    int pkglen = 16;

    for (int pid = 100; pid < 32768; pid++) {
        struct task_struct *task = kf_find_task_by_vpid(pid);
        if (!task) continue;

        char cmdline[256];
        int len = read_cmdline(task, cmdline, sizeof(cmdline));
        if (len < pkglen) continue;

        int match = 1;
        for (int i = 0; i < pkglen; i++) {
            if (cmdline[i] != pkg[i]) { match = 0; break; }
        }
        if (match) return pid;
    }
    return 0;
}

/* ── Write result into utsname.release ───────────────────────────── */
static void write_result(int pid)
{
    if (!g_uts) return;
    char buf[65];
    char num[12];

    if (pid > 0) {
        itoa(pid, num, sizeof(num));
        strncpy(buf, "pubg_pid=", 64);
        strncat(buf, num, 64 - strlen(buf));
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
    /* 1. Get UTS — identical to working spoofer */
    g_uts = (struct uts_namespace *)kallsyms_lookup_name("init_uts_ns");
    if (!g_uts) return -1;

    if (g_uts->name.sysname[0] != 'L') {
        g_uts = (struct uts_namespace *)((char *)g_uts - 4);
        if (g_uts->name.sysname[0] != 'L') return -1;
    }

    /* 2. Resolve task functions */
    kf_find_task_by_vpid = (struct task_struct *(*)(pid_t))
                            kallsyms_lookup_name("find_task_by_vpid");
    kf_get_task_mm       = (void *(*)(struct task_struct *))
                            kallsyms_lookup_name("get_task_mm");
    kf_mmput             = (void (*)(void *))
                            kallsyms_lookup_name("mmput");

    if (!kf_find_task_by_vpid) {
        strncpy(g_uts->name.release, "pid[err:no_find_task]", 65);
        return 0;
    }

    /* 3. Find PUBG */
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
