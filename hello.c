#include <compiler.h>
#include <kpmodule.h>
#include <ksyms.h>
#include <linux/sched.h>
#include <linux/string.h>

KPM_NAME("pid-finder");
KPM_VERSION("1.0.0");
KPM_AUTHOR("ZenfoneDev");
KPM_DESCRIPTION("Find PUBG PID and show via uname -r");
KPM_LICENSE("GPL v2");

/* ── UTS structs — same as working spoofer ───────────────────────── */
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

/* ── kvar_def for init_task — must be declared before use ────────── */
struct task_struct *kvar_def(init_task);

/* ── kfunc_def for task_pid_vnr — not in string.h so safe ──────── */
pid_t kfunc_def(task_pid_vnr)(struct task_struct *tsk);

/* ── UTS pointer ─────────────────────────────────────────────────── */
static struct uts_namespace *g_uts = NULL;

#define TARGET_COMM   "MainThread-UE4"
#define TASK_COMM_LEN 16

/* ── itoa ────────────────────────────────────────────────────────── */
static void itoa(int n, char *out, int sz)
{
    if (n <= 0) { out[0]='0'; out[1]='\0'; return; }
    char tmp[12]; int i = 0;
    while (n > 0) { tmp[i++]='0'+(n%10); n/=10; }
    for (int a=0,b=i-1; a<b; a++,b--)
        { char t=tmp[a]; tmp[a]=tmp[b]; tmp[b]=t; }
    tmp[i]='\0';
    for (int j=0; j<=i && j<sz-1; j++) out[j]=tmp[j];
    out[i<sz?i:sz-1]='\0';
}

/* ── Walk task list ──────────────────────────────────────────────── */
static int find_pubg_pid(void)
{
    if (tasklist_empty()) return 0;

    struct task_struct *init = kvar(init_task);
    if (!init) return 0;

    struct task_struct *task = init;
    do {
        /*
         * get_task_comm() is KP's safe accessor for task->comm.
         * It copies the comm into a local buffer safely.
         */
        char comm[TASK_COMM_LEN + 1];
        get_task_comm(comm, task);

        int match = 1;
        for (int i = 0; i < TASK_COMM_LEN; i++) {
            if (comm[i] != TARGET_COMM[i]) { match = 0; break; }
            if (comm[i] == '\0') break;
        }

        if (match) {
            pid_t pid = kfunc(task_pid_vnr)(task);
            return (int)pid;
        }

        task = next_task(task);
    } while (task != init);

    return 0;
}

/* ── Write result ────────────────────────────────────────────────── */
static void write_result(int pid)
{
    if (!g_uts) return;
    char buf[65];
    char num[12];
    int i = 0;

    if (pid > 0) {
        itoa(pid, num, sizeof(num));
        const char *prefix = "pubg_pid=";
        while (prefix[i] && i < 63) { buf[i] = prefix[i]; i++; }
        int j = 0;
        while (num[j] && i < 63) { buf[i++] = num[j++]; }
        buf[i] = '\0';
    } else {
        const char *msg = "pubg_pid=open_pubg_first";
        while (msg[i] && i < 64) { buf[i] = msg[i]; i++; }
        buf[i] = '\0';
    }

    for (i = 0; i < 65; i++) {
        g_uts->name.release[i] = buf[i];
        if (buf[i] == '\0') break;
    }
}

/* ── KPM lifecycle ───────────────────────────────────────────────── */
static long pid_finder_init(const char *args, const char *event,
                            void *__user reserved)
{
    /* 1. UTS — same as working spoofer */
    g_uts = (struct uts_namespace *)kallsyms_lookup_name("init_uts_ns");
    if (!g_uts) return -1;
    if (g_uts->name.sysname[0] != 'L') {
        g_uts = (struct uts_namespace *)((char *)g_uts - 4);
        if (g_uts->name.sysname[0] != 'L') return -1;
    }

    /* 2. Resolve init_task and task_pid_vnr */
    kvar_lookup_name(init_task);
    kfunc_lookup_name(task_pid_vnr);

    if (!kvar(init_task)) {
        strncpy(g_uts->name.release, "pid[err:no_init_task]", 65);
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
    if (!g_uts) return 0;
    const char *orig = "4.9.186-perf+";
    for (int i = 0; i < 65; i++) {
        g_uts->name.release[i] = orig[i];
        if (orig[i] == '\0') break;
    }
    return 0;
}

KPM_INIT(pid_finder_init);
KPM_CTL0(pid_finder_control);
KPM_EXIT(pid_finder_exit);
