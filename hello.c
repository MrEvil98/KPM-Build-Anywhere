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

/* ── KP proper API for kernel functions ──────────────────────────── */
kfunc_def(strncpy);
kfunc_def(strncat);
kfunc_def(strlen);
kfunc_def(strncmp);
kfunc_def(task_pid_vnr);   /* pid_t task_pid_vnr(struct task_struct *) */

/* ── UTS namespace pointer ───────────────────────────────────────── */
static struct uts_namespace *g_uts = NULL;

/* ── Target ──────────────────────────────────────────────────────── */
#define TARGET_COMM  "MainThread-UE4"
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
    /* plain assignment loop — no kfunc needed for local copy */
    for (int j=0; j<=i && j<sz-1; j++) out[j]=tmp[j];
    out[i<sz?i:sz-1]='\0';
}

/* ── Walk task list using KP's proper API ────────────────────────── */
static int find_pubg_pid(void)
{
    /*
     * KP provides get_task_tasks_p(task) which returns the list_head*
     * for any task_struct — no offset knowledge needed.
     * tasklist_empty() checks if the list is empty.
     * next_task(task) walks to the next task in the list.
     */
    if (tasklist_empty()) return 0;

    struct task_struct *init = kvar(init_task);
    struct task_struct *task = init;

    /* Walk using KP's next_task macro */
    do {
        /* task->comm is accessible because KP's sched.h defines it */
        int match = 1;
        for (int i = 0; i < TASK_COMM_LEN; i++) {
            if (task->comm[i] != TARGET_COMM[i]) { match = 0; break; }
            if (task->comm[i] == '\0') break;
        }

        if (match) {
            /* Use KP's task_pid_vnr to get PID safely */
            pid_t pid = task_pid_vnr(task);
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

    if (pid > 0) {
        itoa(pid, num, sizeof(num));
        /* Use plain string ops on kernel buffers — no user copy needed */
        int i = 0;
        const char *prefix = "pubg_pid=";
        while (prefix[i] && i < 63) { buf[i] = prefix[i]; i++; }
        int j = 0;
        while (num[j] && i < 63) { buf[i++] = num[j++]; }
        buf[i] = '\0';
    } else {
        const char *msg = "pubg_pid=open_pubg_first";
        int i = 0;
        while (msg[i] && i < 64) { buf[i] = msg[i]; i++; }
        buf[i] = '\0';
    }

    /* Direct memory write — same as working spoofer */
    for (int i = 0; i < 65; i++) {
        g_uts->name.release[i] = buf[i];
        if (buf[i] == '\0') break;
    }
}

/* ── KPM lifecycle ───────────────────────────────────────────────── */
static long pid_finder_init(const char *args, const char *event,
                            void *__user reserved)
{
    /* 1. Resolve kfuncs using KP's proper API */
    kfunc_lookup_name(task_pid_vnr);

    /* 2. Resolve init_task and init_uts_ns via kvar */
    kvar_lookup_name(init_task);

    /* 3. UTS — same as working spoofer */
    g_uts = (struct uts_namespace *)kallsyms_lookup_name("init_uts_ns");
    if (!g_uts) return -1;
    if (g_uts->name.sysname[0] != 'L') {
        g_uts = (struct uts_namespace *)((char *)g_uts - 4);
        if (g_uts->name.sysname[0] != 'L') return -1;
    }

    /* 4. Find PUBG */
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
