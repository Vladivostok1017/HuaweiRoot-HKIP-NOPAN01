package com.l5.root;

import android.app.Activity;
import android.content.ComponentName;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.IBinder;

import rikka.shizuku.Shizuku;

/*
 * Client side of Shizuku (official API 13.1.5 jars in app/libs).
 *
 * What this gives us: a privileged process maintained by Shizuku.  We put
 * RootExecService inside it once, then every command is a single binder call --
 * milliseconds, versus the ~0.5 s the file mailbox costs.
 *
 * Two activation levels, decided by whoever started Shizuku:
 *   uid 2000  -> adb-level: pm/am/settings/appops, but no /data/misc, no mount
 *   uid 0     -> root-level: same domain limits as our own gate (shell), i.e. the
 *                maximum this device allows
 *
 * Everything is a state query; nothing here patches anything.
 */
public final class ShizukuBridge {

    private static final int REQ_PERM = 1001;

    private static volatile String lastText = "Shizuku 检测中…";
    private static volatile boolean ready;
    private static volatile int lastUid = -1;

    private static boolean inited;
    private static IRootExec exec;

    private ShizukuBridge() {
    }

    public static String text() {
        return lastText;
    }

    public static boolean ready() {
        return ready;
    }

    public static int uid() {
        return lastUid;
    }

    /** Call once, from the activity. */
    public static void init(final Activity a) {
        if (inited) {
            refresh();
            return;
        }
        inited = true;
        try {
            Shizuku.addBinderReceivedListenerSticky(new Shizuku.OnBinderReceivedListener() {
                public void onBinderReceived() {
                    refresh();
                }
            });
            Shizuku.addBinderDeadListener(new Shizuku.OnBinderDeadListener() {
                public void onBinderDead() {
                    ready = false;
                    exec = null;
                    lastText = "Shizuku 未运行";
                }
            });
            if (Build.VERSION.SDK_INT >= 23) {
                Shizuku.addRequestPermissionResultListener(
                        new Shizuku.OnRequestPermissionResultListener() {
                            public void onRequestPermissionResult(int code, int result) {
                                refresh();
                            }
                        });
            }
        } catch (Throwable t) {
            lastText = "Shizuku 库不可用: " + t;
            return;
        }
        refresh();
    }

    /** Re-read the server state (ping / uid / version / permission). */
    public static void refresh() {
        try {
            if (!Shizuku.pingBinder()) {
                ready = false;
                lastUid = -1;
                lastText = "Shizuku 未运行";
                return;
            }
            ready = true;
            lastUid = Shizuku.getUid();
            int ver = Shizuku.getVersion();
            boolean perm = Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
            String ctx = "";
            try {
                ctx = Shizuku.getSELinuxContext();
            } catch (Throwable ignored) {
                // optional
            }
            lastText = "v" + ver + "  uid=" + lastUid + "  "
                    + (perm ? "已授权" : "未授权") + (ctx == null || ctx.isEmpty() ? "" : "  " + ctx);
        } catch (Throwable t) {
            ready = false;
            lastText = "查询失败: " + t;
        }
    }

    /** Ask the Shizuku manager for permission (shows its own dialog). */
    public static void requestPermission(Activity a) {
        try {
            if (!Shizuku.pingBinder()) {
                lastText = "Shizuku 未运行";
                return;
            }
            if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                lastText = "已授权";
                return;
            }
            Shizuku.requestPermission(REQ_PERM);
        } catch (Throwable t) {
            lastText = "请求授权失败: " + t;
        }
    }

    private static final ServiceConnection CONN = new ServiceConnection() {
        public void onServiceConnected(ComponentName name, IBinder service) {
            exec = IRootExec.Stub.asInterface(service);
            try {
                lastText = "服务已连接  uid=" + exec.uid() + "  " + exec.secontext();
            } catch (Throwable t) {
                lastText = "服务已连接（查询失败: " + t + "）";
            }
        }

        public void onServiceDisconnected(ComponentName name) {
            exec = null;
        }
    };

    private static Shizuku.UserServiceArgs args(String pkg) {
        return new Shizuku.UserServiceArgs(
                new ComponentName(pkg, RootExecService.class.getName()))
                .processNameSuffix("root")
                .version(1)
                .debuggable(false)
                .daemon(false);
    }

    /** Start the privileged helper inside Shizuku's process. */
    public static void bind(Activity a) {
        try {
            if (!Shizuku.pingBinder()) {
                lastText = "Shizuku 未运行";
                return;
            }
            if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                lastText = "未授权，先请求权限";
                return;
            }
            // A stale entry from a previous start must be dropped, otherwise the
            // server keeps the old process (same package/tag/version).
            try {
                Shizuku.unbindUserService(args(a.getPackageName()), CONN, true);
            } catch (Throwable ignored) {
                // nothing was bound
            }
            Shizuku.bindUserService(args(a.getPackageName()), CONN);
            lastText = "正在绑定特权服务…";
        } catch (Throwable t) {
            lastText = "绑定失败: " + t;
        }
    }

    public static void unbind(Activity a) {
        try {
            Shizuku.unbindUserService(args(a.getPackageName()), CONN, true);
            exec = null;
            lastText = "已解绑";
        } catch (Throwable t) {
            lastText = "解绑失败: " + t;
        }
    }

    /** True when the privileged helper is callable. */
    public static boolean serviceReady() {
        return exec != null;
    }

    /** Fast path: one binder call instead of the file mailbox. */
    public static String exec(String cmd) {
        IRootExec e = exec;
        if (e == null) {
            return null;
        }
        try {
            return e.exec(cmd);
        } catch (Throwable t) {
            return "binder 调用失败: " + t;
        }
    }
}
