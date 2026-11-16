package com.l5.root;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;

/*
 * The only channel another app can use on this device.
 *
 * Apps cannot talk to each other over unix sockets here (appdomain is allowed to
 * connect only tombstoned / logd / adbd / system_server) and cannot read another
 * app's /sdcard/Android/data, but Binder is allowed.  So a caller does:
 *
 *   Bundle r = getContentResolver().call(
 *           Uri.parse("content://com.l5.root.gateway"), "exec", "id", null);
 *   String out = r.getString("out");
 *
 * and this provider relays the command to the gate through the same file mailbox
 * the UI uses.  The caller gets the OUTPUT of a uid-0 command; its own process is
 * never touched.
 *
 * Methods:
 *   "ping"           -> Bundle{up:boolean}
 *   "exec" (arg=cmd) -> Bundle{code:0 成功 / -1 无会话, out:String}
 */
public class GatewayProvider extends ContentProvider {

    /** The gate handles exactly one request at a time: req.txt is compared
     *  verbatim and out.txt is truncated per request, so calls must serialize. */
    private static final Object LOCK = new Object();

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        noteCaller();
        Bundle b = new Bundle();
        if ("ping".equals(method)) {
            b.putBoolean("up", sessionUp());
            return b;
        }
        if (!"exec".equals(method)) {
            b.putInt("code", -2);
            b.putString("out", "unknown method: " + method);
            return b;
        }
        String cmd = (arg == null || arg.trim().isEmpty()) ? "id" : arg;
        String out = exec(cmd);
        b.putInt("code", out == null ? -1 : 0);
        b.putString("out", out == null
                ? "无会话（管理器未连接到 root 通道）" : out);
        return b;
    }

    /** Remember which app used the gateway; the home page counts distinct callers. */
    private void noteCaller() {
        try {
            int uid = android.os.Binder.getCallingUid();
            String name = String.valueOf(uid);
            try {
                String[] pkgs = getContext().getPackageManager().getPackagesForUid(uid);
                if (pkgs != null && pkgs.length > 0) {
                    name = pkgs[0];
                }
            } catch (Throwable ignored) {
                // keep the uid form
            }
            FileOutputStream fos = new FileOutputStream(new File(dir(), "callers.txt"), true);
            try {
                fos.write((name + "\n").getBytes("UTF-8"));
                fos.flush();
            } finally {
                fos.close();
            }
            android.util.Log.i("L5GW", "caller=" + name + " uid=" + uid);
        } catch (Throwable t) {
            android.util.Log.w("L5GW", "noteCaller failed: " + t);
        }
    }

    private boolean sessionUp() {
        String s = readAll(new File(dir(), "status.txt"));
        return s != null && (s.contains("session=up") || s.contains("srvroot=1"));
    }

    /** Queue one command and wait for the gate's answer. */
    private String exec(String cmd) {
        synchronized (LOCK) {
            File d = dir();
            // The gate truncates out.txt itself, but deleting first makes sure a
            // stale result can never be mistaken for this call's output.
            new File(d, "out.txt").delete();
            if (!write(new File(d, "cmd.txt"), cmd)) {
                return null;
            }
            // req.txt is compared verbatim by the gate, so the token must differ
            // every time; nanoTime is unique across both this provider and the UI.
            String token = "srvroot " + System.nanoTime();
            if (!write(new File(d, "req.txt"), token)) {
                return null;
            }
            for (int i = 0; i < 100; i++) {
                String s = readAll(new File(d, "out.txt"));
                if (s != null && s.trim().length() > 0) {
                    return s.trim();
                }
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    break;
                }
            }
            return null;
        }
    }

    private File dir() {
        File ext = getContext().getExternalFilesDir(null);
        File d = new File(ext, "l5");
        d.mkdirs();
        return d;
    }

    private static boolean write(File f, String text) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(f, false);
            fos.write((text + "\n").getBytes("UTF-8"));
            fos.flush();
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException ignored) {
                    // best effort
                }
            }
        }
    }

    private static String readAll(File f) {
        if (!f.exists()) {
            return null;
        }
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(f));
            StringBuilder sb = new StringBuilder();
            String ln;
            while ((ln = r.readLine()) != null) {
                sb.append(ln).append('\n');
            }
            return sb.toString();
        } catch (IOException e) {
            return null;
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (IOException ignored) {
                    // best effort
                }
            }
        }
    }

    // ---- unused ContentProvider surface -----------------------------------

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection,
                      String[] selectionArgs) {
        return 0;
    }
}
