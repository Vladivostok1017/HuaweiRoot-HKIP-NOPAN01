package com.l5.root;

import android.os.RemoteException;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/*
 * Loaded by Shizuku into a PRIVILEGED process (uid 2000 when Shizuku was started
 * over adb, uid 0 when started with root).  Everything here therefore runs at that
 * privilege already -- no cred patching, no fork tricks, no HKIP window.
 *
 * This is the "fast channel": the caller does one binder call and gets the output,
 * which removes the file mailbox entirely from the hot path.
 *
 * Rules taken from the Shizuku API docs:
 *   - keep the public no-arg constructor;
 *   - destroy() must exit the process (that is what the server expects);
 *   - do not touch the app's UI or singletons here, this process has none.
 */
public class RootExecService extends IRootExec.Stub {

    public RootExecService() {
    }

    @Override
    public void destroy() throws RemoteException {
        System.exit(0);
    }

    @Override
    public String exec(String cmd) throws RemoteException {
        if (cmd == null || cmd.trim().isEmpty()) {
            return "";
        }
        Process p = null;
        try {
            p = new ProcessBuilder("/system/bin/sh", "-c", cmd)
                    .redirectErrorStream(true)
                    .start();
            StringBuilder sb = new StringBuilder();
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String ln;
            while ((ln = r.readLine()) != null) {
                sb.append(ln).append('\n');
            }
            r.close();
            p.waitFor();
            return sb.toString();
        } catch (Throwable t) {
            throw new RemoteException("exec failed: " + t);
        } finally {
            if (p != null) {
                p.destroy();
            }
        }
    }

    @Override
    public int uid() throws RemoteException {
        return android.os.Process.myUid();
    }

    @Override
    public String secontext() throws RemoteException {
        try {
            BufferedReader r = new BufferedReader(
                    new InputStreamReader(new java.io.FileInputStream("/proc/self/attr/current")));
            String s = r.readLine();
            r.close();
            return s == null ? "" : s.trim();
        } catch (Throwable t) {
            return "";
        }
    }
}
