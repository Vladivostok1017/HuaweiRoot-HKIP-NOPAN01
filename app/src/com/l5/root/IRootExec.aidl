package com.l5.root;

/*
 * Runs inside Shizuku's privileged process (uid 2000 for adb activation, uid 0 for
 * root activation).  This is the fast channel: one binder call in, one string out,
 * instead of writing files and polling them.
 *
 * destroy() keeps Shizuku's reserved transaction code 16777114.
 */
interface IRootExec {
    void destroy() = 16777114;
    String exec(String cmd) = 1;
    int uid() = 2;
    String secontext() = 3;
}
