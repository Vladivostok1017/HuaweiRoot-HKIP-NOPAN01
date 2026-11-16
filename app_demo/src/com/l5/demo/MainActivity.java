package com.l5.demo;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.widget.ScrollView;
import android.widget.TextView;

/*
 * Minimal caller: proves that ANOTHER app can reach the manager's gateway.
 *
 *   Uri "content://com.l5.root.gateway", method "exec", arg = command
 *   -> Bundle{ code, out }
 *
 * The caller is never patched; it only receives the output of a command the
 * manager runs as uid 0.
 */
public class MainActivity extends Activity {
    private TextView tv;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        tv = new TextView(this);
        tv.setTextSize(12);
        tv.setGravity(Gravity.START);
        tv.setTextIsSelectable(true);
        ScrollView sv = new ScrollView(this);
        sv.addView(tv);
        setContentView(sv);
        tv.setText("查询中…\n");

        new Thread(new Runnable() {
            public void run() {
                String out;
                int code;
                try {
                    Bundle r = getContentResolver().call(
                            Uri.parse("content://com.l5.root.gateway"),
                            "exec", "id; cat /proc/self/attr/current", null);
                    if (r == null) {
                        out = "provider 无返回";
                        code = -3;
                    } else {
                        out = r.getString("out", "");
                        code = r.getInt("code", -3);
                    }
                } catch (Throwable e) {
                    out = "调用失败: " + e;
                    code = -4;
                }
                final String fOut = out;
                final int fCode = code;
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    public void run() {
                        tv.setText("code=" + fCode + "\n\n" + fOut);
                    }
                });
            }
        }).start();
    }
}
