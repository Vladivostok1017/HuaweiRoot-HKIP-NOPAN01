package com.l5.root;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

/*
 * L5Root -- two pages.
 *
 *   主页  the KernelSU-looking overview: status card, 超级用户/模块 tiles, info card.
 *   终端  a Termux-looking console: dark page, monospace output, one prompt line,
 *         ↑/↓ history, 清屏.
 *
 * Both speak to the gate through the same mailbox GatewayProvider uses:
 *   cmd.txt                       the command
 *   req.txt  "srvroot <nanoTime>"  must differ every time (the gate compares it)
 *   out.txt                       truncated by the gate per request; holds the output
 */
public class MainActivity extends Activity {

    static String DIR = "/sdcard/Android/data/com.l5.root/files/l5";

    static final int BG = 0xFFF4F4F7;
    static final int WHITE = 0xFFFFFFFF;
    static final int GREEN = 0xFFD9F5E1;
    static final int GREEN_DARK = 0xFF2E7D4F;
    static final int GRAY = 0xFF8A8A8E;
    static final int BLACK = 0xFF111114;
    static final int BLUE = 0xFF2F6BFF;

    static final int TERM_BG = 0xFF0F1115;
    static final int TERM_FG = 0xFFC8D3F5;
    static final int TERM_PROMPT = 0xFF7BD88F;
    static final int TERM_DIM = 0xFF6B7280;

    private TextView stateLine;
    private TextView modeLine;
    private TextView versionLine;
    private TextView suCount;
    private TextView modCount;
    private LinearLayout infoCard;

    private View homePage;
    private View termPage;
    private TextView termOut;
    private ScrollView termScroll;
    private EditText termInput;

    private final ArrayList<String> history = new ArrayList<String>();
    private boolean sessionOn;
    private long sessionOff;
    private int histPos;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        File ext = getExternalFilesDir(null);
        if (ext != null) {
            File d = new File(ext, "l5");
            d.mkdirs();
            DIR = d.getAbsolutePath();
        }
        new File(DIR).mkdirs();

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);

        LinearLayout titleRow = new LinearLayout(this);
        titleRow.setOrientation(LinearLayout.HORIZONTAL);
        titleRow.setGravity(Gravity.CENTER_VERTICAL);
        titleRow.setPadding(dp(20), dp(30), dp(20), dp(10));

        TextView title = new TextView(this);
        title.setText("L5Root");
        title.setTextColor(BLACK);
        title.setTextSize(28);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        titleRow.addView(title, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView power = new TextView(this);
        power.setText("\u23FB");
        power.setTextColor(BLACK);
        power.setTextSize(24);
        power.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                refresh();
                toast("已刷新");
            }
        });
        titleRow.addView(power);
        root.addView(titleRow);

        FrameLayout pages = new FrameLayout(this);
        homePage = buildHome();
        termPage = buildTerm();
        pages.addView(homePage);
        pages.addView(termPage);
        termPage.setVisibility(View.GONE);
        root.addView(pages, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        root.addView(buildNav());
        setContentView(root);

        String want = null;
        Intent it = getIntent();
        if (it != null) {
            want = it.getStringExtra("page");
        }
        showPage("term".equals(want));
        refresh();
    }

    // ---- home (KernelSU-like) -------------------------------------------

    private View buildHome() {
        ScrollView sv = new ScrollView(this);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(16), 0, dp(16), dp(16));

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);

        LinearLayout status = rounded(GREEN, 20);
        LinearLayout.LayoutParams lpStatus = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.45f);
        lpStatus.rightMargin = dp(10);
        status.setPadding(dp(16), dp(12), dp(16), dp(12));

        stateLine = new TextView(this);
        stateLine.setTextColor(BLACK);
        stateLine.setTextSize(18);
        stateLine.setTypeface(null, android.graphics.Typeface.BOLD);
        status.addView(stateLine);

        modeLine = new TextView(this);
        modeLine.setTextColor(BLACK);
        modeLine.setTextSize(12);
        status.addView(modeLine);

        versionLine = new TextView(this);
        versionLine.setTextColor(GREEN_DARK);
        versionLine.setTextSize(12);
        versionLine.setPadding(0, dp(3), 0, 0);
        status.addView(versionLine);
        row.addView(status, lpStatus);

        LinearLayout right = new LinearLayout(this);
        right.setOrientation(LinearLayout.VERTICAL);
        right.addView(tile("超级用户", suCount = new TextView(this)), tileParams());
        View spacer = new View(this);
        spacer.setLayoutParams(new LinearLayout.LayoutParams(0, dp(1)));
        right.addView(spacer);
        right.addView(tile("模块", modCount = new TextView(this)), tileParams());
        row.addView(right, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        col.addView(row);

        infoCard = rounded(WHITE, 18);
        infoCard.setPadding(dp(18), dp(6), dp(18), dp(6));
        LinearLayout.LayoutParams lpInfo = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lpInfo.topMargin = dp(14);
        col.addView(infoCard, lpInfo);

        sv.addView(col);
        return sv;
    }

    // ---- terminal (Termux-like) -----------------------------------------

    private View buildTerm() {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setBackgroundColor(TERM_BG);

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(12), dp(6), dp(8), dp(2));

        TextView name = new TextView(this);
        name.setText("l5root@device");
        name.setTextColor(TERM_DIM);
        name.setTextSize(11);
        name.setTypeface(android.graphics.Typeface.MONOSPACE);
        bar.addView(name, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        bar.addView(termButton("\u2191", new View.OnClickListener() {
            public void onClick(View v) {
                histPrev();
            }
        }));
        bar.addView(termButton("\u2193", new View.OnClickListener() {
            public void onClick(View v) {
                histNext();
            }
        }));
        final Button ses = termButton("会话", new View.OnClickListener() {
            public void onClick(View v) {
                sessionOn = !sessionOn;
                ((Button) v).setText(sessionOn ? "会话" : "单次");
                toast(sessionOn ? "会话模式：命令之间共享目录与环境" : "单次模式：每条命令独立");
            }
        });
        ses.setText("单次");
        bar.addView(ses);
        bar.addView(termButton("\u2715", new View.OnClickListener() {
            public void onClick(View v) {
                termOut.setText("");
            }
        }));
        page.addView(bar);

        termScroll = new ScrollView(this);
        termOut = new TextView(this);
        termOut.setTextColor(TERM_FG);
        termOut.setTextSize(12);
        termOut.setTypeface(android.graphics.Typeface.MONOSPACE);
        termOut.setTextIsSelectable(true);
        termOut.setPadding(dp(12), dp(2), dp(12), dp(8));
        termScroll.addView(termOut);
        page.addView(termScroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        LinearLayout prompt = new LinearLayout(this);
        prompt.setOrientation(LinearLayout.HORIZONTAL);
        prompt.setGravity(Gravity.CENTER_VERTICAL);
        prompt.setBackgroundColor(0xFF161A21);
        prompt.setPadding(dp(12), dp(4), dp(4), dp(4));

        TextView dollar = new TextView(this);
        dollar.setText("$");
        dollar.setTextColor(TERM_PROMPT);
        dollar.setTextSize(15);
        dollar.setTypeface(android.graphics.Typeface.MONOSPACE);
        dollar.setPadding(0, 0, dp(8), 0);
        prompt.addView(dollar);

        termInput = new EditText(this);
        termInput.setTextColor(TERM_FG);
        termInput.setHintTextColor(TERM_DIM);
        termInput.setHint("command");
        termInput.setTextSize(13);
        termInput.setSingleLine(true);
        termInput.setBackgroundColor(Color.TRANSPARENT);
        termInput.setTypeface(android.graphics.Typeface.MONOSPACE);
        termInput.setInputType(InputType.TYPE_CLASS_TEXT);
        termInput.setImeOptions(EditorInfo.IME_ACTION_SEND);
        termInput.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            public boolean onEditorAction(TextView v, int id, android.view.KeyEvent e) {
                runFromInput();
                return true;
            }
        });
        prompt.addView(termInput, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        prompt.addView(termButton("\u21B5", new View.OnClickListener() {
            public void onClick(View v) {
                runFromInput();
            }
        }));
        page.addView(prompt);

        String last = readAll(new File(DIR, "out.txt"));
        if (last != null && last.trim().length() > 0) {
            termAppend(TERM_DIM, "上次输出:\n");
            termAppend(TERM_FG, last.trim() + "\n");
        } else {
            termAppend(TERM_DIM, "输入命令后回车。\n");
        }
        return page;
    }

    private Button termButton(String text, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(text);
        b.setTextSize(11);
        b.setAllCaps(false);
        b.setMinWidth(0);
        b.setMinimumWidth(0);
        b.setPadding(dp(10), 0, dp(10), 0);
        b.setOnClickListener(l);
        return b;
    }

    private void runFromInput() {
        String c = termInput.getText().toString().trim();
        if (c.isEmpty()) {
            return;
        }
        history.add(c);
        histPos = history.size();
        termInput.setText("");
        run(c);
    }

    private void histPrev() {
        if (history.isEmpty() || histPos <= 0) {
            return;
        }
        histPos--;
        termInput.setText(history.get(histPos));
        termInput.setSelection(termInput.getText().length());
    }

    private void histNext() {
        if (history.isEmpty()) {
            return;
        }
        if (histPos < history.size() - 1) {
            histPos++;
            termInput.setText(history.get(histPos));
        } else {
            histPos = history.size();
            termInput.setText("");
        }
        termInput.setSelection(termInput.getText().length());
    }

    /** The single place that speaks to the gate. */
    /** Send one verb and wait up to waitMs for out.txt (null on no answer). */
    private String req(String verb, final int waitMs) {
        // The gate dispatches on req.txt and de-duplicates it verbatim, so the
        // uniqueness has to live in the padding after the verb name: every
        // handler skips leading spaces, and the raw bytes still differ.
        int sp = verb.indexOf(' ');
        String head = sp < 0 ? verb : verb.substring(0, sp);
        String tail = sp < 0 ? "" : verb.substring(sp);
        StringBuilder b = new StringBuilder(head);
        int pad = 1 + (int) ((System.nanoTime() >>> 3) % 5);
        for (int i = 0; i < pad; i++) {
            b.append(' ');
        }
        b.append(tail);
        new File(DIR, "out.txt").delete();
        writeText("req.txt", b.toString());
        long end = System.currentTimeMillis() + waitMs;
        while (System.currentTimeMillis() < end) {
            String s = readAll(new File(DIR, "out.txt"));
            if (s != null && s.trim().length() > 0) {
                return s;
            }
            try {
                Thread.sleep(120);
            } catch (InterruptedException e) {
                break;
            }
        }
        return null;
    }

    /** The single place that speaks to the gate. */
    private void run(final String cmd) {
        showPage(true);
        termAppend(TERM_PROMPT, "$ " + cmd + "\n");
        new Thread(new Runnable() {
            public void run() {
                final StringBuilder sb = new StringBuilder();
                boolean ok;
                if (!sessionOn) {
                    new File(DIR, "out.txt").delete();
                    writeText("cmd.txt", cmd);
                    writeText("req.txt", "srvroot " + System.nanoTime());
                    String s = null;
                    for (int i = 0; i < 100; i++) {
                        s = readAll(new File(DIR, "out.txt"));
                        if (s != null && s.trim().length() > 0) {
                            break;
                        }
                        try {
                            Thread.sleep(200);
                        } catch (InterruptedException e) {
                            break;
                        }
                    }
                    ok = s != null && s.trim().length() > 0;
                    sb.append(ok ? s.trim() : "无会话（未连接到 root 通道）");
                } else {
                    String r0 = req("shnew", 4000);
                    if (r0 == null || !r0.contains("patch=1")) {
                        ok = false;
                        sb.append(r0 == null ? "无法建立会话" : r0.trim());
                    } else {
                        sessionOff = 0;
                        req("shsend " + cmd, 600);
                        ok = true;
                        for (int k = 0; k < 12; k++) {
                            try {
                                Thread.sleep(300);
                            } catch (InterruptedException e) {
                                break;
                            }
                            String so = req("shout " + sessionOff, 1500);
                            if (so == null) {
                                continue;
                            }
                            int cut = so.indexOf("\n---\n");
                            if (cut < 0) {
                                continue;
                            }
                            long next = sessionOff;
                            for (String ln : so.substring(0, cut).split("\n")) {
                                if (ln.startsWith("next=")) {
                                    try {
                                        next = Long.parseLong(ln.substring(5).trim());
                                    } catch (NumberFormatException ignored) {
                                        // keep previous
                                    }
                                }
                            }
                            String data = so.substring(cut + 5);
                            if (next > sessionOff) {
                                sb.append(data);
                                sessionOff = next;
                            } else if (sb.length() > 0) {
                                break;
                            }
                        }
                    }
                }
                final boolean fOk = ok;
                final String show = sb.toString();
                runOnUiThread(new Runnable() {
                    public void run() {
                        termAppend(fOk ? TERM_FG : TERM_DIM,
                                (show.length() == 0 ? "（无输出）" : show) + "\n");
                        if (stateLine != null) {
                            stateLine.setText(fOk ? "工作中" : "未连接");
                        }
                    }
                });
            }
        }).start();
    }

    private void termAppend(int color, String s) {
        if (termOut == null || s == null || s.isEmpty()) {
            return;
        }
        SpannableString sp = new SpannableString(s);
        sp.setSpan(new ForegroundColorSpan(color), 0, s.length(),
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        termOut.append(sp);
        if (termScroll != null) {
            termScroll.post(new Runnable() {
                public void run() {
                    termScroll.fullScroll(View.FOCUS_DOWN);
                }
            });
        }
    }

    // ---- pages / nav -----------------------------------------------------

    private void showPage(boolean term) {
        if (homePage == null || termPage == null) {
            return;
        }
        homePage.setVisibility(term ? View.GONE : View.VISIBLE);
        termPage.setVisibility(term ? View.VISIBLE : View.GONE);
    }

    private View buildNav() {
        LinearLayout nav = new LinearLayout(this);
        nav.setOrientation(LinearLayout.HORIZONTAL);
        nav.setBackgroundColor(WHITE);
        nav.setPadding(dp(4), dp(8), dp(4), dp(12));
        String[][] items = {
                {"\u2302", "主页"},
                {"\u25B6", "终端"},
                {"\u25CF", "超级用户"},
                {"\u2699", "模块"},
                {"\u2261", "设置"},
        };
        for (int i = 0; i < items.length; i++) {
            final int idx = i;
            LinearLayout item = new LinearLayout(this);
            item.setOrientation(LinearLayout.VERTICAL);
            item.setGravity(Gravity.CENTER);

            TextView icon = new TextView(this);
            icon.setText(items[i][0]);
            icon.setTextSize(17);
            icon.setGravity(Gravity.CENTER);
            item.addView(icon);

            TextView label = new TextView(this);
            label.setText(items[i][1]);
            label.setTextSize(10);
            label.setGravity(Gravity.CENTER);
            item.addView(label);

            int c = i == 0 ? BLUE : GRAY;
            icon.setTextColor(c);
            label.setTextColor(c);

            item.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    if (idx == 0) {
                        showPage(false);
                        refresh();
                    } else if (idx == 1) {
                        showPage(true);
                    } else if (idx == 2) {
                        run("id; cat /proc/self/attr/current");
                    } else if (idx == 3) {
                        toast("暂无模块");
                    } else {
                        toast("L5Root · 43499-1");
                    }
                }
            });
            nav.addView(item, new LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        }
        return nav;
    }

    // ---- home refresh ----------------------------------------------------

    private void refresh() {
        String status = readAll(new File(DIR, "status.txt"));
        boolean up = status != null && (status.contains("session=up")
                || status.contains("srvroot=1"));
        String uid = field(status, "uid");
        String dom = field(status, "domain");

        if (stateLine != null) {
            stateLine.setText(up ? "工作中" : "未连接");
        }
        if (modeLine != null) {
            String sub = "";
            if (up && uid != null) {
                sub = "uid=" + uid;
            }
            if (up && dom != null) {
                sub = sub + (sub.isEmpty() ? "" : "  ") + "domain=" + dom;
            }
            modeLine.setText(sub);
        }
        if (versionLine != null) {
            versionLine.setText("43499-1");
        }
        if (suCount != null) {
            suCount.setText(String.valueOf(countCallers()));
        }
        if (modCount != null) {
            modCount.setText(String.valueOf(countModules()));
        }

        infoCard.removeAllViews();
        addInfo("管理器版本", "v0.3-cve43499 (43499-1)");
        addInfo("内核版本", kernelVersion());
        addInfo("设备型号", Build.MANUFACTURER + " " + Build.MODEL);
        addInfo("系统版本", Build.VERSION.RELEASE + " (SDK " + Build.VERSION.SDK_INT + ")");
        addInfo("系统指纹", Build.FINGERPRINT);
        addInfo("SELinux 状态", selinuxState());
        addInfo("Seccomp 状态", seccompState());
    }

    private static String field(String blob, String key) {
        if (blob == null) {
            return null;
        }
        for (String ln : blob.split("\n")) {
            if (ln.startsWith(key + "=")) {
                return ln.substring(key.length() + 1).trim();
            }
        }
        return null;
    }

    private void addInfo(String k, String v) {
        TextView kv = new TextView(this);
        kv.setText(k);
        kv.setTextColor(BLACK);
        kv.setTextSize(15);
        kv.setTypeface(null, android.graphics.Typeface.BOLD);
        kv.setPadding(0, dp(12), 0, 0);
        infoCard.addView(kv);

        TextView vv = new TextView(this);
        vv.setText(v);
        vv.setTextColor(GRAY);
        vv.setTextSize(12);
        vv.setPadding(0, dp(3), 0, dp(12));
        infoCard.addView(vv);

        View line = new View(this);
        line.setBackgroundColor(0xFFEDEDF0);
        infoCard.addView(line, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(1)));
    }

    private LinearLayout tile(String label, TextView value) {
        LinearLayout l = rounded(WHITE, 16);
        l.setPadding(dp(14), dp(10), dp(14), dp(10));

        TextView k = new TextView(this);
        k.setText(label);
        k.setTextColor(GRAY);
        k.setTextSize(12);
        l.addView(k);

        value.setTextColor(BLACK);
        value.setTextSize(22);
        value.setTypeface(null, android.graphics.Typeface.BOLD);
        l.addView(value);
        return l;
    }

    private LinearLayout.LayoutParams tileParams() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        lp.bottomMargin = dp(8);
        return lp;
    }

    // ---- helpers ---------------------------------------------------------

    private LinearLayout rounded(int color, int radius) {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(dp(radius));
        l.setBackground(d);
        return l;
    }

    /** Distinct apps that have called content://com.l5.root.gateway. */
    private int countCallers() {
        String s = readAll(new File(DIR, "callers.txt"));
        if (s == null) {
            return 0;
        }
        java.util.HashSet<String> set = new java.util.HashSet<String>();
        for (String ln : s.split("\n")) {
            if (ln.trim().length() > 0) {
                set.add(ln.trim());
            }
        }
        return set.size();
    }

    private int countModules() {
        File[] f = new File(DIR, "modules").listFiles();
        return f == null ? 0 : f.length;
    }

    private String kernelVersion() {
        String v = readAll(new File("/proc/version"));
        if (v != null) {
            String[] p = v.split(" ");
            if (p.length > 2) {
                return p[2];
            }
        }
        return "5.10.43";
    }

    private String selinuxState() {
        String s = readAll(new File("/sys/fs/selinux/enforce"));
        if (s != null && s.trim().length() > 0) {
            return "1".equals(s.trim()) ? "强制执行" : "宽容";
        }
        // Apps usually cannot read the file at all; do not guess "宽容" from a
        // failed read, that would be a lie on an enforcing device.
        // The framework helper answers false when it also cannot read the file,
        // so a failed read stays "未知" instead of being reported as 宽容.
        return new File("/sys/fs/selinux").exists() ? "未知（不可读）" : "未知";
    }

    private String seccompState() {
        String s = readAll(new File("/proc/self/status"));
        if (s == null) {
            return "未知";
        }
        for (String ln : s.split("\n")) {
            if (ln.startsWith("Seccomp:")) {
                String v = ln.substring(8).trim();
                return "0".equals(v) ? "关闭" : "过滤模式";
            }
        }
        return "未知";
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }

    private void writeText(String name, String text) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(new File(DIR, name), false);
            fos.write((text + "\n").getBytes("UTF-8"));
            fos.flush();
        } catch (IOException e) {
            toast("写入失败: " + e.getMessage());
        } finally {
            close(fos);
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

    private static void close(FileOutputStream f) {
        if (f != null) {
            try {
                f.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
    }
}
