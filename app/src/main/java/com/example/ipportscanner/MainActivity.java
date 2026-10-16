package com.example.ipportscanner;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.ProgressBar;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    private final int bg = Color.rgb(10, 15, 20);
    private final int panel = Color.rgb(20, 29, 36);
    private final int green = Color.rgb(49, 230, 145);
    private final int white = Color.rgb(235, 242, 246);
    private final int muted = Color.rgb(160, 176, 185);
    private EditText ipInput;
    private TextView status, results;
    private Button scanButton;
    private ProgressBar progress;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final int[] ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 8080};

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().setStatusBarColor(bg);
        getWindow().setNavigationBarColor(bg);
        getWindow().getDecorView().setSystemUiVisibility(0);
        buildUi();
    }

    private TextView text(String value, int size, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(value);
        t.setTextSize(size);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        t.setPadding(0, 5, 0, 5);
        return t;
    }

    private LinearLayout.LayoutParams lp(int width, int height) {
        return new LinearLayout.LayoutParams(width, height);
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(bg);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(22, 26, 22, 24);
        scroll.addView(root);
        setContentView(scroll);

        TextView title = text("IP PORT SCANNER", 25, green, true);
        root.addView(title);
        root.addView(text("فاحص المنافذ للشبكات المصرّح لك بفحصها", 14, muted, false));
        root.addView(space(18));

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(16, 16, 16, 16);
        card.setBackgroundColor(panel);
        root.addView(card, lp(-1, -2));
        card.addView(text("عنوان IP المستهدف", 16, white, true));

        ipInput = new EditText(this);
        ipInput.setSingleLine(true);
        ipInput.setTextColor(white);
        ipInput.setHintTextColor(muted);
        ipInput.setHint("مثال: 192.168.1.1");
        ipInput.setTextSize(16);
        ipInput.setInputType( android.text.InputType.TYPE_CLASS_TEXT );
        ipInput.setPadding(12, 10, 12, 10);
        ipInput.setBackgroundTintList(android.content.res.ColorStateList.valueOf(green));
        card.addView(ipInput, lp(-1, -2));

        card.addView(text("يفحص 12 منفذًا شائعًا، بمهلة اتصال قصيرة.", 13, muted, false));
        scanButton = new Button(this);
        scanButton.setText("بدء الفحص");
        scanButton.setTextColor(bg);
        scanButton.setBackgroundTintList(android.content.res.ColorStateList.valueOf(green));
        LinearLayout.LayoutParams bp = lp(-1, -2);
        bp.topMargin = 10;
        card.addView(scanButton, bp);

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setIndeterminate(false);
        progress.setMax(ports.length);
        progress.setProgress(0);
        progress.setVisibility(View.GONE);
        card.addView(progress, lp(-1, 8));

        status = text("جاهز للفحص", 14, muted, false);
        root.addView(status);
        root.addView(space(8));

        root.addView(text("النتائج", 19, white, true));
        results = text("أدخل عنوان IP ثم اضغط «بدء الفحص».", 15, muted, false);
        results.setPadding(14, 14, 14, 14);
        results.setBackgroundColor(panel);
        root.addView(results, lp(-1, -2));

        root.addView(space(14));
        TextView note = text("تنبيه: استخدم الأداة فقط على أجهزتك أو بعد الحصول على إذن. عدم استجابة المنفذ لا يعني بالضرورة أنه مغلق؛ قد تمنعه قواعد الحماية.", 12, muted, false);
        root.addView(note);

        scanButton.setOnClickListener(v -> startScan());
    }

    private View space(int h) {
        View v = new View(this);
        v.setLayoutParams(lp(1, h));
        return v;
    }

    private boolean validIPv4(String ip) {
        String[] p = ip.split("\\.", -1);
        if (p.length != 4) return false;
        for (String part : p) {
            if (part.isEmpty() || !part.matches("\\d{1,3}")) return false;
            int n;
            try { n = Integer.parseInt(part); } catch (Exception e) { return false; }
            if (n < 0 || n > 255) return false;
        }
        return true;
    }

    private void startScan() {
        final String host = ipInput.getText().toString().trim();
        if (!validIPv4(host)) {
            status.setText("أدخل عنوان IPv4 صحيحًا، مثل 192.168.1.1");
            status.setTextColor(Color.rgb(255, 120, 120));
            return;
        }
        scanButton.setEnabled(false);
        ipInput.setEnabled(false);
        progress.setVisibility(View.VISIBLE);
        progress.setProgress(0);
        status.setText("جارٍ الفحص: " + host);
        status.setTextColor(green);
        results.setText("");
        worker.execute(() -> {
            StringBuilder out = new StringBuilder();
            int open = 0;
            for (int i = 0; i < ports.length; i++) {
                int port = ports[i];
                String state = checkPort(host, port);
                if ("مفتوح".equals(state)) open++;
                out.append(port).append("  •  ").append(state).append("\n");
                final int progressNow = i + 1;
                final String partial = out.toString();
                main.post(() -> {
                    progress.setProgress(progressNow);
                    results.setText(partial);
                });
            }
            final int openCount = open;
            main.post(() -> {
                status.setText("اكتمل الفحص • المنافذ المستجيبة: " + openCount);
                status.setTextColor(green);
                scanButton.setEnabled(true);
                ipInput.setEnabled(true);
                progress.setVisibility(View.GONE);
            });
        });
    }

    private String checkPort(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(InetAddress.getByName(host), port), 700);
            return "مفتوح";
        } catch (java.net.SocketTimeoutException e) {
            return "لم يستجب / قد يكون محجوبًا";
        } catch (java.net.ConnectException e) {
            return "مغلق";
        } catch (Exception e) {
            return "تعذّر التحديد";
        }
    }

    @Override protected void onDestroy() {
        super.onDestroy();
        worker.shutdownNow();
    }
}
