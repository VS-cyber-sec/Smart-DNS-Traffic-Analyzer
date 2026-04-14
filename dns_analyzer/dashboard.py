import tkinter as tk
from tkinter import ttk
from collections import Counter, deque
import datetime
import logging

logger = logging.getLogger(__name__)

# Try importing matplotlib — optional dependency
try:
    import matplotlib
    matplotlib.use("TkAgg")   # use the tkinter backend
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    logger.warning("matplotlib not installed. Install with: pip install matplotlib")


class DashboardTab:
    REFRESH_MS = 2000   # every 2 seconds

    def __init__(self, parent_frame, packet_log, anomaly_detector=None):
        self.parent         = parent_frame
        self.packet_log     = packet_log
        self.anomaly_det    = anomaly_detector
        self._running       = False
        self._after_id      = None   # root.after() handle (for cancellation)
        self._threat_history = deque(maxlen=60)
        self._build_layout()

    def _build_layout(self):
           # Configure grid weights so widgets resize with the window
        self.parent.rowconfigure(0, weight=3)
        self.parent.rowconfigure(1, weight=2)
        self.parent.columnconfigure(0, weight=1)
        self.parent.columnconfigure(1, weight=1)

        if MATPLOTLIB_AVAILABLE:
            self._build_bar_chart()
            self._build_timeline_chart()
        else:
            # Fallback: text-based stats if matplotlib not installed
            self._build_text_fallback()

        self._build_top_domains_table()
        self._build_anomaly_panel()

    def _build_bar_chart(self):

        self._bar_fig = Figure(figsize=(4, 3), dpi=80)
        self._bar_fig.patch.set_facecolor("#1a1a1a")   # dark background

        # Add a subplot (Axes) to the figure
        # 111 = 1 row, 1 column, plot 1
        self._bar_ax = self._bar_fig.add_subplot(111)
        self._bar_ax.set_facecolor("#0d0d0d")

        # FigureCanvasTkAgg: bridges matplotlib and tkinter
        # This creates a tkinter widget containing the matplotlib figure
        self._bar_canvas = FigureCanvasTkAgg(self._bar_fig, self.parent)
        self._bar_canvas.get_tk_widget().grid(
            row=0, column=0, padx=8, pady=8, sticky="nsew")

    def _build_timeline_chart(self):
        self._time_fig = Figure(figsize=(4, 3), dpi=80)
        self._time_fig.patch.set_facecolor("#1a1a1a")
        self._time_ax  = self._time_fig.add_subplot(111)
        self._time_ax.set_facecolor("#0d0d0d")

        self._time_canvas = FigureCanvasTkAgg(self._time_fig, self.parent)
        self._time_canvas.get_tk_widget().grid(
            row=0, column=1, padx=8, pady=8, sticky="nsew")

    def _build_text_fallback(self):
        """Simple text display when matplotlib is not installed."""
        frame = ttk.LabelFrame(self.parent, text="Statistics")
        frame.grid(row=0, column=0, columnspan=2,
                   padx=8, pady=8, sticky="nsew")

        self._fallback_var = tk.StringVar(value="Loading...")
        ttk.Label(frame, textvariable=self._fallback_var,
                  font=("Courier", 11)).pack(padx=12, pady=12)

    def _build_top_domains_table(self):
        """
        Builds a Treeview table showing the top queried domains.
        Placed in the bottom-left cell.
        """
        frame = ttk.LabelFrame(self.parent, text="Top queried domains")
        frame.grid(row=1, column=0, padx=8, pady=4, sticky="nsew")

        # Treeview: a proper table widget with columns
        cols = ("rank", "domain", "count", "status")
        self._domain_tree = ttk.Treeview(frame, columns=cols,
                                          show="headings", height=8)

        self._domain_tree.heading("rank",   text="#")
        self._domain_tree.heading("domain", text="Domain")
        self._domain_tree.heading("count",  text="Queries")
        self._domain_tree.heading("status", text="Status")

        self._domain_tree.column("rank",   width=30,  anchor="center")
        self._domain_tree.column("domain", width=240)
        self._domain_tree.column("count",  width=60,  anchor="center")
        self._domain_tree.column("status", width=160)

        # Colour coding by status
        self._domain_tree.tag_configure("suspicious", foreground="#EF9F27")
        self._domain_tree.tag_configure("spoofing",   foreground="#E24B4A")
        self._domain_tree.tag_configure("normal",     foreground="#cccccc")

        self._domain_tree.pack(fill="both", expand=True, padx=4, pady=4)

    def _build_anomaly_panel(self):
        """
        Shows anomaly detector status and warmup progress.
        Placed in the bottom-right cell.
        """
        frame = ttk.LabelFrame(self.parent, text="Anomaly detector status")
        frame.grid(row=1, column=1, padx=8, pady=4, sticky="nsew")

        # Status variables — updated by refresh loop
        self._anomaly_status_var  = tk.StringVar(value="Not configured")
        self._anomaly_progress_var = tk.DoubleVar(value=0)
        self._anomaly_count_var   = tk.StringVar(value="0 anomalies flagged")

        ttk.Label(frame, textvariable=self._anomaly_status_var,
                  font=("", 10)).pack(pady=6)

        # Progress bar for warmup phase
        ttk.Label(frame, text="Warmup progress:").pack(anchor="w", padx=8)
        self._progress_bar = ttk.Progressbar(
            frame,
            variable=self._anomaly_progress_var,
            maximum=100,
            length=200,
        )
        self._progress_bar.pack(pady=4, padx=8)

        ttk.Label(frame, textvariable=self._anomaly_count_var,
                  foreground="#EF9F27").pack(pady=4)

    def start_updates(self):
        """Starts the periodic refresh loop."""
        self._running = True
        self._refresh()

    def stop_updates(self):
        """Stops the refresh loop."""
        self._running = False
        if self._after_id:
            # Cancel the scheduled after() call
            self.parent.after_cancel(self._after_id)
            self._after_id = None

    def _refresh(self):
        """
        Refreshes all dashboard widgets with latest data.
        Called every REFRESH_MS milliseconds via root.after().
        """
        if not self._running:
            return

        try:
            packets = list(self.packet_log)   # snapshot the log

            if MATPLOTLIB_AVAILABLE:
                self._update_bar_chart(packets)
                self._update_timeline(packets)
            else:
                self._update_text_fallback(packets)

            self._update_top_domains(packets)
            self._update_anomaly_panel()

        except Exception as e:
            logger.error(f"Dashboard refresh error: {e}")

        # Schedule next refresh
        self._after_id = self.parent.after(self.REFRESH_MS, self._refresh)

    def _update_bar_chart(self, packets):
        """Updates the status bar chart with current counts."""
        counts = Counter(p["tag"] for p in packets)
        normal     = counts.get("normal", 0)
        suspicious = counts.get("suspicious", 0)
        spoofing   = counts.get("spoofing", 0)

        # Clear the axes and redraw
        self._bar_ax.clear()
        self._bar_ax.set_facecolor("#0d0d0d")

        bars = self._bar_ax.bar(
            ["Normal", "Suspicious", "Spoofing"],
            [normal, suspicious, spoofing],
            color=["#1D9E75", "#EF9F27", "#E24B4A"],
            edgecolor="none",
        )

        # Add value labels on top of each bar
        for bar, val in zip(bars, [normal, suspicious, spoofing]):
            if val > 0:
                self._bar_ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.5,
                    str(val),
                    ha="center", va="bottom",
                    color="white", fontsize=9
                )

        # Style the chart
        self._bar_ax.set_title("Packet status", color="white", fontsize=9)
        self._bar_ax.tick_params(colors="gray", labelsize=8)
        for spine in self._bar_ax.spines.values():
            spine.set_visible(False)

        # Redraw the canvas
        self._bar_canvas.draw_idle()

    def _update_timeline(self, packets):
        """Updates the threat rate timeline chart."""
        # Count current threats and add to history
        threat_count = sum(
            1 for p in packets[-100:]   # look at last 100 packets
            if p["tag"] in ("suspicious", "spoofing")
        )
        self._threat_history.append(
            (datetime.datetime.now(), threat_count))

        self._time_ax.clear()
        self._time_ax.set_facecolor("#0d0d0d")

        if len(self._threat_history) > 1:
            # Extract times and counts for plotting
            times  = [e[0] for e in self._threat_history]
            counts = [e[1] for e in self._threat_history]

            # Plot the line
            self._time_ax.plot(
                range(len(counts)), counts,
                color="#EF9F27", linewidth=1.5, alpha=0.8
            )
            # Fill area under the line
            self._time_ax.fill_between(
                range(len(counts)), counts,
                alpha=0.2, color="#EF9F27"
            )

        self._time_ax.set_title("Threat rate (last 2 min)",
                                 color="white", fontsize=9)
        self._time_ax.tick_params(colors="gray", labelsize=7)
        for spine in self._time_ax.spines.values():
            spine.set_visible(False)

        self._time_canvas.draw_idle()

    def _update_text_fallback(self, packets):
        """Updates text-based stats when matplotlib is unavailable."""
        counts = Counter(p["tag"] for p in packets)
        text   = (
            f"Total:      {len(packets)}\n"
            f"Normal:     {counts.get('normal', 0)}\n"
            f"Suspicious: {counts.get('suspicious', 0)}\n"
            f"Spoofing:   {counts.get('spoofing', 0)}\n"
        )
        self._fallback_var.set(text)

    def _update_top_domains(self, packets):
        """Refreshes the top domains Treeview table."""
        # Clear existing rows
        for row in self._domain_tree.get_children():
            self._domain_tree.delete(row)

        if not packets:
            return

        # Count queries per domain
        domain_counts = Counter(
            p["query"] for p in packets if p.get("query"))

        # Build a lookup for domain status
        domain_status = {}
        for p in packets:
            q = p.get("query", "")
            if q and q not in domain_status:
                domain_status[q] = (p.get("status", "Normal"),
                                    p.get("tag", "normal"))

        # Insert top 10 domains
        for rank, (domain, count) in enumerate(
                domain_counts.most_common(10), start=1):
            status, tag = domain_status.get(domain, ("Normal", "normal"))
            self._domain_tree.insert("", tk.END,
                values=(rank, domain, count, status[:30]),
                tags=(tag,)
            )

    def _update_anomaly_panel(self):
        """Updates the anomaly detector status panel."""
        if self.anomaly_det is None:
            self._anomaly_status_var.set("Not configured")
            return

        stats = self.anomaly_det.get_stats()

        if stats["trained"]:
            self._anomaly_status_var.set(
                f"Active — trained on {stats['buffer_size']} samples")
        else:
            pct = stats["warmup_progress"]
            self._anomaly_status_var.set(
                f"Warming up... {pct:.0f}% complete")

        # Update progress bar (0–100)
        self._anomaly_progress_var.set(stats["warmup_progress"])

        self._anomaly_count_var.set(
            f"{stats['anomalies_flagged']} anomalies flagged")
