# pyright: reportMissingImports=false
import threading             # runs sniffing in background without freezing GUI
import datetime              # for report timestamps
import os                    # file/folder operations

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

from collections import Counter, deque   # deque for memory-safe packet log
from scapy.all import sniff, DNS

# Our refactored modules
from smart_dns_analyzer import SmartDNSAnalyzer
from dns_analyzer.config  import load_config, save_config
from dns_analyzer.lists   import get_wildcard_pattern
from dns_analyzer.reporter import generate_report

# Cross-platform audio beep
try:
    import winsound
    def play_beep(freq, duration):
        winsound.Beep(freq, duration)
except ImportError:
    import beepy
    def play_beep(freq, duration):
        beepy.beep(sound="ping")


# =============================================================================
# SmartDNSAnalyzerGUI — main application class
# =============================================================================
class SmartDNSAnalyzerGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Smart DNS Traffic Analyzer")
        self.root.geometry("1000x750")
        self.root.minsize(800, 600)

        # State
        self.running    = False
        self.stop_event = threading.Event()

        # Load config and create analyzer
        self.cfg      = load_config("config.json")
        self.analyzer = SmartDNSAnalyzer(cfg=self.cfg)

        # Filter toggles — which categories to show in the log
        self.filter_status = {
            "normal":     True,
            "suspicious": True,
            "spoofing":   True,
        }

        # Packet log — deque auto-drops oldest entries when full
        # max_log_entries from config (default 5000)
        self.packet_log = deque(maxlen=self.cfg.get("max_log_entries", 5000))

        # System tray icon reference (created in Step 16)
        self.tray_icon = None

        # Build all GUI widgets
        self._create_widgets()

        # Handle window close button → minimize to tray (Step 16)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)


    # =========================================================================
    # _create_widgets() — builds the entire GUI layout
    # Called once from __init__
    # =========================================================================
    def _create_widgets(self):

        # ---- Top control bar (always visible, outside tabs) ----
        self._build_control_bar()

        # ---- Step 14: Stats panel (always visible, outside tabs) ----
        self._build_stats_panel()

        # ---- Step 17: Notebook with 4 tabs ----
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(padx=8, pady=4, fill="both", expand=True)

        # Tab 1: Monitor (main live log view)
        monitor_tab = ttk.Frame(self.notebook)
        self.notebook.add(monitor_tab, text="  Monitor  ")
        self._build_monitor_tab(monitor_tab)

        # Tab 2: Lists (allowlist/blocklist editor — Step 15)
        lists_tab = ttk.Frame(self.notebook)
        self.notebook.add(lists_tab, text="  Lists  ")
        self._build_lists_tab(lists_tab)

        # Tab 3: Statistics (detailed view)
        stats_tab = ttk.Frame(self.notebook)
        self.notebook.add(stats_tab, text="  Statistics  ")
        self._build_statistics_tab(stats_tab)

        # Tab 4: Settings (thresholds + save to config)
        settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(settings_tab, text="  Settings  ")
        self._build_settings_tab(settings_tab)


    # =========================================================================
    # CONTROL BAR — top bar with all action buttons
    # =========================================================================
    def _build_control_bar(self):
        bar = ttk.Frame(self.root)
        bar.pack(padx=8, pady=(8, 2), fill="x")

        self.start_btn = ttk.Button(bar, text="Start Monitoring",
                                    command=self.start_monitoring)
        self.start_btn.pack(side="left", padx=3)

        self.stop_btn = ttk.Button(bar, text="Stop Monitoring",
                                   command=self.stop_monitoring,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=3)

        ttk.Button(bar, text="Open PCAP File",
                   command=self.open_pcap).pack(side="left", padx=3)

        ttk.Button(bar, text="Generate Report",
                   command=self.generate_report_action).pack(side="left", padx=3)

        ttk.Button(bar, text="Clear Log",
                   command=self.clear_log).pack(side="left", padx=3)

        # Minimize to tray (Step 16) — on the right side
        ttk.Button(bar, text="Minimize to Tray",
                   command=self.minimize_to_tray).pack(side="right", padx=3)


    # =========================================================================
    # STEP 14: STATS PANEL — live counters updated every 1 second
    # =========================================================================
    def _build_stats_panel(self):
        """
        Builds 4 coloured metric cards + top suspicious domains display.
        This panel sits above the tabs and is ALWAYS visible.
        Updates itself every 1 second via root.after().
        """
        stats_frame = ttk.LabelFrame(self.root, text="Live Statistics")
        stats_frame.pack(padx=8, pady=2, fill="x")

        # 4 metric card variables — tk.StringVar() auto-updates the label
        # when its value changes (two-way binding between variable and widget)
        self.stat_vars = {
            "total":      tk.StringVar(value="0"),
            "normal":     tk.StringVar(value="0"),
            "suspicious": tk.StringVar(value="0"),
            "spoofing":   tk.StringVar(value="0"),
        }

        # Each card: title label above, big number below
        # fg= sets text colour. Use distinct colours for each status.
        cards = [
            ("Total Packets", "total",      "#FFFFFF"),
            ("Normal",        "normal",     "#1D9E75"),   # green
            ("Suspicious",    "suspicious", "#EF9F27"),   # amber
            ("Spoofing",      "spoofing",   "#E24B4A"),   # red
        ]

        for col, (title, key, color) in enumerate(cards):
            card = ttk.Frame(stats_frame)
            card.grid(row=0, column=col, padx=16, pady=6, sticky="w")

            # Small title label above the number
            ttk.Label(card, text=title,
                      font=("", 9)).pack(anchor="w")

            # Large number label — updates via StringVar
            tk.Label(card,
                     textvariable=self.stat_vars[key],
                     font=("", 20, "bold"),
                     fg=color,
                     bg="#1a1a1a").pack(anchor="w")

        # Top suspicious domains display (column 4)
        ttk.Label(stats_frame,
                  text="Top suspicious:").grid(row=0, column=4,
                                               padx=(24, 4), pady=6)
        self.top_sus_var = tk.StringVar(value="none yet")
        ttk.Label(stats_frame,
                  textvariable=self.top_sus_var,
                  font=("Courier", 9),
                  foreground="#EF9F27").grid(row=0, column=5,
                                             padx=4, sticky="w")


    def update_stats(self):
    
        if self.packet_log:
            packets = list(self.packet_log)   # snapshot for thread safety

            # Count packets by category
            total      = len(packets)
            normal     = sum(1 for p in packets if p["tag"] == "normal")
            suspicious = sum(1 for p in packets if p["tag"] == "suspicious")
            spoofing   = sum(1 for p in packets if p["tag"] == "spoofing")

            # Update the StringVars — this automatically updates the Labels
            self.stat_vars["total"].set(str(total))
            self.stat_vars["normal"].set(str(normal))
            self.stat_vars["suspicious"].set(str(suspicious))
            self.stat_vars["spoofing"].set(str(spoofing))

            # Find top 3 suspicious domain names by occurrence count
            sus_domains = [
                p["query"] for p in packets
                if p["tag"] == "suspicious" and p.get("query")
            ]
            top3 = Counter(sus_domains).most_common(3)
            # Format: "evil.com (5x)  bad.net (3x)  weird.io (2x)"
            top_text = "   ".join(f"{d} ({c}x)" for d, c in top3)
            self.top_sus_var.set(top_text or "none")

        # Schedule the next update in 1000ms
        # This keeps running as long as the window is open
        self.root.after(1000, self.update_stats)

    def _build_monitor_tab(self, parent):
        """
        Builds the live DNS log view.
        Contains: filter checkboxes, colour-coded ScrolledText output.
        """
        # Filter checkboxes — show/hide normal/suspicious/spoofing packets
        filter_frame = ttk.LabelFrame(parent, text="Show")
        filter_frame.pack(padx=8, pady=4, fill="x")

        self.filter_vars = {
            "normal":     tk.BooleanVar(value=True),
            "suspicious": tk.BooleanVar(value=True),
            "spoofing":   tk.BooleanVar(value=True),
        }

        # Each checkbox calls update_filter() when clicked
        for col, (key, label) in enumerate([
            ("normal",     "Normal"),
            ("suspicious", "Suspicious"),
            ("spoofing",   "Spoofing / Blocked"),
        ]):
            ttk.Checkbutton(filter_frame, text=label,
                            variable=self.filter_vars[key],
                            command=self.update_filter).grid(
                row=0, column=col, padx=10, pady=4)

        # Scrolled text output area
        # font=Courier makes columns align (monospace)
        self.output_text = scrolledtext.ScrolledText(
            parent,
            height=30,
            wrap=tk.WORD,
            font=("Courier", 10),
            bg="#0d0d0d",    # dark background for security-tool look
            fg="#ffffff",
        )
        self.output_text.pack(padx=8, pady=4, fill="both", expand=True)

        # Define colour tags for different threat levels
        # tag_config(name, foreground=text_colour, background=bg)
        # These tags are applied when inserting text: insert(..., "tag")
        self.output_text.tag_config("normal",
                                    foreground="#cccccc",
                                    background="#0d0d0d")
        self.output_text.tag_config("suspicious",
                                    foreground="#EF9F27",
                                    background="#0d0d0d")
        self.output_text.tag_config("spoofing",
                                    foreground="#E24B4A",
                                    background="#0d0d0d")
        self.output_text.tag_config("header",
                                    foreground="#1D9E75",
                                    background="#0d0d0d")
        self.output_text.tag_config("info",
                                    foreground="#378ADD",
                                    background="#0d0d0d")

        # Right-click context menu for quick allowlist/blocklist actions
        # Button-3 = right mouse button
        self.output_text.bind("<Button-3>", self._show_context_menu)
        self._context_menu = tk.Menu(self.root, tearoff=0)

        # Welcome message
        self.output_text.insert(tk.END,
            "Smart DNS Traffic Analyzer — ready\n", "header")
        self.output_text.insert(tk.END,
            "Normal | Suspicious | Spoofing/Blocked\n\n", "info")


    def _build_lists_tab(self, parent):
        """
        Builds the allowlist and blocklist editor.
        Two side-by-side listboxes with add/remove/save controls.
        No more editing .txt files in Notepad!
        """
        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(1, weight=1)

        # --- LEFT SIDE: Allowlist ---
        ttk.Label(parent,
                  text="Allowlist  (wildcards supported: *.google.com)",
                  font=("", 10, "bold")).grid(
            row=0, column=0, padx=12, pady=8, sticky="w")

        # Listbox shows all current allowlist patterns
        # selectmode=SINGLE = only one item can be selected at a time
        self.allow_lb = tk.Listbox(parent, height=20, width=40,
                                   selectmode=tk.SINGLE,
                                   font=("Courier", 10))
        self.allow_lb.grid(row=1, column=0, padx=12, sticky="nsew")

        # Text entry for typing new patterns
        self.allow_entry = ttk.Entry(parent, width=38,
                                     font=("Courier", 10))
        self.allow_entry.grid(row=2, column=0, padx=12, pady=4, sticky="w")
        # Pressing Enter in the entry box calls add_to_allowlist
        self.allow_entry.bind("<Return>", lambda e: self.add_to_allowlist())

        # Buttons row
        allow_btns = ttk.Frame(parent)
        allow_btns.grid(row=3, column=0, padx=12, pady=4, sticky="w")
        ttk.Button(allow_btns, text="Add",
                   command=self.add_to_allowlist).pack(side="left", padx=3)
        ttk.Button(allow_btns, text="Remove selected",
                   command=lambda: self._remove_from_list(
                       self.allow_lb, "allow")).pack(side="left", padx=3)
        ttk.Button(allow_btns, text="Save to file",
                   command=lambda: self._save_list("allow")).pack(
            side="left", padx=3)

        # --- RIGHT SIDE: Blocklist ---
        ttk.Label(parent,
                  text="Blocklist  (always blocked + alert)",
                  font=("", 10, "bold")).grid(
            row=0, column=1, padx=12, pady=8, sticky="w")

        self.block_lb = tk.Listbox(parent, height=20, width=40,
                                   selectmode=tk.SINGLE,
                                   font=("Courier", 10))
        self.block_lb.grid(row=1, column=1, padx=12, sticky="nsew")

        self.block_entry = ttk.Entry(parent, width=38,
                                     font=("Courier", 10))
        self.block_entry.grid(row=2, column=1, padx=12, pady=4, sticky="w")
        self.block_entry.bind("<Return>", lambda e: self.add_to_blocklist())

        block_btns = ttk.Frame(parent)
        block_btns.grid(row=3, column=1, padx=12, pady=4, sticky="w")
        ttk.Button(block_btns, text="Add",
                   command=self.add_to_blocklist).pack(side="left", padx=3)
        ttk.Button(block_btns, text="Remove selected",
                   command=lambda: self._remove_from_list(
                       self.block_lb, "block")).pack(side="left", padx=3)
        ttk.Button(block_btns, text="Save to file",
                   command=lambda: self._save_list("block")).pack(
            side="left", padx=3)

        # Populate listboxes from the analyzer's current lists
        self._reload_list_widgets()


    def _reload_list_widgets(self):
        """Clears and re-populates both listboxes from the analyzer's lists."""
        self.allow_lb.delete(0, tk.END)   # delete(0, END) clears all items
        self.block_lb.delete(0, tk.END)
        for pattern in self.analyzer.allowlist:
            self.allow_lb.insert(tk.END, pattern)
        for pattern in self.analyzer.blocklist:
            self.block_lb.insert(tk.END, pattern)


    def add_to_allowlist(self):
        """Adds the text in allow_entry to the allowlist."""
        pattern = self.allow_entry.get().strip()
        if not pattern:
            return
        if pattern not in self.analyzer.allowlist:
            self.analyzer.allowlist.append(pattern)
            self.allow_lb.insert(tk.END, pattern)
        self.allow_entry.delete(0, tk.END)   # clear the entry box


    def add_to_blocklist(self):
        """Adds the text in block_entry to the blocklist."""
        pattern = self.block_entry.get().strip()
        if not pattern:
            return
        if pattern not in self.analyzer.blocklist:
            self.analyzer.blocklist.append(pattern)
            self.block_lb.insert(tk.END, pattern)
        self.block_entry.delete(0, tk.END)


    def _remove_from_list(self, listbox, which):
        """Removes the selected item from the listbox and the analyzer's list."""
        sel = listbox.curselection()   # tuple of selected indices
        if not sel:
            return
        pattern = listbox.get(sel[0])   # get text of selected item
        listbox.delete(sel[0])          # remove from widget

        if which == "allow":
            self.analyzer.allowlist = [
                p for p in self.analyzer.allowlist if p != pattern
            ]
        else:
            self.analyzer.blocklist = [
                p for p in self.analyzer.blocklist if p != pattern
            ]


    def _save_list(self, which):
        """Writes the current list back to the .txt file on disk."""
        from dns_analyzer.lists import save_list
        if which == "allow":
            path = self.cfg.get("allowlist_path", "data/allowlist.txt")
            save_list(path, self.analyzer.allowlist)
        else:
            path = self.cfg.get("blocklist_path", "data/blocklist.txt")
            save_list(path, self.analyzer.blocklist)
        messagebox.showinfo("Saved", f"{which.title()}list saved to {path}")


    def _show_context_menu(self, event):
        """
        Shows a popup menu when the user right-clicks the log text area.
        Detects which domain was under the mouse click and offers options.
        """
        try:
            # Get the word under the mouse cursor
            # @{x},{y} = tkinter's way of getting index from pixel coordinates
            idx_start = self.output_text.index(
                f"@{event.x},{event.y} wordstart")
            idx_end   = self.output_text.index(
                f"@{event.x},{event.y} wordend")
            word = self.output_text.get(idx_start, idx_end).strip()
        except Exception:
            return

        # Only show menu if the word looks like a domain name (has a dot)
        if not word or "." not in word:
            return

        # Build the wildcard pattern for the suggestion
        # "signaler.clients6.google.com" → "*.google.com"
        wildcard = get_wildcard_pattern(word)

        # Rebuild menu items for this specific domain
        self._context_menu.delete(0, tk.END)
        self._context_menu.add_command(
            label=f"Add '{wildcard}' to allowlist",
            command=lambda w=wildcard: self._quick_allowlist(w)
        )
        self._context_menu.add_command(
            label=f"Add '{word}' to blocklist",
            command=lambda w=word: self._quick_blocklist(w)
        )
        # Show the menu at the mouse position
        self._context_menu.tk_popup(event.x_root, event.y_root)


    def _quick_allowlist(self, pattern):
        """One-click add pattern to allowlist from right-click menu."""
        if pattern not in self.analyzer.allowlist:
            self.analyzer.allowlist.append(pattern)
            self.allow_lb.insert(tk.END, pattern)
        self.output_text.insert(
            tk.END, f"Allowlisted: {pattern}\n", "info")


    def _quick_blocklist(self, domain):
        """One-click add domain to blocklist from right-click menu."""
        if domain not in self.analyzer.blocklist:
            self.analyzer.blocklist.append(domain)
            self.block_lb.insert(tk.END, domain)
        self.output_text.insert(
            tk.END, f"Blocklisted: {domain}\n", "info")


    def _build_statistics_tab(self, parent):
        """
        Detailed statistics view.
        Shows top suspicious domains table and packet counts breakdown.
        """
        ttk.Label(parent,
                  text="Detailed statistics — updates when you switch to this tab",
                  foreground="gray").pack(padx=12, pady=8, anchor="w")

        ttk.Button(parent, text="Refresh Statistics",
                   command=self._refresh_statistics).pack(
            padx=12, pady=4, anchor="w")

        # Treeview = a proper table widget with sortable columns
        # columns= defines the column identifiers
        cols = ("domain", "count", "entropy", "status")
        self.stats_tree = ttk.Treeview(parent, columns=cols,
                                        show="headings", height=20)

        # Set column headings and widths
        self.stats_tree.heading("domain",  text="Domain")
        self.stats_tree.heading("count",   text="Count")
        self.stats_tree.heading("entropy", text="Entropy")
        self.stats_tree.heading("status",  text="Status")
        self.stats_tree.column("domain",  width=350)
        self.stats_tree.column("count",   width=70,  anchor="center")
        self.stats_tree.column("entropy", width=90,  anchor="center")
        self.stats_tree.column("status",  width=250)

        self.stats_tree.pack(padx=12, pady=4, fill="both", expand=True)


    def _refresh_statistics(self):
        """Populates the statistics treeview with current packet_log data."""
        # Clear existing rows
        for row in self.stats_tree.get_children():
            self.stats_tree.delete(row)

        if not self.packet_log:
            return

        # Group packets by domain, collect stats for each
        domain_data = {}
        for p in self.packet_log:
            q = p.get("query", "")
            if not q:
                continue
            if q not in domain_data:
                domain_data[q] = {
                    "count": 0,
                    "entropy": p.get("entropy", 0),
                    "status": p.get("status", ""),
                    "tag": p.get("tag", "normal"),
                }
            domain_data[q]["count"] += 1

        # Sort by count descending (most-queried first)
        sorted_domains = sorted(
            domain_data.items(),
            key=lambda x: x[1]["count"],
            reverse=True
        )

        # Insert rows into the treeview
        for domain, data in sorted_domains:
            # tags= allows colour coding in treeview
            tag = data["tag"]
            self.stats_tree.insert("", tk.END,
                values=(
                    domain,
                    data["count"],
                    f"{data['entropy']:.2f}",
                    data["status"],
                ),
                tags=(tag,)
            )

        # Colour code rows by tag
        self.stats_tree.tag_configure("suspicious", foreground="#BA7517")
        self.stats_tree.tag_configure("spoofing",   foreground="#A32D2D")

    def _build_settings_tab(self, parent):
        """
        Threshold sliders with live value display.
        Save button writes changes back to config.json.
        """
        # --- Threshold variables (same ones used by the monitor) ---
        self.entropy_var = tk.DoubleVar(value=self.cfg["entropy_threshold"])
        self.length_var  = tk.IntVar(value=self.cfg["length_threshold"])
        self.ttl_var     = tk.IntVar(value=self.cfg["ttl_low_threshold"])
        self.freq_var    = tk.IntVar(value=self.cfg["freq_threshold"])

        # Helper to build one slider row
        def slider_row(row, label, var, from_, to_, resolution):
            ttk.Label(parent, text=label, width=20,
                      anchor="w").grid(row=row, column=0,
                                       padx=12, pady=10, sticky="w")
            # ttk.Scale: a horizontal slider widget
            # variable= keeps the slider in sync with the tkinter var
            # from_/to_ = min and max values
            scale = ttk.Scale(parent, variable=var,
                              from_=from_, to=to_,
                              orient="horizontal", length=280)
            scale.grid(row=row, column=1, padx=8, sticky="w")
            # Live value display label next to slider
            ttk.Label(parent, textvariable=var, width=6).grid(
                row=row, column=2, padx=4, sticky="w")

        # Build all 4 threshold sliders
        slider_row(0, "Entropy threshold",     self.entropy_var,
                   2.0, 5.0, 0.1)
        slider_row(1, "Length threshold",      self.length_var,
                   10, 100, 1)
        slider_row(2, "TTL low threshold (s)", self.ttl_var,
                   1, 60, 1)
        slider_row(3, "Frequency threshold",   self.freq_var,
                   1, 30, 1)

        ttk.Separator(parent, orient="horizontal").grid(
            row=4, column=0, columnspan=3, sticky="ew",
            padx=12, pady=12)

        # Save button — writes current slider values to config.json
        ttk.Button(parent, text="Save settings to config.json",
                   command=self._save_settings).grid(
            row=5, column=0, columnspan=3, pady=8)

        # Interface selector for live capture
        ttk.Label(parent, text="Network interface:").grid(
            row=6, column=0, padx=12, pady=8, sticky="w")
        self.iface_var = tk.StringVar(value="(auto)")
        ttk.Entry(parent, textvariable=self.iface_var, width=20).grid(
            row=6, column=1, padx=8, sticky="w")
        ttk.Label(parent,
                  text="Leave as (auto) to capture all interfaces",
                  foreground="gray").grid(row=6, column=2, padx=4)


    def _save_settings(self):
       
        # Update config dict with current slider values
        self.cfg["entropy_threshold"] = round(self.entropy_var.get(), 2)
        self.cfg["length_threshold"]  = self.length_var.get()
        self.cfg["ttl_low_threshold"] = self.ttl_var.get()
        self.cfg["freq_threshold"]    = self.freq_var.get()

        # Apply to the running analyzer immediately
        self.analyzer.entropy_threshold  = self.cfg["entropy_threshold"]
        self.analyzer.length_threshold   = self.cfg["length_threshold"]
        self.analyzer.ttl_low_threshold  = self.cfg["ttl_low_threshold"]
        self.analyzer.freq_threshold     = self.cfg["freq_threshold"]

        # Write to disk
        save_config(self.cfg)
        messagebox.showinfo("Saved", "Settings saved to config.json")


    # =========================================================================
    # MONITORING CONTROL
    # =========================================================================
    def start_monitoring(self):
        """Called when Start Monitoring button clicked."""
        if self.running:
            return

        self.running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        # Apply settings tab values to analyzer
        self.analyzer.entropy_threshold  = round(self.entropy_var.get(), 2)
        self.analyzer.length_threshold   = self.length_var.get()
        self.analyzer.ttl_low_threshold  = self.ttl_var.get()
        self.analyzer.freq_threshold     = self.freq_var.get()

        self.output_text.insert(tk.END,
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] "
            f"Monitoring started\n", "header")

        self.stop_event.clear()

        # Start sniffing in a background daemon thread
        # daemon=True: auto-kills when the main window closes
        self.sniff_thread = threading.Thread(
            target=self._sniff_packets, daemon=True)
        self.sniff_thread.start()

        # Start the 1-second stats update loop (Step 14)
        self.root.after(1000, self.update_stats)


    def stop_monitoring(self):
        """Called when Stop Monitoring button clicked."""
        if not self.running:
            return
        self.running = False
        self.stop_event.set()   # signal the sniff thread to stop
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.output_text.insert(tk.END, "Monitoring stopped.\n", "header")


    def _sniff_packets(self):
        """
        Runs on the BACKGROUND THREAD.
        Calls Scapy's sniff() which blocks until stopped.

        stop_filter= is called after every packet.
        When stop_event is set, stop_filter returns True → sniff() stops.
        """
        try:
            iface = self.iface_var.get().strip()
            kwargs = dict(
                filter="udp port 53",
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: self.stop_event.is_set(),
            )
            if iface and iface != "(auto)":
                kwargs["iface"] = iface

            sniff(**kwargs)

        except PermissionError:
            self.root.after(0, lambda: messagebox.showerror(
                "Permission Error",
                "Run as Administrator (Windows) or sudo (Linux/Mac)\n"
                "Or use 'Open PCAP File' for offline analysis (no admin needed)"))
        except Exception as e:
            self.root.after(0, lambda msg=str(e): messagebox.showerror(
                "Error", msg))


    def open_pcap(self):
        """
        Opens a file dialog to select a .pcap file and analyse it offline.
        PCAP mode does NOT need admin rights — great for testing!
        """
        filepath = filedialog.askopenfilename(
            title="Select PCAP file",
            filetypes=[
                ("PCAP files", "*.pcap *.pcapng"),
                ("All files", "*.*"),
            ]
        )
        if not filepath:
            return   # user cancelled the dialog

        self.output_text.insert(
            tk.END,
            f"Offline analysis: {os.path.basename(filepath)}\n",
            "header"
        )

        # Run PCAP analysis in a background thread to keep GUI responsive
        def run_pcap():
            try:
                sniff(
                    offline=filepath,          # read from file, not network
                    filter="udp port 53",
                    prn=self._process_packet,
                    store=0,
                )
                self.root.after(0, lambda: self.output_text.insert(
                    tk.END, "PCAP analysis complete.\n", "header"))
            except Exception as e:
                self.root.after(0, lambda msg=str(e): messagebox.showerror(
                    "PCAP Error", msg))

        threading.Thread(target=run_pcap, daemon=True).start()


    # =========================================================================
    # PACKET PROCESSING
    # =========================================================================
    def _process_packet(self, packet):
        
        features = self.analyzer.extract_features(packet)
        if not features:
            return

        dns = packet[DNS]

        if features["query"]:
            query = features["query"]
            # Record the query's transaction ID for spoofing detection
            self.analyzer.spoof_detector.record_query(dns)
            ml_result, confidence = self.analyzer.predict(features)
            freq     = self.analyzer.freq_tracker.get_frequency(query)
            spoofed, spoof_reason = False, "none"
        else:
            query    = ""
            ml_result, confidence = None, 0
            freq     = 0
            spoofed, spoof_reason = self.analyzer.spoof_detector.check_response(dns)

        # Determine final status
        from dns_analyzer.lists import is_match
        allowlisted, allow_pat = is_match(query, self.analyzer.allowlist)
        blocklisted, block_pat = is_match(query, self.analyzer.blocklist)

        if allowlisted:
            status = f"Normal (Allowlisted: {allow_pat})"
            tag    = "normal"
        elif blocklisted:
            status = f"Blocked ({block_pat})"
            tag    = "spoofing"
        elif spoofed:
            status = f"Spoofing ({spoof_reason})"
            tag    = "spoofing"
        elif ml_result == "Tunneling" or freq > self.analyzer.freq_threshold:
            status = f"Suspicious — confidence {confidence:.0%}"
            tag    = "suspicious"
        else:
            status = "Normal"
            tag    = "normal"

        packet_data = {
            "timestamp":  datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "query":      features.get("query", ""),
            "length":     features.get("length", 0),
            "entropy":    features.get("entropy", 0.0),
            "subdomains": features.get("subdomains", 0),
            "ttl":        features.get("ttl"),
            "freq":       freq,
            "status":     status,
            "tag":        tag,
        }

        # Store in the rolling log
        self.packet_log.append(packet_data)

        # Schedule UI update on main thread (thread-safe)
        self.root.after(0, lambda pd=packet_data: self._safe_display(pd))

        # Sound alert for threats
        if tag in ("suspicious", "spoofing") and self.cfg.get("alert_sound"):
            play_beep(1500 if tag == "spoofing" else 1000, 200)

        # Tray notification (Step 16)
        if tag in ("suspicious", "spoofing"):
            self._notify_threat(query, status)


    def _safe_display(self, packet_data):
       
        if self.filter_status.get(packet_data["tag"], True):
            self._display_packet(packet_data)


    def _display_packet(self, packet_data):
        """Inserts one packet's data into the output text widget."""
        query = packet_data["query"] or "(response packet)"
        block = (
            f"[{packet_data['timestamp']}] {query}\n"
            f"  Status : {packet_data['status']}\n"
            f"  Entropy: {packet_data['entropy']:.2f}   "
            f"Length: {packet_data['length']}   "
            f"Freq: {packet_data['freq']}\n"
            f"{'─' * 58}\n"
        )
        tag = packet_data["tag"]
        self.output_text.insert(tk.END, block, tag)
        self.output_text.see(tk.END)   # auto-scroll to newest entry


    # =========================================================================
    # FILTER CONTROL
    # =========================================================================
    def update_filter(self):
        """Called when a filter checkbox changes. Refreshes the log display."""
        self.filter_status["normal"]     = self.filter_vars["normal"].get()
        self.filter_status["suspicious"] = self.filter_vars["suspicious"].get()
        self.filter_status["spoofing"]   = self.filter_vars["spoofing"].get()
        self._refresh_log_display()


    def _refresh_log_display(self):
        """Clears and redraws the log based on current filter settings."""
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END,
            "Smart DNS Traffic Analyzer\n", "header")
        for pd in self.packet_log:
            if self.filter_status.get(pd["tag"], True):
                self._display_packet(pd)


    def clear_log(self):
        """Clears the text display (keeps packet_log for reports)."""
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "Log cleared.\n", "info")


    # =========================================================================
    # REPORT GENERATION
    # =========================================================================
    def generate_report_action(self):
        """Generates TXT + CSV + JSON reports and shows where they were saved."""
        if not self.packet_log:
            messagebox.showinfo("No Data", "No packets captured yet.")
            return

        files = generate_report(
            self.packet_log,
            self.cfg,
            fmt="all",
            output_dir=self.cfg.get("reports_dir", "reports/")
        )

        for f in files:
            self.output_text.insert(
                tk.END, f"Saved: {f}\n", "info")

        messagebox.showinfo(
            "Reports Generated",
            f"Saved {len(files)} files to {self.cfg.get('reports_dir', 'reports/')}"
        )


    def _create_tray_icon(self):
        """
        Creates the system tray icon with a right-click menu.
        Uses pystray (install with: pip install pystray pillow).
        """
        try:
            import pystray
            from PIL import Image, ImageDraw

            # Create a simple green circle icon (64x64 pixels)
            # RGBA = Red, Green, Blue, Alpha (transparency)
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            # Draw filled green circle
            draw.ellipse([4, 4, 60, 60], fill=(29, 158, 117, 255))
            # Draw "D" in the centre
            draw.text((22, 18), "DNS", fill=(255, 255, 255, 255))

            # Right-click menu items
            # Each MenuItem takes (label, callback_function)
            menu = pystray.Menu(
                pystray.MenuItem("Show window",
                                 lambda icon, item: self._show_from_tray()),
                pystray.MenuItem("Stop monitoring",
                                 lambda icon, item: self.stop_monitoring()),
                pystray.MenuItem("Generate report",
                                 lambda icon, item: self.generate_report_action()),
                pystray.MenuItem("Quit",
                                 lambda icon, item: self._quit_app()),
            )

            self.tray_icon = pystray.Icon(
                "DNS Analyzer", img, "Smart DNS Analyzer", menu)

            # run_detached() starts the tray icon in a background thread
            # so it doesn't block the GUI
            self.tray_icon.run_detached()

        except ImportError:
            # pystray not installed — tray not available, not a fatal error
            pass


    def minimize_to_tray(self):
        """Hides the window and shows the system tray icon."""
        self.root.withdraw()   # withdraw() hides the window without closing it
        if self.tray_icon is None:
            self._create_tray_icon()


    def _show_from_tray(self):
        """Restores the window from tray. Must run on the main thread."""
        # root.after(0, ...) schedules on main thread from any thread
        self.root.after(0, self.root.deiconify)


    def _notify_threat(self, domain, status):
        """Shows a tray notification popup when a threat is detected."""
        if self.tray_icon:
            try:
                self.tray_icon.notify(
                    title="DNS Threat Detected",
                    message=f"{status[:60]}\n{domain[:60]}"
                )
            except Exception:
                pass   # notifications may not be supported on all systems


    def _on_close(self):
        """
        Called when the user clicks the window's X button.
        Minimizes to tray instead of quitting (keeps monitoring running).
        """
        self.minimize_to_tray()


    def _quit_app(self):
        """Fully quits the application — stops monitoring and exits."""
        self.stop_monitoring()
        if self.tray_icon:
            self.tray_icon.stop()
        self.root.after(0, self.root.quit)
