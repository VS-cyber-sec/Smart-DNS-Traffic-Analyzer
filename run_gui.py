# =============================================================================
# run_gui.py  —  GUI entry point
# =============================================================================
# HOW TO RUN:
#   Windows (Admin): python run_gui.py
#   Linux/Mac:       sudo python3 run_gui.py
#   Offline (no sudo): use the "Open PCAP File" button in the GUI
# =============================================================================

import tkinter as tk
from gui.app import SmartDNSAnalyzerGUI

def main():
    # tk.Tk() creates the main application window
    root = tk.Tk()

    # Create the full GUI app
    app = SmartDNSAnalyzerGUI(root)

    # root.mainloop() starts the tkinter event loop.
    # This blocks here until the window is closed.
    # The event loop processes button clicks, keyboard input,
    # timer callbacks (root.after), and redraws the window.
    root.mainloop()

if __name__ == "__main__":
    main()
