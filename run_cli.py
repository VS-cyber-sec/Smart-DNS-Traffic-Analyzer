# pyright: reportMissingImports=false
import argparse                    # built-in: parses command-line arguments
import os                          # built-in: file existence checks
from colorama import init, Fore, Style  # coloured terminal output

# Scapy sniff() is the function that captures packets
# It works for both live capture AND reading from pcap files
from scapy.all import sniff

# Our refactored analyzer class
from smart_dns_analyzer import SmartDNSAnalyzer

# Load config helper
from dns_analyzer.config import load_config

# Activate colorama (needed for Windows colour support)
init()


# =============================================================================
# main() — everything starts here
# =============================================================================
def main():

    parser = argparse.ArgumentParser(
        description="Smart DNS Traffic Analyzer — monitors DNS for threats",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Detection threshold overrides (override config.json values)
    parser.add_argument("--entropy", type=float, default=None,
        help="Entropy threshold (default from config.json: 3.8)")
    parser.add_argument("--length", type=int, default=None,
        help="Domain length threshold (default: 35)")
    parser.add_argument("--ttl", type=int, default=None,
        help="Low TTL threshold in seconds (default: 5)")
    parser.add_argument("--freq", type=int, default=None,
        help="Max queries per 10 seconds before flagging (default: 5)")

    # PCAP offline mode (Phase 3 Step 12)
    parser.add_argument("--pcap", type=str, default=None,
        help="Path to a .pcap file for offline analysis.\n"
             "No admin rights needed. Example:\n"
             "  python run_cli.py --pcap data/tunneling.pcap")

    # Network interface (useful if you have multiple network adapters)
    parser.add_argument("--iface", type=str, default=None,
        help="Network interface to listen on (e.g. Wi-Fi, Ethernet).\n"
             "Leave blank to capture on all interfaces.")

    # Config file path
    parser.add_argument("--config", type=str, default="config.json",
        help="Path to config.json (default: config.json)")

    # Parse the arguments the user typed
    args = parser.parse_args()


    # ---- Step 2: Load config from config.json ----
    # load_config() reads config.json and fills in defaults for missing keys
    cfg = load_config(args.config)


    # ---- Step 3: Override config with any CLI arguments provided ----
    # If the user typed "--entropy 4.0", override the config value.
    # If they didn't type it (args.entropy is None), keep config value.
    if args.entropy is not None:
        cfg["entropy_threshold"] = args.entropy
    if args.length is not None:
        cfg["length_threshold"] = args.length
    if args.ttl is not None:
        cfg["ttl_low_threshold"] = args.ttl
    if args.freq is not None:
        cfg["freq_threshold"] = args.freq


    # ---- Step 4: Create the analyzer ----
    # SmartDNSAnalyzer uses cfg for all its settings
    analyzer = SmartDNSAnalyzer(cfg=cfg)


    # ---- Step 5: Print startup banner ----
    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)
    print(Fore.CYAN + "  Smart DNS Traffic Analyzer" + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)
    print(f"  Entropy  > {cfg['entropy_threshold']}")
    print(f"  Length   > {cfg['length_threshold']}")
    print(f"  TTL low  < {cfg['ttl_low_threshold']}")
    print(f"  Freq     > {cfg['freq_threshold']} per 10s")
    print(f"  {Fore.WHITE}Normal{Style.RESET_ALL} | "
          f"{Fore.YELLOW}Suspicious{Style.RESET_ALL} | "
          f"{Fore.RED}Critical{Style.RESET_ALL}")
    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)


    # ---- Step 6: Start capturing ----
    try:

        if args.pcap:
            # ----------------------------------------------------------------
            # OFFLINE MODE — read from a saved .pcap file
            # ----------------------------------------------------------------
            # Validate the file exists first
            if not os.path.exists(args.pcap):
                print(Fore.RED + f"Error: File not found: {args.pcap}"
                      + Style.RESET_ALL)
                return

            print(Fore.CYAN + f"Offline mode: analysing {args.pcap}"
                  + Style.RESET_ALL)
            print(Fore.CYAN + "(No admin rights needed for offline mode)"
                  + Style.RESET_ALL)

            # sniff() with offline= reads packets from the .pcap file
            # instead of the live network interface.
            # It calls analyzer.dns_monitor() for each DNS packet found,
            # exactly the same as in live mode.
            # store=0 means don't keep packets in RAM (save memory)
            sniff(
                offline=args.pcap,         # ← read from file, not network
                filter="udp port 53",      # only process DNS packets
                prn=analyzer.dns_monitor,  # call this for every packet
                store=0,
            )
            print(Fore.CYAN + "\nOffline analysis complete." + Style.RESET_ALL)

        else:
            # ----------------------------------------------------------------
            # LIVE MODE — capture packets from the network interface
            # ----------------------------------------------------------------
            if args.iface:
                print(Fore.CYAN + f"Live mode: interface {args.iface} "
                      f"(Ctrl+C to stop)" + Style.RESET_ALL)
                # iface= specifies which network adapter to listen on
                sniff(
                    filter="udp port 53",
                    prn=analyzer.dns_monitor,
                    store=0,
                    iface=args.iface,   # e.g. "Wi-Fi" or "Ethernet"
                )
            else:
                print(Fore.CYAN + "Live mode: all interfaces "
                      "(Ctrl+C to stop)" + Style.RESET_ALL)
                # Without iface=, Scapy listens on all available interfaces
                sniff(
                    filter="udp port 53",
                    prn=analyzer.dns_monitor,
                    store=0,
                )

    except PermissionError:
        # Scapy needs admin (Windows) or sudo (Linux/Mac) for live capture
        print(Fore.RED + "\nError: Permission denied." + Style.RESET_ALL)
        print("  Windows : Run Command Prompt as Administrator")
        print("  Linux   : Run with sudo python3 run_cli.py")
        print("  Mac     : Run with sudo python3 run_cli.py")
        print(Fore.YELLOW + "  Tip: Use --pcap mode — no admin needed!"
              + Style.RESET_ALL)

    except KeyboardInterrupt:
        # User pressed Ctrl+C — clean, expected exit
        print(Fore.CYAN + "\n\nMonitoring stopped." + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"\nUnexpected error: {e}" + Style.RESET_ALL)


# Entry point — only runs main() if this script is executed directly
# (not if it's imported by another file)
if __name__ == "__main__":
    main()
