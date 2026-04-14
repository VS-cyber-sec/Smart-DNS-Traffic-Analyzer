import json   # built-in: reads/writes JSON files
import os     # built-in: checks if a file exists
DEFAULTS = {
    
    "entropy_threshold":    3.8,
    "length_threshold":     35,
    "ttl_low_threshold":    5,
    "ttl_high_threshold":   86400,
    "freq_threshold":       5,
    "freq_window_secs":     10,
    "log_file":             "logs/dns_threats.log",
    "model_path":           "data/dns_model.pkl",
    "allowlist_path":       "data/allowlist.txt",
    "blocklist_path":       "data/blocklist.txt",
    "reports_dir":          "reports/",
    "max_log_entries":      5000,
    "alert_sound":          True,
    "auto_allowlist_reload": True,
    "reload_interval_secs": 30,
}
def load_config(path="config.json"):
    # Start with a full copy of defaults
    # .copy() is important — without it, editing cfg would edit DEFAULTS too
    cfg = DEFAULTS.copy()

    # If config.json exists, read it and merge into cfg
    if os.path.exists(path):
        with open(path, "r") as f:
            # json.load() parses the JSON file into a Python dict
            user_cfg = json.load(f)
        # update() overwrites cfg keys with values from user_cfg
        # Keys in DEFAULTS but NOT in user_cfg keep their default values
        cfg.update(user_cfg)
    else:
        # Config file doesn't exist yet — create it with defaults
        # This happens on first run
        save_config(cfg, path)
        print(f"Created default config: {path}")

    return cfg

def save_config(cfg, path="config.json"):
    with open(path, "w") as f:
        # json.dump() converts Python dict to JSON text
        # indent=2 makes it human-readable (pretty-printed)
        json.dump(cfg, f, indent=2)
