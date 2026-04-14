"""Report generation utilities for DNS packet analysis output."""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime


def _ensure_output_dir(output_dir):
	os.makedirs(output_dir, exist_ok=True)


def _build_base_name(prefix="dns_report"):
	stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
	return f"{prefix}_{stamp}"


def _summary(packet_log):
	total = len(packet_log)
	suspicious = sum(1 for p in packet_log if p.get("tag") == "suspicious")
	spoofing = sum(1 for p in packet_log if p.get("tag") == "spoofing")
	normal = sum(1 for p in packet_log if p.get("tag") == "normal")
	return {
		"total": total,
		"normal": normal,
		"suspicious": suspicious,
		"spoofing": spoofing,
	}


def _write_txt(path, packet_log, summary):
	with open(path, "w", encoding="utf-8") as f:
		f.write("Smart DNS Traffic Analyzer Report\n")
		f.write("=" * 42 + "\n")
		f.write(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n")
		f.write(f"Total packets: {summary['total']}\n")
		f.write(f"Normal: {summary['normal']}\n")
		f.write(f"Suspicious: {summary['suspicious']}\n")
		f.write(f"Spoofing/Blocked: {summary['spoofing']}\n")
		f.write("\nDetails\n")
		f.write("-" * 42 + "\n")

		for p in packet_log:
			line = (
				f"[{p.get('timestamp', '')}] {p.get('query', '') or '(response packet)'} | "
				f"Status: {p.get('status', '')} | "
				f"Entropy: {float(p.get('entropy', 0.0)):.2f} | "
				f"Length: {p.get('length', 0)} | "
				f"Freq: {p.get('freq', 0)}"
			)
			f.write(line + "\n")


def _write_csv(path, packet_log):
	fields = [
		"timestamp",
		"query",
		"length",
		"entropy",
		"subdomains",
		"ttl",
		"freq",
		"status",
		"tag",
	]
	with open(path, "w", newline="", encoding="utf-8") as f:
		writer = csv.DictWriter(f, fieldnames=fields)
		writer.writeheader()
		for p in packet_log:
			writer.writerow({k: p.get(k) for k in fields})


def _write_json(path, packet_log, summary, cfg):
	payload = {
		"generated_at": datetime.now().isoformat(timespec="seconds"),
		"summary": summary,
		"config": {
			"entropy_threshold": cfg.get("entropy_threshold"),
			"length_threshold": cfg.get("length_threshold"),
			"ttl_low_threshold": cfg.get("ttl_low_threshold"),
			"freq_threshold": cfg.get("freq_threshold"),
		},
		"packets": list(packet_log),
	}
	with open(path, "w", encoding="utf-8") as f:
		json.dump(payload, f, indent=2)


def generate_report(packet_log, cfg, fmt="all", output_dir="reports"):
	"""Generate report files and return a list of saved file paths.

	Supported formats: "txt", "csv", "json", "all".
	"""
	_ensure_output_dir(output_dir)

	selected = fmt.lower().strip()
	if selected not in {"txt", "csv", "json", "all"}:
		raise ValueError(f"Unsupported format: {fmt}")

	base = _build_base_name()
	summary = _summary(packet_log)
	files = []

	if selected in {"txt", "all"}:
		txt_path = os.path.join(output_dir, f"{base}.txt")
		_write_txt(txt_path, packet_log, summary)
		files.append(txt_path)

	if selected in {"csv", "all"}:
		csv_path = os.path.join(output_dir, f"{base}.csv")
		_write_csv(csv_path, packet_log)
		files.append(csv_path)

	if selected in {"json", "all"}:
		json_path = os.path.join(output_dir, f"{base}.json")
		_write_json(json_path, packet_log, summary, cfg)
		files.append(json_path)

	return files
