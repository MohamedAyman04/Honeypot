import json

file_path = r"g:\Neutral_Files\GUC\Semester 8\Honeypot\grafana_dashboards\dashboard.json"

with open(file_path, "r", encoding="utf-8") as f:
    data = json.load(f)

for panel in data.get("panels", []):
    # Only touch stat panels (the attack banners)
    if panel.get("type") == "stat":
        for target in panel.get("targets", []):
            if "query" in target:
                q = target["query"]
                # Replace the full dashboard timeRange with a 15-second window
                # so the banner goes back to green (Healthy/Normal) when no new alert arrives.
                if "|> range(start: v.timeRangeStart, stop: v.timeRangeStop)" in q:
                    # BUT ONLY for honeypot_events, modbus_events, security_alerts
                    if "security_alerts" in q or "honeypot_events" in q or "modbus_events" in q:
                        q = q.replace("|> range(start: v.timeRangeStart, stop: v.timeRangeStop)", "|> range(start: -15s)")
                        target["query"] = q

with open(file_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

print("Dashboard time ranges updated.")
