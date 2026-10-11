import subprocess
import requests
import time

WEBHOOK_URL = "https://discord.com/api/webhooks/1558554531283865684/cip-rzOF1bIXilCnF41DfM5epIHJ0hOL2CyGlDL9kU7d-lfW2E_PPK41YSfvOcFxVolI"
CONTAINER_NAME = "wizardly_feynman"

PATTERNS = [
    "UNION SELECT",
    "' OR",
    "<script",
    "onerror=",
    "alert(",
    "/rest/basket/",
    "/api/Users/",
]

def send_alert(line):
    try:
        requests.post(WEBHOOK_URL, json={"content": f"🚨 ALERT: {line.strip()}"})
        print(f"[ALERT SENT] {line.strip()}")
    except Exception as e:
        print(f"[ERROR sending alert] {e}")

def get_latest_log_filename():
    node_cmd = (
        "const fs=require('fs');"
        "const files=fs.readdirSync('/juice-shop/logs')"
        ".filter(f=>f.startsWith('access.log.'));"
        "files.sort();"
        "console.log(files[files.length-1]);"
    )
    result = subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "/nodejs/bin/node", "-e", node_cmd],
        capture_output=True, text=True
    )
    return result.stdout.strip()

def read_log(filename):
    log_path = f"/juice-shop/logs/{filename}"
    node_cmd = f"console.log(require('fs').readFileSync('{log_path}', 'utf8'))"
    result = subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "/nodejs/bin/node", "-e", node_cmd],
        capture_output=True, text=True
    )
    return result.stdout

def main():
    print("Watching Juice Shop logs... (Ctrl+C to stop)")
    seen_lines = set()
    while True:
        filename = get_latest_log_filename()
        if filename:
            content = read_log(filename)
            lines = content.splitlines()
            for line in lines:
                if line not in seen_lines:
                    seen_lines.add(line)
                    for pattern in PATTERNS:
                        if pattern.lower() in line.lower():
                            send_alert(line)
                            break
        time.sleep(2)

if __name__ == "__main__":
    main()