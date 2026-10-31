"""
SkyAV - main.py
CLI entry point. Run examples:

    python main.py --quick
    python main.py --full
    python main.py --custom "D:\\Downloads"
    python main.py --quick --auto-quarantine
    python main.py --list-quarantine
    python main.py --restore q_1234567890
"""

import argparse
import sys
import os
import time


if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

import scanner
import quarantine
import monitor
import logger
import virustotal
import registry_guard
import process_monitor
import alerts
import whitelist
import single_instance
import updater
import startup

def print_progress(count, current_path):
    # Overwrites the same line so it doesn't spam the terminal
    trimmed = current_path if len(current_path) < 70 else "..." + current_path[-67:]
    sys.stdout.write(f"\rScanned: {count}  |  {trimmed}" + " " * 10)
    sys.stdout.flush()


def print_summary(summary: dict, elapsed: float):
    print("\n\n" + "=" * 50)
    print("SCAN COMPLETE")
    print("=" * 50)
    print(f"Files scanned : {summary['scanned']}")
    print(f"Infected      : {summary['infected']}")
    print(f"Suspicious    : {summary['suspicious']}")
    print(f"Skipped       : {summary['skipped']}")
    print(f"Time taken    : {elapsed:.1f}s")

    if summary["flagged"]:
        print("\n--- FLAGGED FILES ---")
        for item in summary["flagged"]:
            print(f"[{item['status'].upper()}] {item['path']}")
            print(f"   -> {item['detail']}")
    else:
        print("\nNo threats found. System looks clean. ✅")


def main():
    parser = argparse.ArgumentParser(description="SkyAV - Custom Antivirus Scanner")
    parser.add_argument("--quick", action="store_true", help="Quick scan of common malware hotspots")
    parser.add_argument("--full", action="store_true", help="Full system scan (all drives)")
    parser.add_argument("--custom", type=str, help="Custom scan of a specific folder path")
    parser.add_argument("--auto-quarantine", action="store_true", help="Automatically quarantine detected threats")
    parser.add_argument("--list-quarantine", action="store_true", help="List quarantined files")
    parser.add_argument("--restore", type=str, help="Restore a quarantined file by its ID")
    parser.add_argument("--delete-quarantine", type=str, help="PERMANENTLY delete a quarantined file by its ID (cannot be undone)")
    parser.add_argument("--protect", action="store_true", help="Start real-time protection (continuous monitoring)")
    parser.add_argument("--gui", action="store_true", help="Launch the graphical interface")
    parser.add_argument("--set-vt-key", type=str, help="Save your VirusTotal API key")
    parser.add_argument("--check-vt", action="store_true", help="Cross-check the last scan's flagged files against VirusTotal")
    parser.add_argument("--guard-baseline", action="store_true", help="Save current registry/startup entries as the 'normal' baseline")
    parser.add_argument("--guard", action="store_true", help="Start Registry/Startup persistence guard")
    parser.add_argument("--history", action="store_true", help="Show recent scan history")
    parser.add_argument("--processes", action="store_true", help="Scan currently running processes for RAT-like behavior")
    parser.add_argument("--kill", type=int, help="Terminate a process by PID (use after --processes)")
    parser.add_argument("--set-telegram", nargs=2, metavar=("TOKEN", "CHAT_ID"),
                         help="Save Telegram bot token and chat ID for remote alerts")
    parser.add_argument("--set-discord-webhook", type=str, help="Save Discord webhook URL for remote alerts")
    parser.add_argument("--set-email", nargs=3, metavar=("SENDER_EMAIL", "APP_PASSWORD", "RECIPIENT_EMAIL"),
                         help="Save email credentials for remote alerts")
    parser.add_argument("--whitelist", type=str, help="Permanently mark a file as safe (won't be flagged again)")
    parser.add_argument("--update", action="store_true", help="Download latest malware signatures from MalwareBazaar")
    parser.add_argument("--auto-update", action="store_true", help="Start background daily signature updater")
    parser.add_argument("--register-startup", action="store_true", help="Register SkyAV to auto-start at Windows login")
    parser.add_argument("--unregister-startup", action="store_true", help="Remove SkyAV from Windows startup")
    parser.add_argument("--register-boot-scan", action="store_true", help="Register Quick Scan at every Windows login")
    parser.add_argument("--unregister-boot-scan", action="store_true", help="Remove boot-time scan task")

    if len(sys.argv) == 1:
        args = parser.parse_args(["--gui"])
    else:
        args = parser.parse_args()

    if args.whitelist:
        success = whitelist.add_to_whitelist(args.whitelist, "Manually marked safe by user")
        print(f"Whitelisted: {args.whitelist}" if success else "File not found or unreadable.")
        return

    if args.update:
        print("Downloading latest signatures from MalwareBazaar...")
        def cb(msg): print(f"  {msg}")
        result = updater.update_from_malwarebazaar(recent_only=True, progress_callback=cb)
        if result["error"]:
            print(f"Update failed: {result['error']}")
        else:
            print(f"Done — {result['added']} new signatures added (total: {result['total']})")
        return

    if args.auto_update:
        print("Starting daily signature updater (Ctrl+C to stop)...")
        updater.start_daily_updater(lambda msg: print(f"  {msg}"))
        return

    if args.register_startup:
        ok, msg = startup.register_startup(True)
        ok2, msg2 = startup.register_daily_update(True)
        print(f"Auto-start: {msg}")
        print(f"Daily update: {msg2}")
        return

    if args.unregister_startup:
        ok, msg = startup.register_startup(False)
        print(msg)
        return

    if args.register_boot_scan:
        ok, msg = startup.register_boot_scan(True)
        print(msg)
        return

    if args.unregister_boot_scan:
        ok, msg = startup.register_boot_scan(False)
        print(msg)
        return

    if args.set_telegram:
        alerts.save_telegram_config(args.set_telegram[0], args.set_telegram[1])
        success = alerts.send_telegram_message("✅ SkyAV is now connected and will send threat alerts here.")
        print("Telegram config saved." + (" Test message sent!" if success else " (test message failed — check token/chat ID)"))
        return

    if args.set_discord_webhook:
        alerts.save_discord_webhook(args.set_discord_webhook)
        success = alerts.send_discord_message("✅ SkyAV is now connected and will send threat alerts here.")
        print("Discord webhook saved." + (" Test message sent!" if success else " (test message failed — check the URL)"))
        return

    if args.set_email:
        alerts.save_email_config(args.set_email[0], args.set_email[1], args.set_email[2])
        error = alerts.send_email_message_debug("SkyAV Connected", "SkyAV is now connected and will send threat alerts here.")
        print("Email config saved." + (" Test message sent!" if error is None else f" (test failed: {error})"))
        return

    if args.kill:
        success = process_monitor.kill_process(args.kill)
        print("Process terminated." if success else "Failed to terminate process.")
        return

    if args.processes:
        print("Scanning running processes for RAT-like behavior...\n")
        flagged = process_monitor.scan_running_processes()
        if not flagged:
            print("No suspicious processes found. ✅")
        else:
            for p in flagged:
                print(f"[PID {p['pid']}] {p['name']}  (score: {p['score']})")
                print(f"   Path: {p['path']}")
                for r in p["reasons"]:
                    print(f"   -> {r}")
                print()
            print("To terminate a flagged process: python main.py --kill PID")
        return

    if args.gui:
        if single_instance.is_already_running():
            print("SkyAV is already running — check your system tray "
                  "(it may be minimized there rather than closed).")
            return
        import gui
        gui.launch()
        return

    if args.set_vt_key:
        virustotal.save_api_key(args.set_vt_key)
        print("VirusTotal API key saved.")
        return

    if args.guard_baseline:
        registry_guard.save_baseline()
        return

    if args.guard:
        registry_guard.start_guard()
        return

    if args.history:
        for entry in logger.read_history(limit=15):
            print(f"{entry['timestamp']} | {entry['scan_type']:12} | scanned={entry['scanned']:>6} "
                  f"infected={entry['infected']} suspicious={entry['suspicious']}")
        return

    if args.protect:
        monitor.start_monitor(auto_quarantine=args.auto_quarantine or True)
        return

    if args.list_quarantine:
        items = quarantine.list_quarantine()
        if not items:
            print("Quarantine is empty.")
        for qid, info in items.items():
            print(f"{qid} | {info['original_path']} | {info['reason']}")
        return

    if args.restore:
        result = quarantine.restore_file(args.restore)
        print(f"Restore result: {result}")
        return

    if args.delete_quarantine:
        confirm = input(f"This will PERMANENTLY delete quarantined item '{args.delete_quarantine}'. "
                         f"Type YES to confirm: ")
        if confirm.strip() == "YES":
            success = quarantine.delete_permanently(args.delete_quarantine)
            print("Permanently deleted." if success else "Item not found.")
        else:
            print("Cancelled.")
        return

    if args.check_vt:
        history = logger.read_history(limit=1)
        if not history or not history[0]["flagged"]:
            print("No flagged files in the last scan to check.")
            return
        print("Cross-checking last scan's flagged files against VirusTotal...\n")
        virustotal.check_flagged_files(history[0]["flagged"])
        return

    if not (args.quick or args.full or args.custom):
        parser.print_help()
        return

    start = time.time()

    if args.quick:
        print("Running QUICK SCAN...\n")
        summary = scanner.quick_scan(args.auto_quarantine, print_progress)
        scan_label = "quick"
    elif args.full:
        print("Running FULL SCAN (this may take a while)...\n")
        summary = scanner.full_scan(args.auto_quarantine, print_progress)
        scan_label = "full"
    else:
        print(f"Running CUSTOM SCAN on: {args.custom}\n")
        summary = scanner.custom_scan(args.custom, args.auto_quarantine, print_progress)
        scan_label = "custom"

    elapsed = time.time() - start
    print_summary(summary, elapsed)
    logger.log_scan(scan_label, summary, elapsed)
    alerts.send_scan_summary(scan_label, summary)


if __name__ == "__main__":
    main()
