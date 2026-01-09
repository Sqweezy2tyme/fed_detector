#!/usr/bin/env python

import asyncio
import datetime
import logging
import sys
from bleak import BleakScanner

LOG_FILE = "le_alerts.log"

OUIS = {
    "00:25:DF": "High",   # Axon (body cams, tasers)
    "00:04:7D": "High",   # Motorola
    "00:1F:92": "High",
    "4C:CC:34": "High",
    "00:1C:64": "High",
    "00:50:FA": "High",
    "00:0C:41": "High",
    "00:18:85": "High",
    "30:83:D2": "High",
    "00:1D:96": "Medium", # WatchGuard
    "AC:CC:8E": "Medium", # Axis
}

RSSI_THRESHOLD = -85
COOLDOWN_SECONDS = 180

last_seen = {}
known_devices = set()

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def estimate_distance(rssi):
    return round(10 ** ((-59 - rssi) / (10 * 2.7)), 2)

async def callback(device, advertisement_data):
    address = device.address.upper()
    name = device.name or "Unknown"
    rssi = advertisement_data.rssi or -100

    if rssi <= RSSI_THRESHOLD:
        return

    matching_oui = next((oui for oui in OUIS if address.startswith(oui)), None)
    if not matching_oui:
        return

    confidence = OUIS[matching_oui]
    now = datetime.datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

    is_new = address not in known_devices
    if is_new:
        known_devices.add(address)

    if not is_new and address in last_seen:
        if (now - last_seen[address]).total_seconds() < COOLDOWN_SECONDS:
            return

    distance = estimate_distance(rssi)
    prefix = "NEW DEVICE " if is_new else "DEVICE "

    message = (
        f"{prefix}DETECTED | Confidence: {confidence} | "
        f"MAC: {address} | Name: {name} | RSSI: {rssi} dBm | "
        f"Distance: ~{distance}m | Time: {timestamp}"
    )

    print(f"\n{message}")
    logging.info(message)
    last_seen[address] = now

async def status():
    while True:
        status_msg = f"Scanning... (Known devices: {len(known_devices)})"
        sys.stdout.write(f"\r{status_msg.ljust(80)}")
        sys.stdout.flush()
        await asyncio.sleep(1)

async def main():
    scanner = BleakScanner(callback)
    await scanner.start()

    asyncio.create_task(status())

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping scanner...")
    finally:
        await scanner.stop()
        print("Scanner stopped.")

if __name__ == "__main__":
    asyncio.run(main())
