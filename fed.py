#!/usr/bin/env python

import asyncio
import datetime
import logging
import sys
from bleak import BleakScanner

LOG_FILE = "global_le_alerts.log"
GLOBAL_LE_OUIS = [
    "00:25:DF",  # Axon - Dominant globally, including USA, Sweden, Australia
    "00:04:7D", "00:1F:92", "4C:CC:34", "00:1C:64", "00:50:FA", "00:0C:41", "00:18:85", "30:83:D2",  # Motorola Solutions - USA, global radios/body cams
    "00:00:C3", "00:06:EC", "00:17:F3", "00:05:D6", "00:30:B2",  # L3Harris - USA military/fed radios
    "AC:CC:8E",  # Axis - Sweden/Europe body cams
    "00:1B:3F",  # Hytera - China/global body cams/radios
    "00:0E:8E",  # Sepura - Europe/Sweden TETRA radios
    "B8:20:8E", "54:CD:10", "00:80:45", "74:A5:7E", "20:0E:0F", "00:C0:8F", "8C:C1:21",  # Panasonic/i-PRO - Japan/global body cams
    "00:0D:CA", "00:12:E0",  # Tait/Codan - Global/Oceania radios
    "00:0F:EF", "00:10:06", "00:26:B3", "00:D0:FA", "A4:34:12", "40:68:26",  # Thales - France/global defense
    "A8:CC:C5", "00:40:85",  # Saab - Sweden defense comms
    "08:10:86", "00:00:74", "00:60:B9", "34:38:39",  # NEC - Japan/Asia
    "38:E0:8E", "00:10:C9", "00:26:92",  # Mitsubishi - Japan/Asia
    "00:1D:96",  # WatchGuard - USA/global body cams
    "00:80:8F", "00:E0:E7",  # Raytheon/RTX
    "00:25:D4"   # General Dynamics
]
RSSI_THRESHOLD = -85
COOLDOWN = 180

last_seen = {}
known_devices = set()

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

def estimate_distance(rssi):
    return round(10 ** ((-59 - rssi) / (10 * 2.7)), 2)

async def detection_callback(device, advertisement_data):
    addr = device.address.upper()
    name = device.name or "Unknown"
    rssi = advertisement_data.rssi or -100
    if rssi <= RSSI_THRESHOLD:
        return
    if not any(addr.startswith(oui) for oui in GLOBAL_LE_OUIS):
        return
    now = datetime.datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")
    is_new = addr not in known_devices
    if is_new:
        known_devices.add(addr)
    if addr in last_seen and (now - last_seen[addr]).total_seconds() < COOLDOWN and not is_new:
        return
    distance = estimate_distance(rssi)
    prefix = "NEW LE GEAR " if is_new else "LE GEAR "
    message = f"{prefix}DETECTED | MAC: {addr} | Name: {name} | RSSI: {rssi} dBm | Est. Distance: {distance}m | Time: {current_time}"
    print(f"\n{message}")
    logging.info(message)
    last_seen[addr] = now

async def status_task():
    while True:
        status = f"scanning worldwide for LE gear (body cams, radios)... (Known: {len(known_devices)})"
        sys.stdout.write(f"\r{status}")
        sys.stdout.flush()
        await asyncio.sleep(1)

async def main():
    scanner = BleakScanner(detection_callback=detection_callback)
    await scanner.start()
    asyncio.create_task(status_task())
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await scanner.stop()
        print("\nscanner stopped.")

if __name__ == "__main__":
    asyncio.run(main())
