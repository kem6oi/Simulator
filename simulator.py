#!/usr/bin/env python3
"""
IoT Bulb Simulator for IoTNode
Simulates a bulb receiving MQTT commands and publishing MQTT status updates.
Telemetry is sent to the backend via the device API for storage.
Reads configuration from config.env file
"""

import paho.mqtt.client as mqtt
import json
import time
import os
import sys
import random
import threading
import urllib.request
import urllib.error
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from config.env file
load_dotenv('config.env')

# Configuration from environment variables
BASE_URL = os.getenv('BASE_URL', 'http://localhost:3000/api/v1')
API_KEY = os.getenv('API_KEY')
DEVICE_ID = os.getenv('DEVICE_ID')
ORGANIZATION_ID = os.getenv('ORGANIZATION_ID')

MQTT_HOST = os.getenv('MQTT_HOST', 'broker.hivemq.com')
MQTT_PORT = int(os.getenv('MQTT_PORT', '8883'))
MQTT_USERNAME = os.getenv('MQTT_USERNAME', '')
MQTT_PASSWORD = os.getenv('MQTT_PASSWORD', '')
MQTT_PROTOCOL = os.getenv('MQTT_PROTOCOL', 'mqtts')

# Validate required environment variables
def validate_config():
    """Validate required configuration"""
    missing = []

    if not API_KEY:
        missing.append('API_KEY')
    if not DEVICE_ID:
        missing.append('DEVICE_ID')
    if not ORGANIZATION_ID:
        missing.append('ORGANIZATION_ID')

    if missing:
        print_status(f"Missing required environment variables: {', '.join(missing)}", "ERROR")
        print_status("Please set them in config.env file", "ERROR")
        sys.exit(1)

    # Check if config.env exists
    if not os.path.exists('config.env'):
        print_status("Warning: config.env file not found!", "WARNING")
        print_status("Create config.env file with your configuration", "WARNING")

# Construct MQTT topics (organization-scoped only)
TOPIC_COMMANDS = f"{ORGANIZATION_ID}/{DEVICE_ID}/commands"
TOPIC_STATUS = f"{ORGANIZATION_ID}/{DEVICE_ID}/status"
TOPIC_TELEMETRY = f"{ORGANIZATION_ID}/{DEVICE_ID}/telemetry"
TOPIC_AVAILABILITY = f"{ORGANIZATION_ID}/{DEVICE_ID}/availability"

# Start time for uptime calculation
start_time = time.time()

# Device state (bulb)
device_state = {
    "power": False,
    "brightness": 0,
    "last_updated": None
}

def print_separator():
    print("=" * 70)

def print_status(message, status_type="INFO"):
    """Print formatted status messages"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    colors = {
        "INFO": "\033[94m",      # Blue
        "SUCCESS": "\033[92m",   # Green
        "WARNING": "\033[93m",   # Yellow
        "ERROR": "\033[91m",     # Red
        "DEVICE": "\033[95m",    # Magenta
        "ALARM": "\033[91;1m"    # Bold Red
    }
    reset = "\033[0m"
    color = colors.get(status_type, "")
    print(f"{color}[{timestamp}] [{status_type}] {message}{reset}")

def display_config():
    """Display current configuration"""
    print_separator()
    print_status("CONFIGURATION (from config.env):", "INFO")
    print(f"  Base URL:      {BASE_URL}")
    print(f"  API Key:       {'*' * 20}{API_KEY[-4:] if API_KEY and len(API_KEY) > 4 else 'NOT SET'}")
    print(f"  Device ID:     {DEVICE_ID}")
    print(f"  MQTT Host:     {MQTT_HOST}")
    print(f"  MQTT Port:     {MQTT_PORT}")
    print(f"  MQTT Protocol: {MQTT_PROTOCOL}")
    print(f"  MQTT Username: {MQTT_USERNAME if MQTT_USERNAME else 'None'}")
    print(f"  MQTT Password: {'***' if MQTT_PASSWORD else 'None'}")
    print(f"  Command Topic: {TOPIC_COMMANDS}")
    print(f"  Status Topic:  {TOPIC_STATUS}")
    print_separator()

def display_device_state():
    """Display current device state"""
    print_separator()
    print_status("CURRENT DEVICE STATE:", "DEVICE")
    print(f"  Power:       {'🟢 ON' if device_state['power'] else '🔴 OFF'}")
    print(f"  Brightness:  {device_state['brightness']}%")
    if device_state['last_updated']:
        print(f"  Last Update: {device_state['last_updated']}")
    print_separator()

def publish_status(client):
    """Publish current device state to MQTT"""
    current_status = "active" if device_state["power"] else "standby"
    power_usage = round(random.uniform(0.3, 0.9), 2) if device_state["power"] else 0.0

    status_payload = {
        "device_id": DEVICE_ID,
        "timestamp": datetime.now().isoformat(),
        "status": current_status,
        "state": {
            "power": device_state["power"],
            "brightness": device_state["brightness"]
        },
        "metadata": {
            "firmware_version": "1.0.0-bulb",
            "uptime": int(time.time() - start_time),
            "wifi_signal": random.randint(-65, -35),
            "ip_address": "192.168.1.128",
            "power_consumption": power_usage
        }
    }

    client.publish(TOPIC_STATUS, json.dumps(status_payload), qos=1)
    print_status(f"📤 Published status update to {TOPIC_STATUS} (Status: {current_status})", "INFO")

def build_telemetry_values():
    """Build telemetry values for MQTT and API."""
    power_consumption = round(random.uniform(0.3, 0.9), 2) if device_state["power"] else 0.0
    return {
        "brightness": device_state["brightness"],
        "power": device_state["power"],
        "power_consumption": power_consumption,
        "uptime": int(time.time() - start_time)
    }

def publish_telemetry_mqtt(client):
    """Publish telemetry over MQTT for real-time updates."""
    telemetry_payload = {
        "device_id": DEVICE_ID,
        "timestamp": datetime.now().isoformat(),
        "sensors": build_telemetry_values()
    }
    client.publish(TOPIC_TELEMETRY, json.dumps(telemetry_payload), qos=0)
    print_status(f"📤 Published telemetry to {TOPIC_TELEMETRY}", "INFO")

def send_telemetry():
    """Send telemetry to backend for storage"""
    telemetry_payload = {
        "dataType": "bulb_metrics",
        "value": build_telemetry_values(),
        "timestamp": datetime.now().isoformat()
    }

    url = f"{BASE_URL}/device/data"
    data = json.dumps(telemetry_payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
        print_status("📡 Telemetry sent to backend", "INFO")
    except urllib.error.HTTPError as e:
        print_status(f"Telemetry HTTP error: {e.code} {e.reason}", "ERROR")
    except urllib.error.URLError as e:
        print_status(f"Telemetry connection error: {e.reason}", "ERROR")
    except Exception as e:
        print_status(f"Telemetry error: {e}", "ERROR")

def send_command_status(command_id, status, result=None, error_message=None):
    """Send command execution status to backend."""
    if not command_id:
        return

    status_payload = {
        "status": status,
        "result": result or {},
        "errorMessage": error_message
    }

    url = f"{BASE_URL}/device/commands/{command_id}/status"
    data = json.dumps(status_payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY
        },
        method="PATCH"
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
        print_status(f"✅ Command status updated: {command_id} -> {status}", "INFO")
    except urllib.error.HTTPError as e:
        print_status(f"Command status HTTP error: {e.code} {e.reason}", "ERROR")
    except urllib.error.URLError as e:
        print_status(f"Command status connection error: {e.reason}", "ERROR")
    except Exception as e:
        print_status(f"Command status error: {e}", "ERROR")

def heartbeat_loop(client):
    """Publish status and telemetry every 30 seconds"""
    while True:
        time.sleep(30)
        publish_status(client)
        publish_telemetry_mqtt(client)
        send_telemetry()

def process_command(client, payload):
    """Process the command payload"""
    try:
        # Parse JSON
        command = json.loads(payload)
        print_status(f"Received JSON: {json.dumps(command, indent=2)}", "INFO")

        action = command.get("action")
        command_id = command.get("id")

        if not action:
            print_status("No action specified in payload!", "ERROR")
            return

        # Extract value from different possible fields
        value = None
        for key in ["value", "state", "level", "mode", "text"]:
            if key in command:
                value = command[key]
                break

        # Process based on action
        if action == "set_power":
            old_state = device_state["power"]

            # Handle different value formats
            if isinstance(value, bool):
                device_state["power"] = value
            elif isinstance(value, str):
                device_state["power"] = value.lower() in ["on", "true", "1"]
            elif isinstance(value, int):
                device_state["power"] = bool(value)
            else:
                print_status(f"Unknown value format: {type(value)}", "ERROR")
                return

            device_state["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Visual output
            print_status(f"Processing: {action}", "SUCCESS")
            print(f"\n  ⚡ Power State Changed:")
            print(f"     Before: {'ON' if old_state else 'OFF'}")
            print(f"     After:  {'ON' if device_state['power'] else 'OFF'}")

            if device_state["power"]:
                print_status("✅ DEVICE IS NOW ON", "SUCCESS")
            else:
                print_status("⛔ DEVICE IS NOW OFF", "WARNING")
            send_command_status(command_id, "completed", {"power": device_state["power"]})

        elif action == "set_brightness":
            old_brightness = device_state["brightness"]
            try:
                brightness_value = int(value)
                if brightness_value < 0 or brightness_value > 100:
                    raise ValueError("Brightness must be between 0 and 100")
                device_state["brightness"] = brightness_value
                device_state["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                print_status(f"Processing: {action}", "SUCCESS")
                print(f"\n  💡 Brightness Changed:")
                print(f"     Before: {old_brightness}%")
                print(f"     After:  {device_state['brightness']}%")

                # Visual brightness bar
                bar_length = 20
                filled = int((device_state['brightness'] / 100) * bar_length)
                bar = "█" * filled + "░" * (bar_length - filled)
                print(f"     [{bar}] {device_state['brightness']}%")

                print_status(f"✅ BRIGHTNESS SET TO {device_state['brightness']}%", "SUCCESS")
                send_command_status(command_id, "completed", {"brightness": device_state["brightness"]})
            except (ValueError, TypeError):
                print_status(f"Invalid brightness value: {value}", "ERROR")
                send_command_status(command_id, "failed", error_message="Invalid brightness value")

        else:
            print_status(f"Unknown action: {action}", "ERROR")
            print_status("Supported actions: set_power, set_brightness", "INFO")
            send_command_status(command_id, "failed", error_message="Unsupported action")
            return

        # Display updated state
        print()
        display_device_state()

        # After successfully processing command, publish status
        publish_status(client)

    except json.JSONDecodeError as e:
        print_status(f"Invalid JSON: {e}", "ERROR")
        print_status(f"Raw payload: {payload}", "ERROR")
    except Exception as e:
        print_status(f"Error processing command: {e}", "ERROR")
        import traceback
        traceback.print_exc()

def on_connect(client, userdata, flags, rc):
    """Callback when connected to MQTT broker"""
    if rc == 0:
        print_status(f"Connected to MQTT Broker: {MQTT_PROTOCOL}://{MQTT_HOST}:{MQTT_PORT}", "SUCCESS")

        # Publish online status
        online_payload = json.dumps({
            "device_id": DEVICE_ID,
            "status": "online",
            "timestamp": datetime.now().isoformat()
        })
        client.publish(TOPIC_AVAILABILITY, online_payload, qos=1, retain=True)
        print_status(f"Published online status to {TOPIC_AVAILABILITY}", "INFO")

        # Subscribe to commands
        client.subscribe(TOPIC_COMMANDS)
        print_status(f"Subscribed to topic: {TOPIC_COMMANDS}", "INFO")

        # Publish initial status
        publish_status(client)

        print_status("Waiting for commands...", "INFO")
        print_status("Supported commands: power, brightness", "INFO")
        display_device_state()
    else:
        error_messages = {
            1: "Connection refused - incorrect protocol version",
            2: "Connection refused - invalid client identifier",
            3: "Connection refused - server unavailable",
            4: "Connection refused - bad username or password",
            5: "Connection refused - not authorized"
        }
        print_status(f"Connection failed: {error_messages.get(rc, f'Unknown error code {rc}')}", "ERROR")
        sys.exit(1)

def on_message(client, userdata, msg):
    """Callback when message is received"""
    print_separator()
    print_status(f"📩 Message received on topic: {msg.topic}", "INFO")
    process_command(client, msg.payload.decode())

def on_disconnect(client, userdata, rc):
    """Callback when disconnected"""
    if rc != 0:
        print_status("Unexpected disconnection. Attempting to reconnect...", "WARNING")

def main():
    """Main function to run the simulator"""
    print_separator()
    print_status("🤖 IoT Device Simulator Starting...", "DEVICE")
    print_separator()

    # Validate configuration
    validate_config()

    # Display configuration
    display_config()

    # Create MQTT client
    client_id = f"simulator_{DEVICE_ID}_{int(time.time())}"
    client = mqtt.Client(client_id=client_id)

    # Set Last Will before connecting
    will_payload = json.dumps({
        "device_id": DEVICE_ID,
        "status": "offline",
        "timestamp": datetime.now().isoformat()
    })
    client.will_set(TOPIC_AVAILABILITY, will_payload, qos=1, retain=True)

    # Set username and password if provided
    if MQTT_USERNAME and MQTT_PASSWORD:
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
        print_status("MQTT authentication configured", "INFO")

    # Configure TLS/SSL for secure connections
    if MQTT_PROTOCOL in ['mqtts', 'ssl', 'tls']:
        try:
            import ssl
            client.tls_set(cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS)
            print_status("TLS/SSL enabled", "INFO")
        except Exception as e:
            print_status(f"TLS/SSL configuration failed: {e}", "ERROR")
            print_status("Falling back to non-secure connection", "WARNING")

    # Set callbacks
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect

    try:
        # Connect to broker
        print_status(f"Connecting to {MQTT_HOST}:{MQTT_PORT}...", "INFO")
        client.connect(MQTT_HOST, MQTT_PORT, 60)

        # Start heartbeat in background thread
        heartbeat_thread = threading.Thread(target=heartbeat_loop, args=(client,), daemon=True)
        heartbeat_thread.start()

        # Start the loop
        client.loop_forever()

    except KeyboardInterrupt:
        print()
        print_status("Simulator stopped by user", "WARNING")
        display_device_state()
        client.disconnect()
        sys.exit(0)
    except Exception as e:
        print_status(f"Error: {e}", "ERROR")
        print_status("Please check your MQTT configuration in config.env", "ERROR")
        sys.exit(1)

if __name__ == "__main__":
    main()
