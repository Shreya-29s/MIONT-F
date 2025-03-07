from flask import Flask, request, jsonify
from flask import send_from_directory
import subprocess
from collections import defaultdict
import threading
import pyshark
from ruleOptimization import manage_rule_optimization, combine_similar_rules

# Flask application initialization
app = Flask(__name__)

# Function to dynamically block IPs based on packet count
def block_high_traffic_ips(ip_count, packet_threshold):
    iptables_rules = []
    for ip, count in ip_count.items():
        print(f"IP: {ip} - Packets: {count}")

        # Dynamically update iptables for high traffic
        if count > packet_threshold:
            print(f"Blocking IP: {ip} - Exceeds packet threshold")
            iptables_rules.append(f'-s {ip} -j DROP')

    return iptables_rules

# Apply optimized rules
def apply_optimized_rules(iptables_rules):
    print("\nOptimizing iptables rules...")
    optimized_rules = manage_rule_optimization(iptables_rules)
    combined_optimized_rules = combine_similar_rules(optimized_rules)

    for rule in combined_optimized_rules:
        add_rule_to_iptables(rule)

    print("Optimized iptables rules applied.")

# Add a rule to iptables

def add_rule_to_iptables(rule): 
    try:
        command = ["sudo", "iptables","-A","INPUT"] + rule.split()
        print(f"Executing command: {' '.join(command)}")  # Debug statement

        process = subprocess.run(command, capture_output=True, text=True)

        if process.returncode != 0:  # Check for errors
            print(f"Error adding rule: {process.stderr.strip()}")
            return process.stderr.strip()  # Return error message
        else:
            print(f"Rule added successfully: {rule}")
            return f"Rule added: {rule}"
    except Exception as e:
        print(f"Exception: {str(e)}")
        return str(e)  # Return exception for debugging

# Example usage
#add_rule_to_iptables("-A INPUT -s 34.117.188.166 -j DROP")

# Fetch iptables rules
def get_iptables_rules():
    try:
        command = ["sudo", "iptables", "-L", "-v", "-n", "--line-numbers"]
        print(f"Executing command: {' '.join(command)}")  # Debug statement

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        if error:
            return {"error": error.decode()}
        return parse_iptables_output(output.decode())
    except Exception as e:
        return {"error": str(e)}

# Parse iptables output
def parse_iptables_output(output):
    rules = {}
    current_chain = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Chain"):
            current_chain = line.split()[1]
            rules[current_chain] = []
        elif current_chain and line and not line.startswith("target") and not line.startswith("pkts"):
            rules[current_chain].append(line)
    return rules

# Live traffic capture
def capture_live_traffic(packet_threshold):
    ip_count = defaultdict(int)

    def process_packet(packet):
        try:
            if 'IP' in packet:
                ip_src = packet.ip.src
                ip_count[ip_src] += 1

                # Block IP if it exceeds threshold
                if ip_count[ip_src] > packet_threshold:
                    print(f"High traffic detected from {ip_src}. Blocking...")
                    add_rule_to_iptables(f"-s {ip_src} -j DROP")
        except AttributeError:
            pass

    print("Starting live traffic capture...")
    capture = pyshark.LiveCapture(interface="eth0")  # Replace 'eth0' with your network interface
    capture.apply_on_packets(process_packet)

# API to fetch iptables rules
@app.route('/iptables-rules', methods=['GET'])
def fetch_rules():
    rules = get_iptables_rules()
    if "error" in rules:
        return jsonify({"status": "error", "message": rules["error"]}), 500
    return jsonify({"status": "success", "rules": rules})

# API to add a new iptables rule
@app.route('/add-rule', methods=['POST'])
def api_add_rule():
    try:
        data = request.json
        print(f"Received data: {data}")  # Debug statement

        chain = data.get('chain')
        action = data.get('action')
        protocol = data.get('protocol', '')
        source = data.get('source', '')
        destination = data.get('destination', '')
        sport = data.get('sport', '')
        dport = data.get('dport', '')
        in_interface = data.get('in_interface', '')
        out_interface = data.get('out_interface', '')

        if not chain or not action:
            return jsonify({"status": "error", "message": "Missing required fields: 'chain' and 'action'"}), 400

        # Construct the iptables rule
        command = ["sudo", "iptables", "-A", chain]

        if protocol:
            command.extend(["-p", protocol])
        if source:
            command.extend(["-s", source])
        if destination:
            command.extend(["-d", destination])
        if sport:
            command.extend(["--sport", str(sport)])
        if dport:
            command.extend(["--dport", str(dport)])
        if in_interface:
            command.extend(["-i", in_interface])
        if out_interface:
            command.extend(["-o", out_interface])

        command.extend(["-j", action])

        # Execute the command
        print(f"Executing command: {' '.join(command)}")  # Debug statement
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, error = process.communicate()

        if error:
            return jsonify({"status": "error", "message": error.decode()}), 500

        return jsonify({"status": "success", "message": "Rule added successfully."})
    except Exception as e:
        print(f"Exception: {str(e)}")  # Debug statement
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

# Main function
if __name__ == '__main__':
    # Packet threshold
    packet_threshold = 20

    # Start live traffic capture in a separate thread
    threading.Thread(target=capture_live_traffic, args=(packet_threshold,), daemon=True).start()

    # Start the Flask app
    app.run(host="0.0.0.0", port=5000, debug=True)  # Run Flask in debug mode for better error visibility
