from collections import defaultdict
import os
import subprocess

# Rule list to store predefined rules and their usage frequency
rule_usage = {}

# Function to add a rule to iptables
def add_rule(rule):
    print(rule)
    os.system(f"sudo iptables -A INPUT -p tcp {rule} -j ACCEPT ")
    os.system(f"kali")

# Function to remove a rule from iptables
def remove_rule(rule):
    os.system(f"sudo iptables -D INPUT {rule} -j DROP")

# Function to update rule usage
def update_rule_usage(rule):
    if rule in rule_usage:
        rule_usage[rule] += 1
    else:
        rule_usage[rule] = 1

# Function to optimize rule placement (add frequently used rules first)
def optimize_rules():
    sorted_rules = sorted(rule_usage.items(), key=lambda item: item[1], reverse=True)
    optimizes_rules=[]
    for rule, _ in sorted_rules:
        optimizes_rules.append(rule)
        add_rule(rule)
    return optimizes_rules

# Example of adding and removing rules based on traffic analysis
def manage_rule_optimization(traffic_pattern):
    if traffic_pattern == "heavy":
        rule = "--dport 443 -p tcp"
        update_rule_usage(rule)
    elif traffic_pattern == "light":
        rule = "--dport 80 -p tcp"
        update_rule_usage(rule)

    optimize_rules()
    
def combine_similar_rules(rules):
    combined_rules = []

    if rules:
        # Combine rules by port or other criteria
        port_rules = defaultdict(list)
        
        for rule in rules:
            if '--dport' in rule:
                # Extract port from the rule
                port = rule.split('--dport ')[1].split(' ')[0]
                port_rules[port].append(rule)
        
        # For each port, either combine or retain the original rules
        for port, port_rule_list in port_rules.items():
            if len(port_rule_list) > 1:
                # Combine similar rules into one rule (if more than one rule for the same port)
                combined_rule = f'-p tcp --dport {port} -j DROP'
                combined_rules.append(combined_rule)
            else:
                # Keep the individual rule if only one exists for that port
                combined_rules.extend(port_rule_list)
    else:
        # If no rules are provided, just return an empty list
        combined_rules = []

    return combined_rules