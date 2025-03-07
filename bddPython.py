# bdd.py
from pybdd import BDD

# Initialize BDD and declare variables
def initialize_bdd():
    bdd = BDD()
    bdd.declare('src_ip', 'dst_ip', 'port', 'protocol')  # Declare BDD variables
    return bdd

# Example: Create BDD rules
def create_rules(bdd):
    # Rule to block traffic from source IP "192.168.1.1"
    rule_block_ip = bdd.var('src_ip') & bdd.var('192.168.1.1')
    
    # Rule to allow traffic on port 80
    rule_allow_port_80 = bdd.var('port') & bdd.var('80')
    
    # Combine rules: Allow port 80 traffic but block "192.168.1.1"
    combined_rules = rule_allow_port_80 & ~rule_block_ip
    
    return combined_rules
