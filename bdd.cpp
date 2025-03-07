#include <bdd.h>
#include <iostream>
#include <map>
#include <string>

// Function to initialize BDD variables and create a simple AND operation for comparison
bdd create_bdd_rule(int var1, int var2) {
    // Initialize BuDDy
    bdd_init(1000, 100);
    bdd_setvarnum(2);  // Using 2 variables for the rule

    // Create BDD variables (representing two parts of the rule)
    bdd p = bdd_ithvar(var1);
    bdd q = bdd_ithvar(var2);

    // Perform AND operation between the two variables (representing a rule)
    bdd rule = p & q;
    return rule;
}

// Function to print the truth table of the BDD rule
void print_bdd(bdd rule) {
    bdd_printtable(rule);
}

// Function to compare captured traffic with predefined BDD rule
bool match_rule(bdd rule, int traffic_var1, int traffic_var2) {
    bdd p_traffic = bdd_ithvar(traffic_var1);
    bdd q_traffic = bdd_ithvar(traffic_var2);
    bdd traffic = p_traffic & q_traffic;

    // Compare the captured traffic with the rule (AND operation)
    return (bdd_equal(rule, traffic) == 1);
}
