# rulevis

A simple tool to visualize the Wazuh ruleset for analysis of connections. It may help finding cycles, duplicates, and redundant rules.

## Requirements

- Python 3.9+
- Wazuh ruleset files including custom rules

## Installation

- Clone this repository
- Use your preferred virtual environment module for Python and activate
- use `pip install -r ./requirements.txt` to install dependencies
- Start using the script

## Usage

```shell
usage: rulevis [-h] --path PATH [--top TOP]

rulevis (0.1) is a Wazuh rule visualization tool.

options:
  -h, --help            show this help message and exit
  --path PATH, -p PATH  Path to the Wazuh rule directories. Comma-separated multiple paths are accepted.
  --top TOP, -t TOP     Top N XML files to process, especially for testing purposes
```

## Detecting cycles

We can now detect the cycles in the ruleset by default. Choose the color red to filter cycles. Below you can see that 80790 and 80791 are in a cycle due to `if_group` condition that the two ruless call each other. I have observed that these kind of cycles create an issue when the analysisd tries to create a tree of rules. Since a tree by definition should be a directed acyclic graph, the cycles crate recursive calls, and at one point analysisd creates a mesh topology between all possible childs.

I once created 8 rules that has the same group name in rule groups, also that is the condition in the `if_group` accidentally. That added around 2 minutes to the start time of the service. So, eliminating them would not only increase load performance but also the rule analysis when a rule in the cycle is hit. This is when the cycle detection came to my mind.

![A cycle detected](/assets/cycle.gif)

The detected cycle above are these rules below. As you can see, they use `audit_watch_write` on both in `if_group` condition and setting rule `group`.

```xml
  <rule id="80790" level="3">
    <if_group>audit_watch_write</if_group>
    <match>type=CREATE</match>
    <description>Audit: Created: $(audit.file.name).</description>
    <group>audit_watch_create,audit_watch_write,gdpr_II_5.1.f,gdpr_IV_30.1.g,</group>
  </rule>

  <rule id="80791" level="3">
    <if_group>audit_watch_write</if_group>
    <match>type=DELETE</match>
    <description>Audit: Deleted: $(audit.file.name).</description>
    <mitre>
      <id>T1070.004</id>
    </mitre>
    <group>audit_watch_delete,audit_watch_write,gdpr_II_5.1.f,gdpr_IV_30.1.g,</group>
  </rule>
```

## Note

Beware the higher the number of the nodes, the higher the CPU and memory usage, the longer drawing time. Start by using `-t` and increase incrementally to ensure it works.

## Internals

Wazuh rules are designed with a tree-like structure in mind.

```c
typedef struct _RuleNode {
    RuleInfo *ruleinfo;
    struct _RuleNode *next;
    struct _RuleNode *child;
} RuleNode;
```

A rule node is a linked-list node actually. It contains the deserialized data struct parsed through the pseudo-XML rules. Tne `*next` is the thing that allows traversal. But the `*child` allows rules to have child rules either by id, group or category through `<ifsid>`,`<if_matched_sid>`, `<if_group>`, `<if_matched_group>` or `<category>` tags. Mind that the `<category>` check has not been implemented yet. Since it would not be wise to have clusters of rules to match, there is a root node which has a `NULL` value:

```c
RuleNode *os_analysisd_rulelist;

/* Create the RuleList */
void OS_CreateRuleList() {
    os_analysisd_rulelist = NULL;
}

/* Get first node from rule */
RuleNode *OS_GetFirstRule()
{
    RuleNode *rulenode_pt = os_analysisd_rulelist;
    return (rulenode_pt);
}
```

Let's visualise what does this mean. The diagram belows shows the root node and 2 rules. They both have one child. The Rule 1 and Rule 2 has no parent-child relationship, so they are added as nodes in the linked-list.

![2 rules ant the root](/assets/tree1.png)

Let's add another rule. Rule 3 is added as next but has a parent-child relationship with Rule 2-child. It may happen via `if_mathched_*` connections.

![3 rules and the root](/assets/tree2.png)

Let's make it complicated. It is possible that a rule may be child of many rules. think about multiple authentication failures. We add a condition, so that Rule 3 is child of Rule 1 and rule 2-child simultaneously.

![3 rules and the root, but it is complicated](/assets/tree3.png)

Now, let's add a Rule 4, and due to the cycle in their conditions, Rule 2 is a child of Rule 4 and vice versa. Sorry for the extra line, I could not get rid of it.

![4 rules and the root, with a cycle](/assets/tree4.png)

If you consider the number of rules, you can find that the topology created with this becomes more complex. That is how `analysisd` works until the release of [the new engine](https://github.com/wazuh/wazuh/issues/24312).

However in my visualization, I ignored the root rule and linked-list as they are an implementation detail of the abstraction of rules in the memory. Therefore, I visualise the rules as DAG in-mind, not a tree-like structure. Though, you can see that there are cycles in the ruleset.

![A screenshot of the whole default ruleset](/assets/full.png)

![A screenshot of a single rule cluster](/assets/single.png)