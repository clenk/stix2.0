"""STIX 2.0 open vocabularies and other lists
"""


# Error codes for setting which checks to ignore
IGNORE_CUSTOM_OBJECT_PREFIX =               '101'

IGNORE_ALL_VOCABS =                         '110'
IGNORE_ATTACK_MOTIVATION =                  '111'
IGNORE_ATTACK_RESOURCE_LEVEL =              '112'
IGNORE_IDENTITY_CLASS =                     '113'
IGNORE_INDICATOR_LABEL =                    '114'
IGNORE_INDUSTRY_SECTOR =                    '115'
IGNORE_MALWARE_LABEL =                      '116'
IGNORE_PATTERN_LANG =                       '117'
IGNORE_REPORT_LABEL =                       '118'
IGNORE_THREAT_ACTOR_LABEL =                 '119'
IGNORE_THREAT_ACTOR_ROLE =                  '120'
IGNORE_THREAT_ACTOR_SOPHISTICATION_LEVEL =  '121'
IGNORE_TOOL_LABEL =                         '122'
IGNORE_MARKING_DEFINITION_TYPE =            '129'

IGNORE_KILL_CHAIN_NAMES =                   '131'


# Enumerations of the default values of STIX open vocabularies
ATTACK_MOTIVATION_OV = [
    "accidental",
    "coercion",
    "dominance",
    "ideology",
    "notoriety",
    "organizational-gain",
    "personal-gain",
    "personal-satisfaction",
    "revenge",
    "unpredictable"
]
ATTACK_RESOURCE_LEVEL_OV = [
    "individual",
    "club",
    "contest",
    "team",
    "organization",
    "government"
]
IDENTITY_CLASS_OV = [
    "individual",
    "group",
    "organization",
    "class",
    "unknown"
]
INDICATOR_LABEL_OV = [
    "anomalous-activity",
    "anonymization",
    "benign",
    "compromised",
    "malicious-activity",
    "attribution"
]
INDUSTRY_SECTOR_OV = [
    "agriculture",
    "aerospace",
    "automotive",
    "communications",
    "construction",
    "defence",
    "education",
    "energy",
    "entertainment",
    "financial-services",
    "government-national",
    "government-regional",
    "government-local",
    "government-public-services",
    "healthcare",
    "hospitality-leisure",
    "infrastructure",
    "insurance",
    "manufacturing",
    "mining",
    "non-profit",
    "pharmaceuticals",
    "retail",
    "technology",
    "telecommunications",
    "transportation",
    "utilities"
]
MALWARE_LABEL_OV = [
    "adware",
    "backdoor",
    "bot",
    "ddos",
    "dropper",
    "exploit-kit",
    "keylogger",
    "ransomware",
    "remote-access-trojan",
    "resource-exploitation",
    "rogue-antivirus",
    "rootkit",
    "screen-capture",
    "spyware",
    "trojan",
    "virus",
    "worm"
]
PATTERN_LANG_OV = [
    "cybox",
    "openioc",
    "snort",
    "yara"
]
REPORT_LABEL_OV = [
    "threat-report",
    "attack-pattern",
    "campaign",
    "indicator",
    "malware",
    "observed-data",
    "threat-actor",
    "tool",
    "victim-target",
    "vulnerability"
]
THREAT_ACTOR_LABEL_OV = [
    "activist",
    "competitor",
    "crime-syndicate",
    "criminal",
    "hacker",
    "insider-accidental",
    "insider-disgruntled",
    "nation-state",
    "sensationalist",
    "spy",
    "terrorist"
]
THREAT_ACTOR_ROLE_OV = [
    "agent",
    "director",
    "independent",
    "infrastructure-architect",
    "infrastructure-operator",
    "malware-author",
    "sponsor"
]
THREAT_ACTOR_SOPHISTICATION_LEVEL_OV = [
    "none",
    "minimal",
    "intermediate",
    "advanced",
    "expert",
    "innovator",
    "strategic"
]
TOOL_LABEL_OV = [
    "denial-of-service",
    "exploitation",
    "information-gathering",
    "network-capture",
    "credential-exploitation",
    "remote-access",
    "vulnerability-scanning"
]


# Dictionaries mapping object types to properties that use a given vocabulary
ATTACK_MOTIVATION_USES = {
    "intrusion-set": ["primary_motivation", "secondary_motivations"],
    "threat-actor": ["primary_motivation", "secondary_motivations", "personal_motivations"]
}
ATTACK_RESOURCE_LEVEL_USES = {
    "intrusion-set": ["resource_level"],
    "threat-actor": ["resource_level"]
}
IDENTITY_CLASS_USES = {
    "identity": ["identity_class"]
}
INDICATOR_LABEL_USES = {
    "indicator": ["labels"]
}
INDUSTRY_SECTOR_USES = {
    "identity": ["sectors"]
}
MALWARE_LABEL_USES = {
    "malware": ["labels"]
}
PATTERN_LANG_USES = {
    "indicator": ["pattern_lang"]
}
REPORT_LABEL_USES = {
    "report": ["labels"]
}
THREAT_ACTOR_LABEL_USES = {
    "threat-actor": ["labels"]
}
THREAT_ACTOR_ROLE_USES = {
    "threat-actor": ["roles"]
}
THREAT_ACTOR_SOPHISTICATION_LEVEL_USES = {
    "threat-actor": ["sophistication"]
}
TOOL_LABEL_USES = {
    "tool": ["labels"]
}


# List of default STIX object types
TYPES = [
    "attack-pattern",
    "campaign",
    "course-of-action",
    "identity",
    "indicator",
    "intrusion-set",
    "malware",
    "observed-data",
    "report",
    "threat-actor",
    "tool",
    "vulnerability",
    "bundle",
    "relationship",
    "sighting",
    "marking-definition"
]


# List of default marking definition types
MARKING_DEFINITION_TYPES = [
    "statement",
    "tlp"
]

# List of object types which have a `kill-chain-phases` property
KILL_CHAIN_PHASE_USES = [
    "attack-pattern",
    "indicator",
    "malware",
    "tool"
]
