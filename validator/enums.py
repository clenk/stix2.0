"""STIX 2.0 open vocabularies and other lists
"""


# Error codes for setting which checks to ignore
IGNORE_CUSTOM_OBJECT_PREFIX =               '101'
IGNORE_CUSTOM_PROPERTY_PREFIX =             '102'

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


# Mapping of official STIX objects to their official properties
PROPERTIES = {
    "attack-pattern": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'kill_chain_phases'
    ],
    "campaign": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'aliases',
        'first_seen',
        'first_seen_precision',
        'objective'
    ],
    "course-of-action": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'action'
    ],
    "identity": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'identity_class',
        'sectors',
        'regions',
        'nationalities',
        'contact_information'
    ],
    "indicator": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'pattern',
        'pattern_lang',
        'pattern_lang_version',
        'valid_from',
        'valid_from_precision',
        'valid_until',
        'valid_until_precision',
        'kill_chain_phases'
    ],
    "intrusion-set": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'aliases',
        'first_seen',
        'first_seen_precision',
        'goals',
        'resource_level',
        'primary_motivation',
        'secondary_motivations',
        'region',
        'country'
    ],
    "malware": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'kill_chain_phases'
    ],
    "observed-data": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'first_observed',
        'last_observed',
        'number_observed',
        'cybox'
    ],
    "report": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'published',
        'object_refs'
    ],
    "threat-actor": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'aliases',
        'roles',
        'goals',
        'sophistication',
        'resource_level',
        'primary_motivation',
        'secondary_motivations',
        'personal_motivations'
    ],
    "tool": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'kill_chain_phases',
        'tool_version'
    ],
    "vulnerability": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description'
    ],
    "bundle": [
        'type',
        'id',
        'spec_version',
        'attack_patterns',
        'campaigns',
        'courses_of_action',
        'identities',
        'indicators',
        'intrusion_sets',
        'malware',
        'marking_definitions',
        'observed_data',
        'relationships',
        'reports',
        'sightings',
        'threat_actors',
        'tools',
        'vulnerabilities',
        'custom_objects'
    ],
    "relationship": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'relationship_type',
        'description',
        'source_ref',
        'target_ref'
    ],
    "sighting": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'first_seen',
        'first_seen_precision',
        'last_seen',
        'last_seen_precision',
        'count',
        'sighting_of_ref',
        'observed_data_refs',
        'where_sighted_refs',
        'summary'
    ],
    "marking-definition": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'definition_type',
        'definition'
    ]
}
