import unittest
import json
from . import SCHEMA_DIR
from .. import ValidationOptions, validate_string

VALID_THREAT_ACTOR = """
{
  "type": "threat-actor",
  "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:48Z",
  "modified": "2016-04-06T20:03:48Z",
  "version": 1,
  "labels": ["hacker"],
  "name": "Evil Org",
  "description": "The Evil Org threat actor group"
}
"""


class ThreatActorTestCases(unittest.TestCase):
    valid_threat_actor = json.loads(VALID_THREAT_ACTOR)
    options = ValidationOptions(schema_dir=SCHEMA_DIR)

    def test_wellformed_threat_actor(self):
        results = validate_string(VALID_THREAT_ACTOR, self.options).schema_results
        self.assertTrue(results.is_valid)

    def test_vocab_attack_motivation(self):
        threat_actor = dict(self.valid_threat_actor)
        threat_actor['primary_motivation'] = ["selfishness", "pride"]
        threat_actor = json.dumps(threat_actor)
        results = validate_string(threat_actor, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_vocab_attack_resource_level(self):
        threat_actor = dict(self.valid_threat_actor)
        threat_actor['resource_level'] = "high"
        threat_actor = json.dumps(threat_actor)
        results = validate_string(threat_actor, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_vocab_threat_actor_label(self):
        threat_actor = dict(self.valid_threat_actor)
        threat_actor['labels'] += "anonymous"
        threat_actor = json.dumps(threat_actor)
        results = validate_string(threat_actor, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_vocab_threat_actor_role(self):
        threat_actor = dict(self.valid_threat_actor)
        threat_actor['role'] = "contributor"
        threat_actor = json.dumps(threat_actor)
        results = validate_string(threat_actor, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_vocab_threat_actor_sophistication_level(self):
        threat_actor = dict(self.valid_threat_actor)
        threat_actor['sophistication_level'] = "high"
        threat_actor = json.dumps(threat_actor)
        results = validate_string(threat_actor, self.options).schema_results
        self.assertEqual(results.is_valid, False)


if __name__ == "__main__":
    unittest.main()
