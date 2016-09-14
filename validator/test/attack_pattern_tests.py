import unittest
import copy
import json
from . import SCHEMA_DIR
from .. import validate_string
from ..validators import ValidationOptions

VALID_ATTACK_PATTERN = """
{
  "type": "attack-pattern",
  "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
  "created": "2016-05-12T08:17:27.000000Z",
  "modified": "2016-05-12T08:17:27.000000Z",
  "version": 1,
  "name": "Spear Phishing",
  "description": "...",
  "external_references": [
    {
      "source_name": "capec",
      "external_id": "CAPEC-463"
    }
  ]
}
"""


class AttackPatternTestCases(unittest.TestCase):
    valid_attack_pattern = json.loads(VALID_ATTACK_PATTERN)
    options = ValidationOptions(schema_dir=SCHEMA_DIR)

    def test_wellformed_attack_pattern(self):
        results = validate_string(VALID_ATTACK_PATTERN, self.options).schema_results
        self.assertTrue(results.is_valid)

    def test_valid_capec_id(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        ext_refs = attack_pattern['external_references']
        ext_refs[0]['external_id'] = "CAPEC-abc"
        attack_pattern = json.dumps(attack_pattern)
        results = validate_string(attack_pattern, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_external_reference_no_external_id(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        ext_refs = attack_pattern['external_references']
        del ext_refs[0]['external_id']
        attack_pattern = json.dumps(attack_pattern)
        results = validate_string(attack_pattern, self.options).schema_results
        self.assertEqual(results.is_valid, False)


if __name__ == "__main__":
    unittest.main()
