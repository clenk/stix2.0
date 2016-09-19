import unittest
import copy
import json
from . import SCHEMA_DIR
from .. import validate_string
from ..validators import ValidationOptions

VALID_RELATIONSHIP = """
{
    "type": "relationship",
    "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:06:37Z",
    "modified": "2016-04-06T20:06:37Z",
    "version": 1,
    "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
    "relationship_type": "indicates"
}
"""


class RelationshipTestCases(unittest.TestCase):
    valid_relationship = json.loads(VALID_RELATIONSHIP)
    options = ValidationOptions(schema_dir=SCHEMA_DIR)

    def test_wellformed_relationship(self):
        results = validate_string(VALID_RELATIONSHIP, self.options).schema_results
        self.assertTrue(results.is_valid)

    def test_relationship_type(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['relationship_type'] = "SOMETHING"
        relationship = json.dumps(relationship)
        results = validate_string(relationship, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_source_relationship(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "relationship--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship = json.dumps(relationship)
        results = validate_string(relationship, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_source_sighting(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "sighting--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship = json.dumps(relationship)
        results = validate_string(relationship, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_target_bundle(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['target_ref'] = "bundle--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship = json.dumps(relationship)
        results = validate_string(relationship, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_target_marking_definition(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['target_ref'] = "marking-definition--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship = json.dumps(relationship)
        results = validate_string(relationship, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_lax_option(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['relationship_type'] = "SOMETHING"
        relationship = json.dumps(relationship)
        lax_options = ValidationOptions(schema_dir=SCHEMA_DIR, lax=True)
        results = validate_string(relationship, lax_options).schema_results
        self.assertEqual(results.is_valid, False)


if __name__ == "__main__":
    unittest.main()
