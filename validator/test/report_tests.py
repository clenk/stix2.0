import unittest
import json
from . import SCHEMA_DIR
from .. import ValidationOptions, validate_string

VALID_REPORT = """
{
  "type": "report",   
  "id": "report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
  "created_by_ref": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283",
  "created": "2015-12-21T19:59:11Z",
  "modified": "2016-05-21T19:59:11Z",
  "published": "2016-05-21T19:59:11Z",
  "version": 2,
  "name": "The Black Vine Cyberespionage Group",
  "description": "A simple report with an indicator and campaign",
  "labels": ["campaign"],
  "object_refs": [
    "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
    "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
    "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a"
  ]
}
"""


class IdentityTestCases(unittest.TestCase):
    valid_report = json.loads(VALID_REPORT)
    options = ValidationOptions(schema_dir=SCHEMA_DIR)

    def test_wellformed_report(self):
        results = validate_string(VALID_REPORT, self.options).schema_results
        self.assertTrue(results.is_valid)

    def test_vocab_report_label(self):
        report = dict(self.valid_report)
        report['labels'] = ["something"]
        report = json.dumps(report)
        results = validate_string(report, self.options).schema_results
        self.assertEqual(results.is_valid, False)


if __name__ == "__main__":
    unittest.main()