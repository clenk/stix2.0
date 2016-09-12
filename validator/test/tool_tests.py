import unittest
import json
from . import SCHEMA_DIR
from .. import ValidationOptions, validate_string

VALID_TOOL = """
{
  "type": "tool",
  "id": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:48Z",
  "modified": "2016-04-06T20:03:48Z",
  "version": 1,
  "name": "VNC",
  "labels": ["remote-access"]
}
"""


class ToolTestCases(unittest.TestCase):
    valid_tool = json.loads(VALID_TOOL)
    options = ValidationOptions(schema_dir=SCHEMA_DIR)

    def test_wellformed_tool(self):
        results = validate_string(VALID_TOOL, self.options).schema_results
        self.assertTrue(results.is_valid)

    def test_vocab_tool_label(self):
        tool = dict(self.valid_tool)
        tool['labels'] += ["multi-purpose"]
        tool = json.dumps(tool)
        results = validate_string(tool, self.options).schema_results
        self.assertEqual(results.is_valid, False)


if __name__ == "__main__":
    unittest.main()
