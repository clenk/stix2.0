import unittest
import json 
from . import SCHEMA_DIR
from .. import ValidationOptions, validate_string, ValidationError

VALID_CUSTOM_OBJECT = """
{
  "type": "x-example-com-customobject",
  "id": "x-example-com-customobject--4527e5de-8572-446a-a57a-706f15467461",
  "created": "2016-08-01T00:00:00Z",
  "modified": "2016-08-01T00:00:00Z",
  "version": 1,
  "some_custom_stuff": 14,
  "other_custom_stuff": "hello"
}
"""


class CustomObjectTestCases(unittest.TestCase):
    valid_custom_object = json.loads(VALID_CUSTOM_OBJECT)
    options = ValidationOptions(schema_dir=SCHEMA_DIR)

    def test_wellformed_custom_object(self):
        results = validate_string(VALID_CUSTOM_OBJECT, self.options).schema_results
        self.assertTrue(results.is_valid)

    def test_no_type(self):
        custom_obj = dict(self.valid_custom_object)
        del custom_obj['type']
        custom_obj = json.dumps(custom_obj)
        self.assertRaises(ValidationError, validate_string, custom_obj, self.options)

    def test_no_id(self):
        custom_obj = dict(self.valid_custom_object)
        del custom_obj['id']
        custom_obj = json.dumps(custom_obj)
        results = validate_string(custom_obj, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_no_created(self):
        custom_obj = dict(self.valid_custom_object)
        del custom_obj['created']
        custom_obj = json.dumps(custom_obj)
        results = validate_string(custom_obj, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_no_modified(self):
        custom_obj = dict(self.valid_custom_object)
        del custom_obj['modified']
        custom_obj = json.dumps(custom_obj)
        results = validate_string(custom_obj, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_no_version(self):
        custom_obj = dict(self.valid_custom_object)
        del custom_obj['version']
        custom_obj = json.dumps(custom_obj)
        results = validate_string(custom_obj, self.options).schema_results
        self.assertEqual(results.is_valid, False)


if __name__ == "__main__":
    unittest.main()
