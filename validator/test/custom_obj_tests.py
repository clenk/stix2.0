import unittest
import copy
import json
from . import ValidatorTest
from .. import validate_string, ValidationError
from .. import enums

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


class CustomObjectTestCases(ValidatorTest):
    valid_custom_object = json.loads(VALID_CUSTOM_OBJECT)

    def test_wellformed_custom_object(self):
        results = validate_string(VALID_CUSTOM_OBJECT, self.options).schema_results
        self.assertTrue(results.is_valid)

    def test_no_type(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['type']
        custom_obj = json.dumps(custom_obj)
        self.assertRaises(ValidationError, validate_string, custom_obj, self.options)

    def test_no_id(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['id']
        custom_obj = json.dumps(custom_obj)
        results = validate_string(custom_obj, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_no_created(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['created']
        custom_obj = json.dumps(custom_obj)
        results = validate_string(custom_obj, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_no_modified(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['modified']
        custom_obj = json.dumps(custom_obj)
        results = validate_string(custom_obj, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_no_version(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['version']
        custom_obj = json.dumps(custom_obj)
        results = validate_string(custom_obj, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_invalid_type_name(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        custom_obj['type'] = "corpo_ration"
        custom_obj_string = json.dumps(custom_obj)
        results = validate_string(custom_obj_string, self.options).schema_results
        self.assertEqual(results.is_valid, False)

        custom_obj['type'] = "corpor@tion"
        custom_obj_string = json.dumps(custom_obj)
        results = validate_string(custom_obj_string, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_invalid_type_name_lax(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        custom_obj['type'] = "x-corporation"
        custom_obj_string = json.dumps(custom_obj)
        results = validate_string(custom_obj_string, self.options).schema_results
        self.assertEqual(results.is_valid, False)

        self.check_lax_prefix(custom_obj_string)

        self.check_ignore(custom_obj_string, enums.IGNORE_CUSTOM_OBJECT_PREFIX)

    def test_valid_type_name(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        custom_obj['type'] = "x-corp-oration"
        custom_obj_string = json.dumps(custom_obj)
        results = validate_string(custom_obj_string, self.options).schema_results
        self.assertTrue(results.is_valid)


if __name__ == "__main__":
    unittest.main()
