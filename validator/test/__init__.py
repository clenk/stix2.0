import unittest
import os
from .. import validate_string
from ..validators import ValidationOptions

SCHEMA_DIR = os.path.abspath(os.path.dirname(__file__) + "../../../schemas")


class ValidatorTest(unittest.TestCase):
    options = ValidationOptions(schema_dir=SCHEMA_DIR)

    def check_ignore(self, instance, ignored_error):
        """Test that the given instance is valid if the given error is ignored.
        """
        ignore_options = ValidationOptions(schema_dir=SCHEMA_DIR,
                                           ignored_errors=ignored_error)
        results = validate_string(instance, ignore_options).schema_results
        self.assertTrue(results.is_valid)
