import unittest
import os
from .. import validate_string
from ..validators import ValidationOptions
import json

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

    def check_lax_prefix(self, instance):
        """Test that the given instance is valid if the --lax-prefix option is
        used for custom object types and custom properties.

        Args:
            instance: The JSON string to be validated.
        """
        lax_options = ValidationOptions(schema_dir=SCHEMA_DIR, lax_prefix=True)
        results = validate_string(instance, lax_options).schema_results
        self.assertTrue(results.is_valid)
