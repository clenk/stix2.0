import unittest
import os
from .. import validate_string
from ..validators import ValidationOptions

SCHEMA_DIR = os.path.abspath(os.path.dirname(__file__) + "../../../schemas")


class ValidatorTest(unittest.TestCase):
    options = ValidationOptions(schema_dir=SCHEMA_DIR)

    def check_ignore(self, instance, error):
        """Test that the given instance is valid if the given error is ignored.

        Args:
            instance: The JSON string to be validated.
            error: The numerical error code to be ignored.
        """
        self.assertTrueWithOptions(instance, ignored_errors=error)

    def check_lax_prefix(self, instance):
        """Test that the given instance is valid if the --lax-prefix option is
        used for custom object types and custom properties.

        Args:
            instance: The JSON string to be validated.
        """
        self.assertTrueWithOptions(instance, lax_prefix=True)

    def assertTrueWithOptions(self, instance, **kwargs):
        """Test that the given instance is valid when using the validation
        options provided by kwargs.

        Args:
            instance: The JSON string to be validated.
            kwargs: Any number of keyword arguments to be passed to the
                    ValidationOptions constructor.
        """
        options = ValidationOptions(schema_dir=SCHEMA_DIR, **kwargs)
        results = validate_string(instance, options).schema_results
        self.assertTrue(results.is_valid)
