
# builtin
import os
import sys
import argparse
import json
import logging

# external
from jsonschema import Draft4Validator, RefResolver
from jsonschema import exceptions as schema_exceptions
from six import python_2_unicode_compatible

#internal
from . import output


class ValidationError(Exception):
    """Base Exception for all validator-specific exceptions. This can be used
    directly as a generic Exception.
    """
    pass


class SchemaInvalidError(Exception):
    """Exception to be raised when schema validation fails for a given
    document.
    """
    def __init__(self, msg=None, results=None):
        super(SchemaInvalidError, self).__init__(msg)
        self.results = results


@python_2_unicode_compatible
class SchemaError(ValidationError):
    """Represents a JSON Schema validation error.

    Args:
        error: An error returned from JSON Schema validation

    Attributes:
        message: The JSON validation error message.

    """
    def __init__(self, error):
        super(SchemaError, self).__init__()

        if error:
            self.message = str(error)
        else:
            self.message = None

    def as_dict(self):
        """Returns a dictionary representation.
        """
        return {'message':self.message}

    def __str__(self):
        return str(self.message)



class FileResults(object):
    """Stores all validation results for given file.

    Args:
        fn: The filename/path for the file that was validated.
    Attributes:

        fn: The filename/path for the file that was validated.
        schema_results: JSON schema validation results.
        best_practice_results: STIX Best Practice validation results.
        profile_resutls: STIX Profile validation results.
        fatal: Fatal error

    """
    def __init__(self, fn=None):
        self.fn = fn
        self.schema_results = None
        # TODO
        # self.best_practice_results = None
        self.fatal = None


class BaseResults(object):
    """Base class for all validation result types.
    """
    def __init__(self, is_valid=False):
        self.is_valid = is_valid

    @property
    def is_valid(self):
        """Returns ``True`` if the validation attempt was successful and
        ``False`` otherwise.
        """
        return self._is_valid

    @is_valid.setter
    def is_valid(self, value):
        self._is_valid = bool(value)

    def as_dict(self):
        """Returns a dictionary representation of this class.

        Keys:
            ``'result'``: The validation result. Values will be ``True`` or
            ``False``.

        """
        return {'result': self.is_valid}

    def as_json(self):
        """Returns a JSON representation of this class instance.
        """
        return json.dumps(self.as_dict())


class ValidationResults(BaseResults):
    """Results of JSON schema validation.

    Args:
        is_valid: The validation result.
        errors: A list of strings reported from the JSON validation engine.

    Attributes:
        is_valid: ``True`` if the validation was successful and ``False``
            otherwise.

    """
    def __init__(self, is_valid, errors=None):
        super(ValidationResults, self).__init__(is_valid)
        self.errors = errors

    @property
    def errors(self):
        """"A list of :class:`SchemaError` validation errors.
        """
        return self._errors

    @errors.setter
    def errors(self, value):
        if not value:
            self._errors = []
        elif hasattr(value, "__iter__"):
            self._errors = [SchemaError(x) for x in value]
        else:
            self._errors = [SchemaError(value)]

    def as_dict(self):
        """A dictionary representation of the :class:`.ValidationResults`
        instance.

        Keys:
            * ``'result'``: The validation results (``True`` or ``False``)
            * ``'errors'``: A list of validation errors.
        Returns:

            A dictionary representation of an instance of this class.

        """
        d = super(ValidationResults, self).as_dict()

        if self.errors:
            d['errors'] = [x.as_dict() for x in self.errors]

        return d


class ValidationErrorResults(BaseResults):
    """Can be used to communicate a failed validation due to a raised Exception.

    Args:
        error: An ``Exception`` instance raised by validation code.

    Attributes:
        is_valid: Always ``False``.
        error: The string representation of the Exception being passed in.
        exception: The exception which produced these results.

    """
    def __init__(self, error):
        self._is_valid = False
        self.error = str(error)
        self.exception = error

    def as_dict(self):
        d = super(ValidationErrorResults, self).as_dict()
        d['error'] = self.error

        return d



def is_json(fn):
    """Returns ``True`` if the input filename `fn` ends with a JSON extension.
    """
    return os.path.isfile(fn) and fn.lower().endswith('.json')


def list_json_files(directory, recursive=False):
    """Returns a list of file paths for JSON files contained within `directory`.

    Args:
        directory: A path to a directory.
        recursive: If ``True``, this function will descend into all
            subdirectories.

    Returns:
        A list of JSON file paths directly under `directory`.

    """
    json_files = []

    for top, _, files in os.walk(directory):
        # Get paths to each file in `files`
        paths = (os.path.join(top, f) for f in files)

        # Add all the .json files to our return collection
        json_files.extend(x for x in paths if is_json(x))

        if not recursive:
            break

    return json_files


def get_json_files(files, recursive=False):
    """Returns a list of files to validate from `files`. If a member of `files`
    is a directory, its children with a ``.json`` extension will be added to
    the return value.

    Args:
        files: A list of file paths and/or directory paths.
        recursive: If ``true``, this will descend into any subdirectories
            of input directories.

    Returns:
        A list of file paths to validate.

    """
    json_files = []

    if not files:
        return json_files

    for fn in files:
        if os.path.isdir(fn):
            children = list_json_files(fn, recursive)
            json_files.extend(children)
        elif is_json(fn):
            json_files.append(fn)
        else:
            continue

    return json_files



def run_validation(options):
    """Validates files based on command line options.

    Args:
        options: An instance of ``argparse.Namespace`` containing options for
            this validation run.

    """
    # The JSON files to validate
    files = get_json_files(options.files, options.recursive)

    results = {}
    for fn in files:
        results[fn] = validate_file(fn, options)

    return results


def validate_file(fn, options):
    """Validates the input document `fn` with the validators that are passed
    in.

    If any exceptions are raised during validation, no further validation
    will take place.

    Args:
        schema_validator: An instance of STIXSchemaValidator (optional)
        profile_validator: An instance of STIXProfileValidator (optional)
        best_practice_validator: An instance of STIXBestPracticeValidator
            (optional).
        options: An instance of ``argparse.Namespace``.

    Returns:
        An instance of FileResults.

    """
    results = FileResults(fn)

    try:
        if options.files:
            results.schema_results = schema_validate(fn, options)
        # TODO
        # if options.best_practice_validate:
        #     results.best_practice_results = best_practice_validate(fn, options)
    except SchemaInvalidError as ex:
        results.schema_results = ex.results
        # TODO
        # if options.best_practice_validate:
        #     msg = ("File '{fn}' was schema-invalid. No further validation "
        #            "will be performed.")
        #    output.info(msg.format(fn=fn))
    except Exception as ex:
        results.fatal = ValidationErrorResults(ex)
        msg = ("Unexpected error occurred with file '{fn}'. No further "
               "validation will be performed: {error}")
        logging.info(msg.format(fn=fn, error=str(ex)))

    return results


def load_validator(schema_path, schema):
    try:
    	# Get correct prefix based on OS
        if os.name == 'nt':
            file_prefix = 'file:///'
        else:
            file_prefix = 'file:'

        resolver = RefResolver(file_prefix + schema_path.replace("\\", "/"), schema)
        validator = Draft4Validator(schema, resolver=resolver)

    except schema_exceptions.RefResolutionError:
        raise SchemaInvalidError('Invalid JSON schema')

    return validator


def load_schema(schema_path):
    try:
        with open(schema_path) as schema_file:
            schema = json.load(schema_file)
    except ValueError as e:
        raise SchemaInvalidError('Invalid JSON in schema or included schema: ' + schema_file.name + "\n" + str(e))

    return schema


def schema_validate(fn, options):
    """Performs STIX JSON Schema validation against the input filename.
    Finds the correct schema by looking at what folder the input file is in.

    Args:
        fn: A filename for a STIX JSON document
        options: ValidationOptions instance with validation options for this
            validation run.

    Returns:
        A dictionary of validation results

    """
    output.info("Performing JSON schema validation on %s" % fn)

    # Use correct slashes for OS
    if os.name == 'nt':
        slash = '\\'
    else:
        slash = '/'
    schema_path = options.schema_dir + slash + ('/').join(fn.split('tests'+slash)[1].split(slash)[0:-1]) + '.json'
    schema = load_schema(schema_path)
    validator = load_validator(schema_path, schema)

    with open(fn) as instance_file:
        instance = json.load(instance_file)

    # Actual validation
    errors = sorted(validator.iter_errors(instance), key=lambda e: e.path)
    error_list = [SchemaError(error.message) for error in errors]

    if len(errors) == 0:
        return ValidationResults(True)
    else:
        return ValidationResults(False, error_list)
