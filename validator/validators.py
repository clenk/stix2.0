"""Custom jsonschema.IValidator class and validator functions.
"""

# builtin
import re
from collections import deque

# external
from jsonschema import Draft4Validator
from jsonschema import exceptions as schema_exceptions


class JSONError(schema_exceptions.ValidationError):
    """Wrapper for errors originating from iter_errors() in the jsonschema module.
    """
    def __init__(self, msg=None, instance_type=None):
        super(JSONError, self).__init__(msg, path=deque([instance_type]))


# Checks for MUST Requirements

def modified_created(instance):
    """`modified` property must be later or equal to `created` property
    """
    if 'modified' in instance and 'created' in instance and \
            instance['modified'] < instance['created']:
        return JSONError("'modified' (%s) must be later or equal to 'created' (%s)"\
            % (instance['modified'], instance['created']), instance['type'])

def version(instance):
    """Check constraints on 'version' property
    """
    if 'version' in instance and 'modified' in instance and \
            'created' in instance:
        if instance['version'] == 1 and instance['modified'] != instance['created']:
            return JSONError("'version' is 1, but 'created' (%s) is not "\
                "equal to 'modified' (%s)" \
                % (instance['created'], instance['modified']), instance['type'])
        elif instance['version'] > 1 and instance['modified'] <= instance['created']:
            return JSONError("'version' is greater than 1, but 'modified'"\
                " (%s) is not greater than 'created' (%s)" \
                % (instance['modified'], instance['created']), instance['type'])

def cybox(instance):
    """Ensure that if CybOX is used, version 1.0 of the patterning language is used.
    """
    if instance['type'] == 'indicator' and 'pattern_lang' in instance and \
            instance['pattern_lang'] == 'cybox':
        if 'pattern_lang_version' in instance and instance['pattern_lang_version'] != '1.0':
            return JSONError("'pattern_lang' is 'cybox' but " \
                 "'pattern_lang_version' is not '1.0'!", instance['type'])

def capec(instance):
    """If CAPEC is used in an attack pattern's external reference,
    ensure a CAPEC id is also used.
    """
    if instance['type'] == 'attack-pattern' and 'external_references' in instance:
        for ref in instance['external_references']:
            if ref['source_name'] == 'capec' and 'external_id' not in ref or \
                    re.match('^CAPEC-\d+$', ref['external_id']) is None:
                return JSONError("A CAPEC 'external_reference' must have an "\
                        "'external_id' formatted as CAPEC-[id]", 'external_reference')

def custom_property_names(instance):
    """Ensure the names of custom properties are valid.
    """
    for prop_name in instance.keys():
        if not re.match('[a-z0-9_]{3,250}', prop_name):
            return JSONError("Custom property names must only contain the" \
                "lowercase ASCII letters a-z, 0-9, and underscore(_).", 'custom property')




# Checks for SHOULD Requirements
# TODO


class CustomDraft4Validator(Draft4Validator):
    """Custom validator class for JSON Schema Draft 4.

    """
    def __init__(self, schema, types=(), resolver=None, format_checker=None, options=None):
        super(CustomDraft4Validator, self).__init__(schema, types, resolver, format_checker)
        # Construct list of validators to be run by this validator
        self.validator_list = [
            modified_created,
            version,
            cybox,
            capec,
        ]

    def iter_errors_more(self, instance, options=None, _schema=None):
        """Adds a custom function to perform additional validation not possible
        merely with JSON schemas.

        """
        # Ensure `instance` is a whole STIX object, not just a property of one
        if not (type(instance) is dict and 'id' in instance and 'type' in instance):
            return

        if _schema is None:
            _schema = self.schema

        # Perform validation
        for v_function in self.validator_list:
            result = v_function(instance)
            if result is not None:
                yield result

        # Validate any child STIX objects
        for field in instance:
            if type(instance[field]) is list:
                for obj in instance[field]:
                    for err in self.iter_errors_more(obj, _schema):
                        yield err