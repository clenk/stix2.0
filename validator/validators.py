"""Custom jsonschema.IValidator class and validator functions.
"""

# builtin
import re
from collections import deque

# external
from jsonschema import Draft4Validator
from jsonschema import exceptions as schema_exceptions

# internal
from . import enums


class ValidationOptions(object):
    """Collection of validation options which can be set via command line or
    programmatically in a script.

    It can be initialized either by passing in the result of parse_args() from
    argparse, or by specifying individual options.

    Args:
        cmd_args: An instance of ``argparse.Namespace`` containing options
            supplied on the command line.
        verbose: True if informational notes and more verbose error messages
            should be printed to stdout/stderr.
        files: A list of input files and directories of files to be
            validated.
        recursive: Recursively descend into input directories.
        schema_dir: A user-defined schema directory to validate against.

    Attributes:
        verbose: True if informational notes and more verbose error messages
            should be printed to stdout/stderr.
        files: A list of input files and directories of files to be
            validated.
        recursive: Recursively descend into input directories.
        schema_dir: A user-defined schema directory to validate against.

    """
    def __init__(self, cmd_args=None, verbose=False, files=None, recursive=False, schema_dir=None, ignored_errors="", lax=False, lax_prefix=False):
        if cmd_args is not None:
            self.verbose = cmd_args.verbose
            self.files = cmd_args.files
            self.recursive = cmd_args.recursive
            self.schema_dir = cmd_args.schema_dir
            self.ignored_errors = cmd_args.ignored_errors
            self.lax = cmd_args.lax
            self.lax_prefix = cmd_args.lax_prefix
        else:
            # SHOULD requirements
            # TODO
            # self.best_practice_validate = False

            # input options
            self.files = files
            self.recursive = recursive
            self.schema_dir = schema_dir

            # output options
            self.verbose = verbose
            self.ignored_errors = ignored_errors
            self.lax = lax
            self.lax_prefix = lax_prefix


class JSONError(schema_exceptions.ValidationError):
    """Wrapper for errors thrown by iter_errors() in the jsonschema module.
    """
    def __init__(self, msg=None, instance_type=None):
        super(JSONError, self).__init__(msg, path=deque([instance_type]))


# Checks for MUST Requirements

def modified_created(instance):
    """`modified` property must be later or equal to `created` property
    """
    if 'modified' in instance and 'created' in instance and \
            instance['modified'] < instance['created']:
        return JSONError("'modified' (%s) must be later or equal to 'created' (%s)"
            % (instance['modified'], instance['created']), instance['type'])


def version(instance):
    """Check constraints on 'version' property
    """
    if 'version' in instance and 'modified' in instance and \
            'created' in instance:
        if instance['version'] == 1 and instance['modified'] != instance['created']:
            return JSONError("'version' is 1, but 'created' (%s) is not "
                "equal to 'modified' (%s)" 
                % (instance['created'], instance['modified']), instance['type'])
        elif instance['version'] > 1 and instance['modified'] <= instance['created']:
            return JSONError("'version' is greater than 1, but 'modified'"
                " (%s) is not greater than 'created' (%s)" 
                % (instance['modified'], instance['created']), instance['type'])


def cybox(instance):
    """Ensure that if CybOX is used, it is CybOX version 1.0.
    """
    if instance['type'] == 'indicator' and 'pattern_lang' in instance and \
            instance['pattern_lang'] == 'cybox':
        if 'pattern_lang_version' in instance and instance['pattern_lang_version'] != '1.0':
            return JSONError("'pattern_lang' is 'cybox' but " 
                 "'pattern_lang_version' is not '1.0'!", instance['type'])


def capec(instance):
    """If CAPEC is used in an attack pattern's external reference,
    ensure a CAPEC id is also used.
    """
    if instance['type'] == 'attack-pattern' and 'external_references' in instance:
        for ref in instance['external_references']:
            if ref['source_name'] == 'capec' and 'external_id' not in ref or \
                    re.match('^CAPEC-\d+$', ref['external_id']) is None:
                return JSONError("A CAPEC 'external_reference' must have an "
                        "'external_id' formatted as CAPEC-[id]", 'external_reference')


def custom_property_names(instance):
    """Ensure the names of custom properties are valid.
    """
    for prop_name in instance.keys():
        if not re.match('^[a-z0-9_]{3,250}$|id', prop_name):
            return JSONError("Custom property names must be between 3 and 250 "
                             "characters long and only contain the lowercase "
                             "ASCII letters a-z, 0-9, and underscore(_)",
                             'custom property (' + prop_name + ')')


def cve(instance):
    """If CAPEC is used in an attack pattern's external reference,
    ensure a CAPEC id is also used.
    """
    if instance['type'] == 'vulnerability' and 'external_references' in instance:
        for ref in instance['external_references']:
            if ref['source_name'] == 'cve' and 'external_id' not in ref or \
                    re.match('^CVE-\d{4}-(0\d{3}|[1-9]\d{3,})$', ref['external_id']) is None:
                return JSONError("A CVE 'external_reference' must have an "
                        "'external_id' formatted as CAPEC-[id]", 'external_reference (CVE)')
            elif 'external_id' in ref and re.match('^CVE-\d{4}-(0\d{3}|[1-9]\d{3,})$', ref['external_id']) \
                    and ref['source_name'] != 'cve':
                return JSONError("A CVE 'external_reference' must have a "
                        "'source_name' of 'cve'", 'external_reference (CVE)')


def empty_lists(instance):
    """Ensure that all lists are non-empty.
    This function is necesary because schemas won't check custom objects.
    """
    for prop_name in instance.keys():
        if type(instance[prop_name]) is list and len(instance[prop_name]) == 0:
            return JSONError("Empty lists are not permitted", prop_name)


def id_type(instance):
    """Ensure that an object's id` starts with its type.
    Checking of the UUID portion of the id is handled in the JSON schemas.
    """
    t = instance['type']
    if not re.search("%s\-\-" % t, instance['id']):
        return JSONError("'id' must be prefixed by %s--." % t, t)


def timestamp_precision(instance):
    """Ensure that for every precision property there is a matching timestamp
    property that uses the proper timestamp format for the given precision.
    """
    for prop_name in instance.keys():
        precision_matches = re.match("^(.*)_precision$", prop_name)
        if not precision_matches:
            continue

        ts_field = precision_matches.group(1)
        if ts_field not in instance:
            return JSONError("There is no corresponding %s field" % ts_field, prop_name)

        pattern = ""
        if instance[prop_name] == 'year':
            pattern = "^[0-9]{4}-01-01T00:00:00(\\.0+)?Z$"
        elif instance[prop_name] == 'month':
            pattern = "^[0-9]{4}-[0-9]{2}-01T00:00:00(\\.0+)?Z$"
        elif instance[prop_name] == 'day':
            pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00(\\.0+)?Z$"
        elif instance[prop_name] == 'hour':
            pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:00:00(\\.0+)?Z$"
        elif instance[prop_name] == 'minute':
            pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:00(\\.0+)?Z$"

        if not re.match(pattern, instance[ts_field]):
            return JSONError("Timestamp is not the correct format for '%s' "
                             "precision." % instance[prop_name], ts_field)


# Checks for SHOULD Requirements

def check_vocab(instance, vocab):
    """Ensure that the open vocabulary specified by `vocab` is used properly.

    It checks properties of objects specified in the appropriate `_USES`
    dictionary to determine which properties SHOULD use the given vocabulary,
    then checks that the values in those properties are from the vocabulary.
    """
    vocab_uses = getattr(enums, vocab + "_USES")
    for k in vocab_uses.keys():
        if instance['type'] == k:
            for prop in vocab_uses[k]:
                if prop not in instance:
                    continue

                vocab_ov = getattr(enums, vocab + "_OV")
                if type(instance[prop]) is list:
                    is_in = set(instance[prop]).issubset(set(vocab_ov))
                else:
                    is_in = instance[prop] in vocab_ov

                if not is_in:
                    vocab_name = vocab.replace('_', '-').lower()
                    return JSONError("%s contains a value not in the %s-ov "
                                     "vocabulary." % (prop, vocab_name), prop)


def vocab_attack_motivation(instance):
    return check_vocab(instance, "ATTACK_MOTIVATION")


def vocab_attack_resource_level(instance):
    return check_vocab(instance, "ATTACK_RESOURCE_LEVEL")


def vocab_identity_class(instance):
    return check_vocab(instance, "IDENTITY_CLASS")


def vocab_indicator_label(instance):
    return check_vocab(instance, "INDICATOR_LABEL")


def vocab_industry_sector(instance):
    return check_vocab(instance, "INDUSTRY_SECTOR")


def vocab_malware_label(instance):
    return check_vocab(instance, "MALWARE_LABEL")


def vocab_pattern_lang(instance):
    return check_vocab(instance, "PATTERN_LANG")


def vocab_report_label(instance):
    return check_vocab(instance, "REPORT_LABEL")


def vocab_threat_actor_label(instance):
    return check_vocab(instance, "THREAT_ACTOR_LABEL")


def vocab_threat_actor_role(instance):
    return check_vocab(instance, "THREAT_ACTOR_ROLE")


def vocab_threat_actor_sophistication_level(instance):
    return check_vocab(instance, "THREAT_ACTOR_SOPHISTICATION_LEVEL")


def vocab_tool_label(instance):
    return check_vocab(instance, "TOOL_LABEL")


def vocab_marking_definition(instance):
    """Ensure that the `definition_type` property of `marking-definition`
    objects is one of the values in the STIX 2.0 specification.
    """
    if (instance['type'] == 'marking-definition' and
            'definition_type' in instance and not
            instance['definition_type'] in enums.MARKING_DEFINITION_TYPES):

        return JSONError("Marking definition's `definition_type` should be one of "
                         "%s." % enums.MARKING_DEFINITION_TYPES, instance['type'])


def kill_chain_phase_names(instance):
    """Ensure the `kill_chain_name` and `phase_name` properties of
    `kill_chain_phase` objects follow naming style conventions.
    """
    if instance['type'] in enums.KILL_CHAIN_PHASE_USES and 'kill_chain_phases' in instance:
        for phase in instance['kill_chain_phases']:

            chain_name = phase['kill_chain_name']
            if not chain_name.islower() or '_' in chain_name or ' ' in chain_name:
                return JSONError("kill_chain_name (%s) should be all lowercase"
                                 " and use dashes instead of spaces or "
                                 "underscores as word separators." % chain_name,
                                 instance['type'])

            phase_name = phase['phase_name']
            if not phase_name.islower() or '_' in phase_name or ' ' in phase_name:
                return JSONError("phase_name (%s) should be all lowercase and "
                                 "use dashes instead of spaces or underscores "
                                 "as word separators." % phase_name,
                                 instance['type'])


def custom_object_prefix_strict(instance):
    """Ensure custom objects follow strict naming style conventions.
    """
    if instance['type'] not in enums.TYPES and not re.match("^x\-.+\-.+$", instance['type']):
        return JSONError("Custom objects should have a type that starts with "
                         "'x-' followed by a source unique identifier (like "
                         "a domain name with dots replaced by dashes), a dash "
                         "and then the name.", instance['type'])


def custom_object_prefix_lax(instance):
    """Ensure custom objects follow lenient naming style conventions
    for forward-compatibility.
    """
    if instance['type'] not in enums.TYPES and not re.match("^x\-.+$", instance['type']):
        return JSONError("Custom objects should have a type that starts with "
                         "'x-' in order to be compatible with future versions"
                         " of the STIX 2 specification.", instance['type'])


def custom_property_prefix_strict(instance):
    """Ensure custom properties follow strict naming style conventions.

    Does not check property names in custom objects.
    """
    for prop_name in instance.keys():
        if (instance['type'] in enums.PROPERTIES and
                prop_name not in enums.PROPERTIES[instance['type']] and
                not re.match("^x_.+_.+$", prop_name)):

            return JSONError("Custom properties should have a type that starts"
                             " with 'x_' followed by a source unique "
                             "identifier (like a domain name with dots "
                             "replaced by dashes), a dash and then the name.",
                             prop_name)


def custom_property_prefix_lax(instance):
    """Ensure custom properties follow lenient naming style conventions
    for forward-compatibility.

    Does not check property names in custom objects.
    """
    for prop_name in instance.keys():
        if (instance['type'] in enums.PROPERTIES and
                prop_name not in enums.PROPERTIES[instance['type']] and
                not re.match("^x_.+$", prop_name)):

            return JSONError("Custom properties should have a type that starts"
                             " with 'x_' in order to be compatible with future"
                             " versions of the STIX 2 specification.",
                             prop_name)


def relationships_strict(instance):
    """Ensure that only the relationship types defined in the specification are
    used.
    """
    if (instance['type'] != 'relationship' or
            instance['type'] not in enums.TYPES):
        return

    r_type = instance['relationship_type']
    r_source = re.search("(.+)\-\-", instance['source_ref']).group(1)
    r_target = re.search("(.+)\-\-", instance['target_ref']).group(1)

    if r_source not in enums.RELATIONSHIPS:
        return JSONError("'%s' is not a valid relationship source object."
                         % r_source, "relationship_type")

    if r_type not in enums.RELATIONSHIPS[r_source]:
        return JSONError("'%s' is not a valid relationship type for '%s' "
                         "objects." % (r_type, r_source), "relationship_type")

    if r_target not in enums.RELATIONSHIPS[r_source][r_type]:
        return JSONError("'%s' is not a valid relationship target object for "
                         "'%s' objects with the '%s' relationship."
                         % (r_target, r_source, r_type), "relationship_type")


class CustomDraft4Validator(Draft4Validator):
    """Custom validator class for JSON Schema Draft 4.

    """
    def __init__(self, schema, types=(), resolver=None, format_checker=None,
                 options=ValidationOptions()):
        super(CustomDraft4Validator, self).__init__(schema, types, resolver, format_checker)
        # Construct list of validators to be run by this validator
        self.validator_list = [
            modified_created,
            version,
            cybox,
            capec,
            custom_property_names,
            cve,
            empty_lists,
            id_type,
            timestamp_precision
        ]

        # If only checking MUST requirements, the list is complete
        if options.lax:
            return

        # Add SHOULD requirements to the list unless ignored
        ignored = options.ignored_errors.split(",")

        if enums.IGNORE_CUSTOM_OBJECT_PREFIX not in ignored:
            if options.lax_prefix:
                self.validator_list.append(custom_object_prefix_lax)
            else:
                self.validator_list.append(custom_object_prefix_strict)

        if enums.IGNORE_CUSTOM_PROPERTY_PREFIX not in ignored:
            if options.lax_prefix:
                self.validator_list.append(custom_property_prefix_lax)
            else:
                self.validator_list.append(custom_property_prefix_strict)

        if enums.IGNORE_ALL_VOCABS not in ignored:
            if enums.IGNORE_ATTACK_MOTIVATION not in ignored:
                self.validator_list.append(vocab_attack_motivation)
            if enums.IGNORE_ATTACK_RESOURCE_LEVEL not in ignored:
                self.validator_list.append(vocab_attack_resource_level)
            if enums.IGNORE_IDENTITY_CLASS not in ignored:
                self.validator_list.append(vocab_identity_class)
            if enums.IGNORE_INDICATOR_LABEL not in ignored:
                self.validator_list.append(vocab_indicator_label)
            if enums.IGNORE_INDUSTRY_SECTOR not in ignored:
                self.validator_list.append(vocab_industry_sector)
            if enums.IGNORE_MALWARE_LABEL not in ignored:
                self.validator_list.append(vocab_malware_label)
            if enums.IGNORE_PATTERN_LANG not in ignored:
                self.validator_list.append(vocab_pattern_lang)
            if enums.IGNORE_REPORT_LABEL not in ignored:
                self.validator_list.append(vocab_report_label)
            if enums.IGNORE_THREAT_ACTOR_LABEL not in ignored:
                self.validator_list.append(vocab_threat_actor_label)
            if enums.IGNORE_THREAT_ACTOR_ROLE not in ignored:
                self.validator_list.append(vocab_threat_actor_role)
            if enums.IGNORE_THREAT_ACTOR_SOPHISTICATION_LEVEL not in ignored:
                self.validator_list.append(vocab_threat_actor_sophistication_level)
            if enums.IGNORE_TOOL_LABEL not in ignored:
                self.validator_list.append(vocab_tool_label)
            if enums.IGNORE_MARKING_DEFINITION_TYPE not in ignored:
                self.validator_list.append(vocab_marking_definition)

        if enums.IGNORE_KILL_CHAIN_NAMES not in ignored:
            self.validator_list.append(kill_chain_phase_names)

        if enums.IGNORE_RELATIONSHIP_TYPES not in ignored:
            self.validator_list.append(relationships_strict)

    def iter_errors_more(self, instance, options=None, _schema=None):
        """Custom function to perform additional validation not possible
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
