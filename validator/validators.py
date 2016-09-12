"""Custom jsonschema.IValidator class and validator functions.
"""

# builtin
import re
from collections import deque

# external
from jsonschema import Draft4Validator
from jsonschema import exceptions as schema_exceptions

# internal
from . import vocabs


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
# TODO

def check_vocab(instance, vocab):
    """Ensure that the open vocabulary specified by `vocab` is used properly.

    It checks properties of objects specified in the appropriate `_USES`
    dictionary to determine which properties SHOULD use the given vocabulary,
    then checks that the values in those properties are from the vocabulary.
    """
    vocab_uses = getattr(vocabs, vocab + "_USES")
    for k in vocab_uses.keys():
        if instance['type'] == k:
            for prop in vocab_uses[k]:
                if prop not in instance:
                    continue

                vocab_ov = getattr(vocabs, vocab + "_OV")
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
            custom_property_names,
            cve,
            empty_lists,
            timestamp_precision
        ]

        if not options or not options.ignored_errors:
            return

        ignored = options.ignored_errors.split(",")

        # Ignore vocabulary value checks
        if '110' not in ignored:
            if '111' not in ignored:
                self.validator_list.append(vocab_attack_motivation)
            if '112' not in ignored:
                self.validator_list.append(vocab_attack_resource_level)
            if '113' not in ignored:
                self.validator_list.append(vocab_identity_class)
            if '114' not in ignored:
                self.validator_list.append(vocab_indicator_label)
            if '115' not in ignored:
                self.validator_list.append(vocab_industry_sector)
            if '116' not in ignored:
                self.validator_list.append(vocab_malware_label)
            if '117' not in ignored:
                self.validator_list.append(vocab_pattern_lang)
            if '118' not in ignored:
                self.validator_list.append(vocab_report_label)
            if '119' not in ignored:
                self.validator_list.append(vocab_threat_actor_label)
            if '120' not in ignored:
                self.validator_list.append(vocab_threat_actor_sophistication_level)
            if '121' not in ignored:
                self.validator_list.append(vocab_attack_motivation)
            if '122' not in ignored:
                self.validator_list.append(vocab_tool_label)


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
