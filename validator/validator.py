import glob, os, fnmatch, json
from jsonschema import Draft4Validator, RefResolver
from jsonschema import exceptions as schema_exceptions
from urllib import urlopen

print ""

schemas_dir = os.path.abspath(os.path.dirname(__file__) + '/../schemas/')
examples_dir = os.path.abspath(os.path.dirname(__file__) + '/../examples/')

# This is necessary because the URL resolver doesn't think a filename is a file URL. Setting the handler for the "" URL scheme to default to file (as here) solves it
def default_handler (uri):
    return json.loads(urlopen("file://" + uri).read().decode("utf-8"))

def run_test(schema, validator, test_case):
    with open(test_case) as instance_file:
        instance = json.load(instance_file)

    # Actual validation
    errors = sorted(validator.iter_errors(instance), key=lambda e: e.path)

    if len(errors) == 0:
        print '.',
    else:
        error_messages = [(error.message) for error in errors]
        all_errors.append({'file': test_case, 'errors': error_messages})
        print 'E',

# Essentially equivalent to "glob": load all JSON files in the examples directory and stick them in matches
matches = []
for root, dirnames, filenames in os.walk(examples_dir):
    for filename in fnmatch.filter(filenames, '*.json'):
        matches.append(os.path.join(root, filename))

# Go through each test case, loading the appropriate schema based on directory hierarchy
all_errors = []
for test_case in matches:
    schema_path = ('/').join(test_case.split('/examples/')[1].split('/')[0:-1]) + '.json'
    with open(schemas_dir + '/' + schema_path) as schema_file:
        try:
            schema = json.load(schema_file)
            resolver = RefResolver(schemas_dir + '/' + schema_path, schema, {}, True, {"": default_handler})
            validator = Draft4Validator(schema, resolver=resolver)
            run_test(schema, validator, test_case)
        except ValueError:
            all_errors.append({'file': test_case, 'errors': ['invalid JSON']})
        except schema_exceptions.RefResolutionError:
            all_errors.append({'file': test_case, 'errors': ['invalid JSON Schema']})

# Print results
for errors in all_errors:
    print "\n\nFile: {0}".format(errors['file'])
    print "----------------------------"
    print ("\n").join(errors['errors'])

print "\n\n{0} passed, {1} errors\n".format(len(matches) - len(all_errors), len(all_errors))
