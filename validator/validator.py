import glob, os, fnmatch, json
from jsonschema import Draft4Validator

print ""

root = os.path.dirname(__file__) + '/..'
examples_dir = root + '/examples/'
schemas_dir = root + '/schemas/'

matches = []
for root, dirnames, filenames in os.walk(examples_dir):
    for filename in fnmatch.filter(filenames, '*.json'):
        matches.append(os.path.join(root, filename))

all_errors = []

for test_case in matches:
    schema_path = ('/').join(test_case.split('/examples/')[1].split('/')[0:-1]) + '.json'
    with open(schemas_dir + schema_path) as schema_file:
        schema = json.load(schema_file)
        validator = Draft4Validator(schema)

    with open(test_case) as instance_file:
        instance = json.load(instance_file)


    errors = sorted(validator.iter_errors(instance), key=lambda e: e.path)

    if len(errors) == 0:
        print '.',
    else:
        all_errors.append({'file': test_case, 'errors': errors})
        print 'E',

for errors in all_errors:
    print "\n\nFile: {0}".format(errors['file'])
    print "----------------------------"
    error_messages = [(error.message) for error in errors['errors']]
    print ("\n").join(error_messages)

print "\n\n{0} passed, {1} errors\n".format(len(matches) - len(all_errors), len(all_errors))
