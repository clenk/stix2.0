import glob, os, fnmatch, json
from jsonschema import Draft4Validator, RefResolver
from jsonschema import exceptions as schema_exceptions
from urllib.request import urlopen
import argparse

parser = argparse.ArgumentParser(description='Validate STIX 2.0 against the schemas')
parser.add_argument('docs', type=str, help="Documents to validate. Leave blank to validate everything in tests.", nargs='?')
args = parser.parse_args()

print("\n")

schemas_dir = os.path.abspath(os.path.dirname(__file__) + '/../schemas/')
examples_dir = os.path.abspath(os.path.dirname(__file__) + '/../tests/')

# This is necessary because the URL resolver doesn't think a filename is a file URL. Setting the handler for the "" URL scheme to default to file (as here) solves it
def default_handler (uri):
    return json.loads(urlopen("file://" + uri).read().decode("utf-8"))

def run_test(schema, test_case, schema_path):
    validator = load_validator(schema_path, schema)

    with open(test_case) as instance_file:
        instance = json.load(instance_file)

    # Actual validation
    errors = sorted(validator.iter_errors(instance), key=lambda e: e.path)

    if len(errors) == 0:
        return True
    else:
        return [(error.message) for error in errors]

def run_tests():
    # Essentially equivalent to "glob": load all JSON files in the examples directory and stick them in matches
    matches = []
    for root, dirnames, filenames in os.walk(examples_dir):
        for filename in fnmatch.filter(filenames, '*.json'):
            matches.append(os.path.join(root, filename))

    # Go through each test case, loading the appropriate schema based on directory hierarchy
    all_errors = []
    for test_case in matches:
        schema_path = ('/').join(test_case.split('/tests/')[1].split('/')[0:-1]) + '.json'
        schema = load_schema(schemas_dir + '/' + schema_path)

        results = run_test(schema, test_case, schemas_dir + '/' + schema_path)
        if results == True:
            print("."),
        else:
            print("E"),
            all_errors.append({'file': test_case, 'errors': results})

    print_results(all_errors)
    print("\n\n{0} passed, {1} errors\n".format(len(matches) - len(all_errors), len(all_errors)))

def load_schema(schema_path):
    try:
        with open(schema_path) as schema_file:
            schema = json.load(schema_file)
    except ValueError as e:
        raise StixValidatorException('invalid JSON in schema or included schema: ' + schema_file.name + "\n" + str(e))

    return schema
	

def load_validator(schema_path, schema):
    print("Schema Path:" + schema_path)
    #schema_path = "file:\\C:\\Users\\atweed\\Documents\\GitHub\\stix2.0\\schemas" + schema_path
    #print ("SCHEMA PATH:" + schema_path)
    try:	    
        #resolver = RefResolver(schema_path, schema, {}, True, {"": default_handler})
		
        #resolver = RefResolver.from_schema(schema, base_uri=schema_path, handlers={"": default_handler})
        #resolver = RefResolver.from_schema(schema, base_uri='file://'+schema_path)
		
        resolver = RefResolver('file:///' + schemas_dir.replace("\\", "/") + '/schemas/', schema)
        validator = Draft4Validator(schema, resolver=resolver)
    except schema_exceptions.RefResolutionError:
        raise StixValidatorException('invalid JSON schema')
    return validator

def print_results(all_errors):
    # Print results
    for errors in all_errors:
        print("\n\nFile: {0}".format(errors['file']))
        print("----------------------------")
        print(("\n").join(errors['errors']))

def run_validation(doc):

    all_errors = []
    with open(doc) as instance_file:
        instance = json.load(instance_file)

    # Load the schema corresponding to its type
    schema_filename = instance[0]['type']

    matches = []
    for root, dirnames, filenames in os.walk(schemas_dir):
        for filename in fnmatch.filter(filenames, schema_filename + '.json'):
            matches.append(os.path.join(root, filename))
    if len(matches) > 0:
        print(matches)
        schema_path = matches[0]
        schema = load_schema(schema_path)
        results = run_test(schema, doc, schema_path)
        if results == True:
            print("Passed schema validation!")
        else:
            print_results([{'file': doc, 'errors': results}])
    else:
        print("Unable to find schema for " + schema_filename)

class StixValidatorException(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

if args.docs == None:
    run_tests()
else:
    # Open the instance file
    try:
        run_validation(args.docs)
    except ValueError:
        print("Invalid JSON: " + args.docs)
