#!/usr/bin/env python

"""Validate STIX 2.0 documents against the schemas.
"""


import logging
from validator import *
from validator import codes


EXAMPLES_DIR = os.path.abspath(os.path.dirname(__file__) + '/tests/')


def _get_arg_parser():
    """Initializes and returns an argparse.ArgumentParser instance for this
    application.

    Returns:
        Instance of ``argparse.ArgumentParser``

    """
    parser = argparse.ArgumentParser(
        description=__doc__
    )

    parser.add_argument(
        "files",
        metavar="FILES",
        nargs="*",
        default=[EXAMPLES_DIR],
        help="A whitespace separated list of STIX files or directories of "
             "STIX files to validate. If none is given, the tests/ directory "
             "will be recursively validated."
    )

    parser.add_argument(
        "-r",
        "--recursive",
        dest="recursive",
        action="store_true",
        default=False,
        help="Recursively descend into input directories."
    )

    parser.add_argument(
        "--schemas",
        dest="schema_dir",
        default='schemas/',
        help="Schema directory. If not provided, the STIX schemas bundled "
             "with this script will be used."
    )

    # TODO
    # parser.add_argument(
    #     "--best-practices",
    #     dest="best_practices",
    #     action='store_true',
    #     default=False,
    #     help="Check that the document follows authoring best practices."
    # )

    parser.add_argument(
        "-q",
        "--quiet",
        dest="quiet",
        action="store_true",
        default=False,
        help="Only print results and errors if they occur."
    )

    return parser


def main():
    # Parse command line arguments
    parser = _get_arg_parser()
    args = parser.parse_args()
    args.schema_dir = os.path.abspath(os.path.dirname(__file__) + args.schema_dir)
    
    # If validating the tests directory, look in its subdirectories
    if args.files == [EXAMPLES_DIR]:
        args.recursive = True

    try:
        # Set the output level (e.g., quiet vs. verbose)
        output.set_level(args.quiet)

        # Validate input documents
        results = run_validation(args)

        # Print validation results
        output.print_results(results, args)

        # Determine exit status code and exit.
        code = codes.get_code(results)
        sys.exit(code)

    except (ValidationError, IOError) as ex:
        output.error(
            "Validation error occurred: '%s'" % str(ex),
            codes.EXIT_VALIDATION_ERROR
        )
    except Exception:
        logging.exception("Fatal error occurred")
        sys.exit(codes.EXIT_FAILURE)

if __name__ == '__main__':
    main()