#!/usr/bin/env python

"""Validate STIX 2.0 documents against the schemas.
"""


import logging
from validator import *
from validator import codes


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
        help="A whitespace separated list of STIX files or directories of "
             "STIX files to validate."
    )

    parser.add_argument(
        "--recursive",
        dest="recursive",
        action="store_true",
        default=False,
        help="Recursively descend into input directories."
    )

    # TODO
    # parser.add_argument(
    #     "--schema-dir",
    #     dest="schema_dir",
    #     default=os.path.abspath(os.path.dirname(__file__) + '/schemas/'),
    #     help="Schema directory. If not provided, the STIX schemas bundled "
    #          "with this script will be used."
    # )

    # TODO
    # parser.add_argument(
    #     "--best-practices",
    #     dest="best_practices",
    #     action='store_true',
    #     default=False,
    #     help="Check that the document follows authoring best practices."
    # )

    parser.add_argument(
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