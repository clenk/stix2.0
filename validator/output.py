import sys
from colorama import init, Fore, Style
from six import iteritems
from . import codes

init(autoreset=True)
_GREEN = Fore.GREEN
_RED = Fore.RED + Style.BRIGHT
_VERBOSE = False


def set_level(verbose_output=False):
    """Set the output level for the application.
    If ``verbose_output`` is False then the application does not print
    informational messages to stdout; only results or fatal errors are printed
    to stdout.
    """
    global _VERBOSE
    _VERBOSE = verbose_output


def error(msg, status=codes.EXIT_FAILURE):
    """Prints a message to the stderr prepended by '[!]' and calls
    ```sys.exit(status)``.

    Args:
        msg: The error message to print.
        status: The exit status code. Defaults to ``EXIT_FAILURE`` (1).

    """
    sys.stderr.write("[!] %s\n" % str(msg))
    sys.exit(status)


def info(msg):
    """Prints a message to stdout, prepended by '[-]'.

    Note:
        If the application is running in "Quiet Mode"
        (i.e., ``_VERBOSE == False``), this function will return
        immediately and no message will be printed.

    Args:
        msg: The message to print.

    """
    if not _VERBOSE:
        return

    print("[-] %s" % msg)


def print_level(fmt, level, *args):
    """Prints a formatted message to stdout prepended by spaces. Useful for
    printing hierarchical information, like bullet lists.

    Args:
        fmt (str): A Python formatted string.
        level (int): Used to determing how many spaces to print. The formula
            is ``'    ' * level ``.
        *args: Variable length list of arguments. Values are plugged into the
            format string.

    Examples:
        >>> print_level("%s %d", 0, "TEST", 0)
        TEST 0
        >>> print_level("%s %d", 1, "TEST", 1)
            TEST 1
        >>> print_level("%s %d", 2, "TEST", 2)
                TEST 2

    """
    msg = fmt % args
    spaces = '    ' * level
    print("%s%s" % (spaces, msg))


def print_fatal_results(results, level=0):
    """Prints fatal errors that occurred during validation runs.
    """
    print_level(_RED + "[!] Fatal Error: %s", level, results.error)


def print_schema_results(results, level=0):
    """Prints JSON Schema validation results to stdout.

    Args:
        results: An instance of ValidationResults.
        level: The level at which to print the results.

    """
    marker = _GREEN + "[+]" if results.is_valid else _RED + "[!]"
    print_level("%s JSON Schema: %s", level, marker, results.is_valid)

    if results.is_valid:
        return

    for error in results.errors:
        print_level(_RED + "[!] %s", level + 1, error)


def print_results(results, options):
    """Prints `results` to stdout. If ``options.json_output`` is set, the
    results are printed in JSON format.

    Args:
        results: A dictionary of ValidationResults instances. The key is the
            file path to the validated document.
        options: An instance of ``ValidationOptions`` which contains output
            options.

    """
    if not hasattr(results, 'items'):
        results_arr = {'result': results}
        results = results_arr

    level = 0
    for fn, result in sorted(iteritems(results)):
        print("=" * 80)
        print_level("[-] Results: %s", level, fn)

        if result.schema_results is not None:
            print_schema_results(result.schema_results, level)
        if result.fatal is not None:
            print_fatal_results(result.fatal, level)
