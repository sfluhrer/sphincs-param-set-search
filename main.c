/*
 * This is the program that lists the potential Sphincs+ parameter sets,
 * given the target requirements (security level, number of signatures at
 * that security level, overuse characteristics)
 *
 * This portion of the program does the command line handling
 */
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "search.h"

/*
 * Routine used to parse parameters in the form XXX=<number>
 * It returns either 0 (parameter wasn't of that form) or the value of <number>
 */
static unsigned long get_int_param( const char *arg, const char *param_name ) {
    /*
     * Check if we have the expected prefix
     */
    while (*param_name) {
        if (*arg++ != *param_name++) {
            return 0;   /* Nope; not a match */
        }
    }
    if (!isdigit( *arg )) return 0; /* Not followed by a number */

    /* We do; convert the number, and return it */
    unsigned long val = 0;
    do {
        val = 10*val + *arg++ - '0';
    } while (isdigit( *arg ));
    if (*arg != '\0') return 0;  /* Oops; not expecting anything after */
                                 /* the last digit */
    return val;
}

static void usage(const char *program) {
    fprintf( stderr, "Usage: %s params\n", program );
    fprintf( stderr, "Supported parameters:\n"
                     "    s=#    Security level; must be specified\n"
                     "           128 = NIST level 1, 192 = level 3, 256 = level 5\n"
                     "    n=#    Number of signatures; must be specified\n"
                     "           This is the log2; 16 means 65536 signatures\n"
                     "    sign=# Maximum number of hashes during signing\n"
                     "           Must be specified\n"
                     "    tests=# The test security level for overuse\n"
                     "    maxs=# Stop listing parameter sets once they hit\n"
                     "           log2 number of signatures for overuse security\n"
                     "    label=string Prefix each entry with the given label\n"
                     "    d=#    Only consider parameter sets with the specified tree depth\n"
                     "    h=#    Only consider parameter sets with the specified merkle height\n"
                     "    a=#    Only consider parameter sets with the specified number of FORS\n"
            );                 
}

/*
 * The main routine: parse the arguments, and pass them to the routines that
 * will do the real work
 */
int main(int argc, char **argv) {
    int sec_level = 0;
    int num_sig = 0;
    int sign_op = 0;
    int test_s = 0;
    int max_s = 0;
    int d = 0;
    int h = 0;
    int a = 0;
    int i;
    char *label = 0;

    /* Parse the parameters */
    for (i=1; i<argc; i++) {
        unsigned long t;
        /* Check for security level */
        if ((t = get_int_param( argv[i], "s=" )) != 0) {
            sec_level = t;
        }
        /* Check for number of signatures */
        else if ((t = get_int_param( argv[i], "n=" )) != 0) {
            num_sig = t;
        }
        /* Check for the number of hash operations */
        else if ((t = get_int_param( argv[i], "sign=" )) != 0) {
            sign_op = t;
        }
        /* Check for the overuse test level */
        else if ((t = get_int_param( argv[i], "tests=" )) != 0) {
            test_s = t;
        }
        /* Check for the max listed overuse level */
        else if ((t = get_int_param( argv[i], "maxs=" )) != 0) {
            max_s = t;
        }
        /* Check for the label */
        else if (0 == strncmp( argv[i], "label=", 6 )) {
            label = &argv[i][6];
        }
        /* Check for the d */
        else if ((t = get_int_param( argv[i], "d=" )) != 0) {
            d = t;
        }
        /* Check for the h */
        else if ((t = get_int_param( argv[i], "h=" )) != 0) {
            h = t;
        }
        /* Check for the a */
        else if ((t = get_int_param( argv[i], "a=" )) != 0) {
            a = t;
        }
        else {
            usage(argv[0]);
            return 0;
        }
    }

    /* Check if all the mandatory parameters were provided */
    if (sec_level == 0) {
        fprintf( stderr, "security level not specified\n" );
        usage(argv[0]);
        return 0;
    }
    if (num_sig == 0) {
        fprintf( stderr, "number of signatures not specified\n" );
        usage(argv[0]);
        return 0;
    }
    if (sign_op == 0) {
        fprintf( stderr, "max number of hashes per sign operation not specified\n" );
        usage(argv[0]);
        return 0;
    }

    /* If the secondary security level (for overuse) was not provided, pick */
    /* a reasonable default */
    if (test_s == 0) {
        test_s = sec_level - 32;
        if (test_s < 0) test_s = sec_level / 2;
    }

    /* Pass the parameters to the searcher */
    do_search( sec_level, num_sig, test_s, sign_op, max_s, label, d, h, a );

    return 0;
}
