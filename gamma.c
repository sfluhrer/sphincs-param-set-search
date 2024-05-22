/*
 * This is the program that lists the potential Sphincs+ parameter sets,
 * given the target requirements (security level, number of signatures at
 * that security level, overuse characteristics)
 *
 * This part of the program computes the actual security level, that is,
 * it evaluates equation (1) of the paper
 */
#include <math.h>
#include <ctype.h>
#include "gamma.h"

#if 0
/*
 * This is a straightfoward implementation of algorithm (1)
 * It works fine for reasonable inputs; however it runs into floating point
 * errors (loss of precision, overflow) when asked to evaluate things in
 * drastic overuse conditions
 *
 * It is here because it should be helpful to compare this implementation with
 * the rather less straightforward implementation we use below
 */
double compute_sec_level( double m, int H, int T, int K ) {
    double lambda;
    if (m > H) {
        lambda = pow(2, m-H);
    } else {
        lambda = pow(0.5, H-m);
    }
    double prob_not_get_single_hit = 1.0 - pow(0.5, T); /* This is the */
        /* probability that a probe does not hit a specific valid signature */
        /* within a specific FORS tree */
    double prob_not_get_g_hit = 1.0;

    double a = 1.0;
    double sum = 0.0;

    for (unsigned g = 1; g < 10000; g++) {
        a *= lambda;
        a /= g;
        prob_not_get_g_hit *= prob_not_get_single_hit;

        double b = pow( 1 - prob_not_get_g_hit, K );

        sum += a*b;
        if (g >= 10 && sum > 1e5 * a ) break;
    }

    return -log2( exp( -lambda ) * sum );
}

#else

/*
 * This is an alternate implementation designed to work in drastic overuse
 * conditions (and also in normal ones as well).  It keeps most things in
 * logarithmic form, that is, log_2 of the 'actual' value - this avoids
 * overflows (and at the one point where we might lose significance, we
 * have explicit code handling that)
 */

/* Add two values in log2 representation */
/* That is, given log2(a), log2(b), this returns log2(a+b) */
static double do_add(double x, double y) {
    double big, little;
    if (x > y) {
        big = x; little = y;
    } else {
        big = y; little = x;
    }
    if (big > little + 64) return big;  /* If a > b * 2^64, then log2(a+b) */
                                        /* is essentially log2(a) */

    double temp = 1 + pow( 0.5, big - little ); /* temp = 1 + b/a (assuming */
                                        /* a >= b, otherwise swap them) */

    return big + log2( temp );  /* big+log2(temp) = log(a) + log2(1 + b/a) */
                                /*                = log( a*(1+b/a) ) */
                                /* (assuming a >= b, otherwise swap them) */
}

/*
 * This computes the security level after pow(2,m) signatures, assuming
 * the hypertree has H levels, and that we have K FORS trees of height T
 */
double compute_sec_level( double m, int H, int T, int K ) {
    /*
     * Compute lambda which is the expected number of signatures per hypertree
     * leaf at the specified number of signatures
     */
    double lambda;
    if (m > H) {
        lambda = pow(2, m-H);
    } else {
        lambda = pow(0.5, H-m);
    }
    double log_lambda = log2(lambda);   /* ... or m-H */

    double prob_not_get_single_hit = 1.0 - pow(0.5, T); /* This is */
        /* the probability that a probe does not hit a specific valid */
        /* signature within a specific FORS tree */
    double prob_not_get_g_hit = 1.0;  /* This is the probability that */
        /* no probes hit a specific valid signature in a specific FORS tree */
        /* after g signatures have been generated from this FORS */
        /* This is updated as g is iterated */

    double log_a = 0.0;    /* a == lambda^g */
    double log_sum = 0.0;  /* the running sum */

    for (unsigned g = 1;; g++) {
            /* Update the variables that depend on g */
        log_a += log_lambda;
        log_a -= log2(g);
        prob_not_get_g_hit *= prob_not_get_single_hit;

        /*
         * a is the probability that there will be precisely g valid signatures
         * for this FORS (except for the constant e^{-\lambda} term; we'll
         * account for that at the end)
         */
        
        /*
         * Compute b which is probability that a single forgery query will lie
         * entirely in revealed FORS leaves (and thus will allow a signature
         * of that forgery), assuming we have precisely g valid signatures for
         * this FORS
         */
        double log_b;
        if (prob_not_get_g_hit < 1E-5) {
            /*
             * If prob_not_get_g_hit is sufficiently small, the subtraction
             * will lose significant bits (or just result in 1)
             * In this regime, the quadratic approximation, that is, the first
             * two terms in the Taylor expansion, gives us a more accurate
	     * value
             */
            log_b = -K * (prob_not_get_g_hit / log(2.0) + 
	               prob_not_get_g_hit*prob_not_get_g_hit / (2*log(2.0)));
        } else {
            /*
             * prob_not_get_g_hit is still large enough; compute it directly
             */
            log_b = K * log2( 1 - prob_not_get_g_hit );
        }

        /*
         * Hence, the probability that this iteration adds to the sum is
         * a*b, and since we're dealing with logs, log(ab) = log(a) + log(b)
         */

        if (g == 1) {
            /* For the first iteration, the running sum is the first output */
            log_sum = log_a+log_b;
        } else {
            /* For latter iterations, add log(ab) to the running sum */
            log_sum = do_add(log_sum, log_a+log_b);
        }

        /*
         * If the additional terms we're seeing is less than 2^{-20} of the
         * sum, any further terms won't change the answer much - we might as
         * well stop.  We test against log_a, as that is strictly decreasing
         * and bounds the probability (as log_b < 0)
         */
        if (g >= 10 && log_sum > 20 + log_a ) break;
    }

    /*
     * Return the -log2 of the total probability, that is, the expected
     * security level.  And, since we didn't include the e^{-\lambda} constant
     * term in 'a', we add it in now
     */
    return lambda * log2( exp( 1 )) - log_sum;
}
#endif

/*
 * This does a quick test of whether, after pow(2,m) signatures, the
 * specified Sphincs+ structure will meet the specified security level
 * It does early outs (either way) when it is clear what the answer is, hence
 * it is cheaper than computing the exact security level
 */
int check_sec_level( double m, int H, int T, int K, double sec_level ) {
    /*
     * Compute lambda which is the expected number of signatures per hypertree
     * leaf at the specified number of signatures
     */
    double lambda;
    if (m > H) {
        lambda = pow(2, m-H);
    } else {
        lambda = pow(0.5, H-m);
    }
    double log_lambda = log2(lambda);   /* ... or m-H */
    double log_target = log2(exp(lambda)) - sec_level;  /* If log_sum */
               /* exeeds this, we know we didn't hit the security level */

    double prob_not_get_single_hit = 1.0 - pow(0.5, T); /* This is */
        /* the probability that a probe does not hit a specific valid */
        /* signature within a specific FORS tree */
    double prob_not_get_g_hit = 1.0;  /* This is the probability that */
        /* no probes hit a specific valid signature in a specific FORS tree */
        /* after g signatures have been generated from this FORS */
        /* This is updated as g is iterated */

    double log_a = 0.0;    /* a == lambda^g */
    double log_sum = 0.0;  /* the running sum */

    for (unsigned g = 1;; g++) {
            /* Update the variables that depend on g */
        log_a += log_lambda;
        log_a -= log2(g);
        prob_not_get_g_hit *= prob_not_get_single_hit;

        /*
         * a is the probability that there will be precisely g valid signatures
         * for this FORS (except for the constant e^{-\lambda} term; we'll
         * account for that at the end)
         */
        
        /*
         * Compute b which is probability that a single forgery query will lie
         * entirely in revealed FORS leaves (and thus will allow a signature
         * of that forgery), assuming we have precisely g valid signatures for
         * this FORS
         */
        double log_b;
        if (prob_not_get_g_hit < 1E-5) {
            /*
             * If prob_not_get_g_hit is sufficiently small, the subtraction
             * will lose significant bits (or just result in 1)
             * In this regime, the quadratic approximation, that is, the first
             * two terms in the Taylor expansion, gives us a more accurate
	     * value
             */
            log_b = -K * (prob_not_get_g_hit / log(2.0) + 
	               prob_not_get_g_hit*prob_not_get_g_hit / (2*log(2.0)));
        } else {
            /*
             * prob_not_get_g_hit is still large enough; compute it directly
             */
            log_b = K * log2( 1 - prob_not_get_g_hit );
        }

        /*
         * Hence, the probability that this iteration adds to the sum is
         * a*b, and since we're dealing with logs, log(ab) = log(a) + log(b)
         */

        if (g == 1) {
            /* For the first iteration, the running sum is the first output */
            log_sum = log_a+log_b;
        } else {
            /* For latter iterations, add log(ab) to the running sum */
            log_sum = do_add(log_sum, log_a+log_b);
        }

        /* Check for negative results (we don't meet the target) */
        if (log_sum > log_target) return 0;  /* Sum exceeded target; we */
                                      /* didn't meet the security level */

        /* Check for positive results (we know we meet the target) */
        if (g > 2*lambda) {
            double p = lambda / (g+1);
            double log_max_sum = log2(p) - log2(1-p); /* The maximum value */
                                     /* the rest of the terms can add to sum */
            if (do_add(log_sum, log_max_sum) <= log_target) return 1; /* The */
                                     /* sum cannot reach target (that is, we */
                                     /* will exceed the security level) */
        }
        if (g >= 10 && log_sum > 20 + log_a ) return 1; /* The rest of the */
                                     /* terms are small; we will exceed the */
                                     /* security level */
    }
}

/*
 * Given a security level and Sphincs+ parameters, this estimates how many
 * signatures we can generate while still remaining within that security
 * level.
 * What this returns is the integer round(100*log2( num_sigs ))
 *
 * Yes, I know there are faster ways to compute this (binary search)
 * However, we don't need speed here, and so doing it in the straightforward
 * (and stupid) way is good enough
 */
int compute_sigs_at_sec_level( double sec_level, int H, int T, int K ) {
    int lower;

    /* Scan for the number of signatures at a gross level (by integers) */
    for (lower = 0;; lower++) {
        double r = compute_sec_level(lower + 1, H, T, K);
        if (r < sec_level) break;
    }
    /* Ok, the nmber of signatures is between lower and lower+1, now scan */
    /* by hundreds */
    int fract;
    for (fract = 0; fract < 100; fract++) {
        double m = lower + fract * 0.01 + 0.005;
        double r = compute_sec_level(m, H, T, K);
        if (r < sec_level) break;
    }

    return 100*lower + fract;
}
