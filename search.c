/*
 * This is the program that lists the potential Sphincs+ parameter sets,
 * given the target requirements (security level, number of signatures at
 * that security level, overuse characteristics)
 *
 * This part of the program actually goes through the various possible
 * parameter sets, evaluates them, sorts them, and lists the best ones
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include "search.h"
#include "gamma.h"

#define MAX_K   100 /* SANITY LIMIT */
                    /* Don't bother checking any parameter set with more */
                    /* than 100 FORS trees */

/*
 * Return a/b, rounded up
 */
static unsigned divru( unsigned a, unsigned b ) {
    return (a+b-1)/b;
}

/*
 * An instance of this structure stands for a parameter set we found (not
 * necessarily a 'good one').  It includes both the parameter set settings,
 * and the evaluated costs
 */
struct parameter_set {
    struct parameter_set *link;  /* We place this structure on a linked list */
    unsigned char h;             /* Hypertree height */
    unsigned char d;             /* Number of Merkle trees */
    unsigned char a;             /* Height of each FORS tree */
    unsigned char k;             /* Number of FORS trees */
    unsigned short w;            /* Winternitz parameter used */
    unsigned sig_size;           /* Size of the signature */
    unsigned sig_time;           /* Number of hashes computed during signing */
    unsigned ver_time;           /* Number of hashes computed during verif */
};

/*
 * This compares two parameter sets and returns 1 or -1 dependong on which
 * one we consider 'better'
 */
static int my_compare( struct parameter_set *a, struct parameter_set *b ) {
    /* Smallest signature size wins */
    if (a->sig_size < b->sig_size) return  1;
    if (a->sig_size > b->sig_size) return -1;

    /* If equal, the smallest sign_time wins */
    if (a->sig_time < b->sig_time) return  1;
    if (a->sig_time > b->sig_time) return -1;

    /* If equal, the smallest verify_time wins */
    if (a->ver_time < b->ver_time) return  1;
    if (a->ver_time > b->ver_time) return -1;

    /* These two are identical as far as we can tell */
    return 0;
}

/*
 * This takes two lists of parameter sets (both in 'best first' order), and
 * merges them into a single list (in 'best first' order
 */
static struct parameter_set *my_merge( struct parameter_set *a, struct parameter_set *b ) {
    struct parameter_set *list = 0;
    struct parameter_set **tail = &list;

    while (a && b) {
        struct parameter_set *p;
        if (my_compare( a, b ) >= 0) {
            p = a;
            a = a->link;
        } else {
            p = b;
            b = b->link;
        }
        *tail = p;
        tail = &p->link;
    }
    if (a) {
        *tail = a;
    } else {
        *tail = b;
    }
    return list;
}

static int ilog2( unsigned n ) {
    int i;
    for (i=0; n>1; i++, n >>= 1) {
	;
    }
    return i;
}

/*
 * This sorts the list of parameter sets into 'best first' order
 * It uses a merge sort
 */
static struct parameter_set *my_sort( struct parameter_set *list ) {
#define NUM_BIN 20    /* This routine works even if we get more than */
                      /* 2^20 parameter sets, it just goes slower */
    struct parameter_set *bins[ NUM_BIN ] = { 0 }; /* bin[i] is either */
                      /* NULL or a list of precisely 2^i parameter sets in */
                      /* best-first order (except for i==19; we use that */
                      /* as an overflow if we get more than 2^20) */

    while (list) {
        /* Extract the next time in the input list; make that a list with */
        /* a single item */
        struct parameter_set *p = list;
        list = p->link;
        p->link = 0;

        /* Ripple-add that to the lists in bin */
        int i;
        for (i=0; i<NUM_BIN; i++) {
            /* p is a sorted list of 2^i items */

            if (!bins[i]) {
                /* That bin is empty; insert it onto the list */
                bins[i] = p;
                break;
            }

            /* That bin also has a list; merge them (and empty the bin) */
            p = my_merge( bins[i], p );
            bins[i] = 0;
            /* p is a sorted list of 2^{i+1} items */
        }

        /* If we ran out of bins, store the list in the overflow bin */
        if (i == NUM_BIN) {
            bins[NUM_BIN-1] = p;
        }
    }

    /*
     * We sorted the entire input list into bins; combine the bins
     */
    struct parameter_set *p = 0;
    for (int i=0; i<NUM_BIN; i++) {
        p = my_merge( bins[i], p );
    }

    return p;
}

/*
 * Convert the given number into ASCII with commas inserted to make reading
 * large numbers easier
 * For example: commify(65536) yields "65,536"
 * This uses a static buffer, the string should be used before this is
 * called again; don't use it multiple times in the same printf
 */
static char *commify( unsigned n ) {
    static char buffer[100];
    int z = 100;
    buffer[--z] = 0;
    while (n >= 1000) {
        buffer[--z] = (n%10) + '0'; n /= 10;
        buffer[--z] = (n%10) + '0'; n /= 10;
        buffer[--z] = (n%10) + '0'; n /= 10;
        buffer[--z] = ',';
    }
    while (n) {
        buffer[--z] = (n%10) + '0'; n /= 10;
    }
    return &buffer[z];
}

/*
 * And the reason for this file - search for decent Sphincs+ parameter sets
 * that match the various criteria given, and print out the best ones
 * Parameters:
 * sec_level        - The required security level.  Used both the compute the
 *                hash size, and also the security level at the given number
 *                of signatures
 * num_sig        - We require that the parameter sets maintain sec_level
 *                security after this many signatures have been generated
 * test_sec_level - The secondary security level; we compute the number of
 *                signatures we can generate while still maintaining this
 *                lower security level.  More signatures means that the
 *                parameter set has better overuse characteristics
 * sign_op        - The maximum number of signatures that we can consider doing
 *                a signature generation operation
 * max_s        - The highest level of secondary signature usage we can
 *                consider.  That is, once we get a parameter set that
 *                maintains the secondary security level with more than
 *                this many signatures, we can stop listing
 * label        - If provided (not NULL), we also place the overuse
 *                characteristics of the listed parameter sets into CSV files
 *                (in a format that GnuPlot likes)
 * d_restrict, h_restrict, a_restrict - If provided, we consider only parameter
 *                sets with the given d, h_merkle, a parameters (where h_merkle
 *                is the height of an individual Merkle tree, not the total
 *                hypertree height).  These are useful if we're studying the
 *                overuse characteristics of a specific parameter set (which
 *                might not happen to be one of the 'best' parameter sets
 *                listed by default).
 */
void do_search( int sec_level, unsigned num_sig,
                unsigned test_sec_level, unsigned sign_op, int max_s,
                char *label, int d_restrict, int h_restrict, int a_restrict ) {
    unsigned w, log_w;

    /*
     * We actually maintain three lists of 'acceptable' parameter sets, based
     * by w value (w=16, w=4,256 and w=2,8,32,64,128.
     * We do this because w=16 parameter sets are the easiest to install into
     * an existing SLH-DSA system, w=4,256 is the second easiest (because we
     * have to break the W=16 assumption, but the byte->digit parsing is still
     * easy), and the other W values are the hardest (because digits will
     * span bytes)
     * We keep them in separate lists so that:
     * - We list all W=16 parameter sets (even if we found a better W!=16
     *   parameter set)
     * - We list all W=4,256 parameter sets (except when we found a better
     *   W=16 parameter set)
     * - We list W=2,8,32,64,128 parameter sets (as long as we haven't found
     *   a better one)
     * And, yes, the w256_q list also includes W=4...
     */
    struct parameter_set *w16_q = 0, *w256_q = 0, *wother_q = 0;

    /* Compute the size of the hash (in bytes) based on the security level */
    unsigned hash_size = (sec_level + 7)/8;

    /*
     * Now, we'll go through the various possibilities of parameter sets
     * First, we step through the possible w values
     */
    for (w = 4, log_w = 2; w <= 256; w <<= 1, log_w++) {
        /* Pick the list that we'll be inserting the parameter sets into */
        struct parameter_set **current_list;
        if (w == 16) {
            current_list = &w16_q;
        } else if (w == 256 || w == 4) {
            current_list = &w256_q;
        } else {
            current_list = &wother_q;
        }

        unsigned wd, cost_ots;

        /* Compute the number of Winternitz digits used */
        {
            /* Number of digits used to express the hash */
            unsigned hash_d = (sec_level + log_w - 1) / log_w;

            /* Number of digits used to express the checksum */
            unsigned max_sum = (w-1) * hash_d;
            unsigned checksum_d, prod;
            for (checksum_d = 1, prod = w; prod < max_sum; checksum_d++, prod *= w ) {
                ;
            }

            /* Number of Winternitz digits */
            wd = hash_d + checksum_d;

            /*
             * Cost of generating a one time public key
             * This includes:
             * The cost of converting the private seed into the bottom-most
             *     chain values (wd)
             * The cost of stepping through each chain (wd * (w-1))
             * The top-most hash combining the values (1)
             *
             * Costing the top-most hash as one hash computation isn't
             * precisely accurate; however it isn't that misleading (and the
             * actual value depends on the hash function used)
             */
            cost_ots = 1 + wd * w;
        }

        /*
         * Now, step through the various heights of each Merkle tree
         */
        int h_merkle;
        for (h_merkle = 2; h_merkle <= sec_level+20 && h_merkle < 32; h_merkle++) {
            if (h_restrict && h_merkle != h_restrict) continue;
            int h, d; /* h == hypertree height, d == number of Merkle levels */
            unsigned node_tree = 1<<h_merkle;  /* The number of leaves of a single Merkle tree */

            /*
             * Now, step through the total number of Merkle tree layers
             * We only consider hypertree heights that are reasonable:
             * - If it exceeds the security level by more than 30, there are
             *   likely to be cheaper options
             * - If the height is less than 5 fewer than the number of
             *   signatures we'll require, it's likely not going to meet our
             *   security requirements
             * - If it has 30 or more Merkle levels, the signature size is
             *   likely to be unreasonable
             */
            for (h = h_merkle, d = 1 ; h <= sec_level+30; h += h_merkle, d++) {
                if (d >= 30) break;
                if (d_restrict && d != d_restrict) continue;
                if (h < num_sig - 5) continue;

                /*
                 * The number of hashes we'll need to build the Merkle trees
                 * during a signing operation (which are:
                 * - The cost of building all the one-time public keys:
                 *     d * cost_ots * node_tree
                 * - The cost of combining all the internal nodes of the Merkle
                 *   trees:
                 *     d * (node_tree-1)
                 */
                float cost_hypertree = d*((float)(cost_ots+1) * node_tree - 1);

                /*
                 * If that cost exceeds our cost limit, we can stop at this h
                 */
                if (cost_hypertree >= sign_op) break; /* Step to the next */
                                                      /* Merkle tree height */

                /*
                 * Now, step through the various heights of FORS trees
                 * We stop at FORS tree height 30 - that is likely to be
                 * far too expensive
                 */
                unsigned a;
                for (a=1; a<30; a++) {
                    if (a_restrict && a != a_restrict) continue;

                    /*
                     * Cost of building a FORS tree, including:
                     * The cost of converting the private seed into the
                     *     private FORS value (1 << a)
                     * The cost of converting the private FORS value into the
                     *     public one (1 << a)
                     * The cost of building the Merkle tree (1 << a) - 1
                     */
                    unsigned cost_fors_tree = 3 * (1 << a) - 1;

                    unsigned k;
                    /*
                     * And step through the various possible number of FORS
                     * trees
                     */
                    for (k=1; k<MAX_K; k++) {
                        /*
                         * If the combined cost of building the Hypertree and
                         * the FORS trees are more than our budget, we can
                         * stop here
                         */
                        if (cost_hypertree + k*cost_fors_tree > sign_op) break;

                        /* Check if it meets the security requirement */
                        if (!check_sec_level( num_sig, h, a, k, sec_level )) {
                            continue;
                        }

                        /*
                         * This one checks out - add it to the list of
                         * acceptable parameter sets that we've found
                         */
                        struct parameter_set *p = malloc( sizeof *p );
                        if (!p) {
                            fprintf( stderr, "Get a real computer you cheapskate\n" );
                            return;
                        }
                        p->h = h;
                        p->d = d;
                        p->a = a;
                        p->k = k;
                        p->w = w;
                        p->sig_size = hash_size * (1 + k * (a+1) + d * (wd + h_merkle ) );
                        /*
                         * Sign time is:
                         * - Time for PRF_msg evaluation (1)
                         * - Time for H_msg evaluation (1)
                         * - Time for the FORS (k trees at the cost we
                         *   computed each, plus 1 for the hash to combine)
                         * - Time to compute the hypertree (already computed)
                         */
                        p->sig_time = 3 + cost_hypertree + k*cost_fors_tree;

                        /*
                         * Verify time is:
                         * - Time for H_msg message hash (1)
                         * - Time to walk up each FORS tree (a+1 each, k times)
                         * - Time to combine the FORS roots together (1)
                         * - For each Merkle tree (that is, d itmes):
                         *   - Walk up (on average) half the Winternitz chain,
                         *     for each Winternitz digit (wd times)
                         *   - Compute the Winternitz heads together
                         *   - Walk up the Merkle auth path (h_merkle)
                         */
                        p->ver_time = 1 + k * (a+1) + 1 + d * (wd * w/2 + 1 + h_merkle);
                        p->link = *current_list;
                        *current_list = p;
                    }
                }

            }
        }
    }

    /* Sort the queues into the order of decreasing goodness */
    w16_q = my_sort( w16_q );
    w256_q = my_sort( w256_q );
    wother_q = my_sort( wother_q );

    /* And start printing out the table, in the format that can be pasted */
    /* directly into the Latex document */
    printf( "\\begin{longtable}{c|c|c|c|c|c|c|c|c|c|c|c|c|c|c|c|c}\n" );
    printf( "      &     &     &     &      &     &     &        &     & sec  &  pk   &  sig  & \\%% & sign & verify & sigs at & overuse \\\\\n" );
    printf( "   ID & $n$ & $h$ & $d$ & $h'$ & $a$ & $k$ & $lg_w$ & $m$ & cat. & bytes & bytes & size & time & time   & level %d & safety \\\\\n", test_sec_level );
#if 0
    printf( "   ID & H  &  D &  A &  K &  W  &  SigSize & Sign Time & Verify Time & Sigs/level %d \\\\\n", test_sec_level );
#endif
    printf( "  \\hline \\endhead\n" );

    /* Gather up the parameter sets to print */
    struct parameter_set *print_list = 0, **end_print_list;
    end_print_list = &print_list;

    /* Now, step through the lists, and select 'the good entries' */
    int min_sec_level[3] = { 0, 0, 0 };  /* This is the 'overuse' level of */
                /* the three W types.  That is, the highest value we've seen */
                /* of 100 * log2 of the number of signatures that still */
                /* achieve the secondary security level (test_sec_level) */
               
    int cutoff[3] = { 0, 0, 0 };
    unsigned smallest_sig = UINT_MAX;
//    unsigned smallest_overuse = UINT_MAX;
    while (w16_q || w256_q || wother_q) {

        /* Get the next 'best' parameter set */
        int winner;
        struct parameter_set *p;
            /* Start with the best W=16 parameter set */
        { p = w16_q; winner = 0; }
            /* Switch to the best W=4,256 parameter set if it is better */
        if (!p || (w256_q && w256_q->sig_size < p->sig_size)) {
            p = w256_q; winner = 1;
        }
            /* Switch to the best W=2,8,32,64,128 parameter set if better */
        if (!p || (wother_q && wother_q->sig_size < p->sig_size)) {
            p = wother_q; winner = 2;
        }

        /* Pull the winner off of its list */
        switch (winner) {
        case 0: w16_q = p->link; break;
        case 1: w256_q = p->link; break;
        case 2: wother_q = p->link; break;
        }

        if (cutoff[winner]) {
            /* We're not listing outputs at this level anymore */
            free(p);
            continue;
        }

        /*
         * Check the overuse level of this parameter set
         * Note that this 'overuse' value is 100 times the actual value
         * which is the log2 of the number of signatures we can sign and
         * still be at the secondary security level (test_sec_level)
         */
        int overuse = compute_sigs_at_sec_level( test_sec_level, p->h, p->a, p->k );
        if (overuse <= min_sec_level[winner]) {
            /* Not as good as ones we've seen before */
            free(p);
            continue;
        }

        /* We decided to output this parameter set */
	*end_print_list = p;
	end_print_list = &p->link;
	p->link = 0;

	/* And record the smallest sig size */
	if (p->sig_size < smallest_sig) smallest_sig = p->sig_size;
	/* And the largest overuse value */
//	if (overuse < smallest_overuse) smallest_overuse = overuse;

        /*
         * Record how good this parameter set was (so we don't list any
         * latter ones which aren't better than this one)
         */
        int do_cutoff = max_s && (overuse/100 >= max_s); /* Set if this */
                  /* parameter set exceeded our top level limit, so we */
                  /* don't feel the need to list any more) */

        /*
         * W=16 parameter sets also block any other parameter sets which
         *      aren't better
         * W=4,256 parameter sets also block any W=2,8,32,64,128 parameter
         *      sets which aren't better
         */
        for (int j=winner; j<3; j++) {
            if (overuse > min_sec_level[j]) min_sec_level[j] = overuse;
            cutoff[j] |= do_cutoff;
        }
        if (cutoff[0]) break;  /* If we've blocked everything, we might */
                               /* as well stop going through the lists */
    }

    /* Ok, we have the list - print them out */
    int count = 0;
    for (; print_list; print_list = print_list->link) {
        struct parameter_set *p = print_list;

        count++;
        if (label) {
            printf( "  %s-", label );
            int k = strlen( label ) + 1 + printf( "%d", count );
            for (; k<4; k++) printf( " " );
            printf( "& " );
        } else {
            printf( "  %4d & ", count );
        } 
	int m = divru(p->h - p->h/p->d, 8) + divru(p->h/p->d, 8) + divru(p->a*p->k, 8);
        int overuse = compute_sigs_at_sec_level( test_sec_level, p->h, p->a, p->k );
//	int delta_overuse = overuse - smallest_overuse;
        printf( "%2d & %3d & %2d & %2d & %2d & %2d &   %d  & %2d &    %d     &     %d   & %  8d  & %d\\%% & % 9d & % 11d & %d.%02d & %u \\\\\n",
	         sec_level/8,
                       p->h, p->d, p->h/p->d, p->a, p->k, ilog2(p->w), m,
		       (sec_level/64)*2 - 3, 2*(sec_level/8),
		                           p->sig_size, 100*p->sig_size / smallest_sig, p->sig_time,
                                                               p->ver_time,
                   overuse/100, overuse % 100, (unsigned)pow(2, (float)overuse/100 - num_sig ) );
#if 0
        printf( "%2d & %2d & %2d & %2d & %3d & % 8d & % 9d & % 11d & %d.%02d \\\\\n",
                 p->h, p->d,  p->a,p->k, p->w,   p->sig_size,
                                                        p->sig_time,
                                                               p->ver_time,
                   overuse/100, overuse % 100 );
#endif

        /* If the user asked for the overuse graph being dumped to a file, */
        /* compute and write those values */
        if (label) {
            char filename[200];
            sprintf( filename, "%s-%d.csv", label, count );
            FILE *f = fopen( filename, "w" );
            if (!f) {
                fprintf( stderr, "Unable to open %s\n", filename );
                goto skip_file_output;
            }
            unsigned x;
            for (x = 100*(num_sig-1); x < 100*(max_s+10); x++) {
                double fx = x / 100.0;
                double y = compute_sec_level(fx, p->h, p->a, p->k);
                if (y > sec_level) y = sec_level;
                if (y < 10) break;  /* No reason to list where the security */
                                    /* level drops to below '10 bits' */
                fprintf( f, "%f, %f\n", fx, y );
            }
            fclose(f);
skip_file_output:;
        }
    }

    /*
     * And print out the table trailer
     */
    printf( "\\caption{Selection set (%d, %d, $2^{%d}$, %s)}\n",
            sec_level, test_sec_level, num_sig, commify( sign_op ) );
    if (label) {
        printf( "\\label{table:%s}\n", label );
    }
    printf( "\\end{longtable}\n" );
}
