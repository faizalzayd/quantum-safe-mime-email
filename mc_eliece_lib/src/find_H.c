/*
 * find_H.c
 * Usage: find_H --G <G_pub.mat> --out <H.mat>
 *
 * Computes parity-check matrix H (r×n) such that G * H^T = 0 over GF(2).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "matrix.h"

static void usage(void)
{ fprintf(stderr,"usage: find_H --G <G.mat> --out <H.mat>\n"); exit(1); }

int main(int argc, char *argv[])
{
    const char *G_path=NULL, *H_path=NULL;
    for (int i=1; i<argc; i++) {
        if      (!strcmp(argv[i],"--G")   && i+1<argc) G_path = argv[++i];
        else if (!strcmp(argv[i],"--out") && i+1<argc) H_path = argv[++i];
        else usage();
    }
    if (!G_path||!H_path) usage();

    Matrix *G = mat_read(G_path);
    int k = G->rows, n = G->cols, r = n - k;
    if (r <= 0) { fprintf(stderr,"find_H: n must be > k\n"); exit(1); }

    /* RREF copy to find pivot columns */
    Matrix *Gc = mat_alloc(k, n);
    memcpy(Gc->data, G->data, k*n*sizeof(int));
    int *pivot = (int*)malloc(k*sizeof(int));
    int rank = gf2_rref(Gc, pivot);
    if (rank != k) { fprintf(stderr,"find_H: G has rank %d < k=%d\n",rank,k); exit(1); }

    /* Identify non-pivot (redundancy) columns */
    int *is_piv = (int*)calloc(n, sizeof(int));
    for (int i=0; i<k; i++) is_piv[pivot[i]] = 1;
    int *red = (int*)malloc(r*sizeof(int));
    int ri = 0;
    for (int c=0; c<n; c++) if (!is_piv[c]) red[ri++] = c;

    /*
     * H in original column order:
     *   H[j][pivot[i]]  = Gc[i][red[j]]   (R^T block)
     *   H[j][red[j]]    = 1               (identity block)
     */
    Matrix *H = mat_alloc(r, n);
    for (int j=0; j<r; j++) {
        for (int i=0; i<k; i++)
            mat_set(H, j, pivot[i], mat_get(Gc, i, red[j]));
        mat_set(H, j, red[j], 1);
    }

    mat_write(H_path, H);
    fprintf(stderr,"[find_H] H: %dx%d -> %s\n", H->rows, H->cols, H_path);

    free(pivot); free(is_piv); free(red);
    mat_free(G); mat_free(Gc); mat_free(H);
    return 0;
}
