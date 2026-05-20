/*
 * encryption.c
 * Usage: encryption --G <G_pub.mat> --msg <m.vec> --t <t> --out <c.vec>
 *
 * Computes ciphertext  c = m * G_pub + e  over GF(2).
 * e is a random error vector of Hamming weight exactly t.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "matrix.h"

static void usage(void)
{ fprintf(stderr,"usage: encryption --G <G.mat> --msg <m.vec> --t <t> --out <c.vec>\n"); exit(1); }

static void shuffle(int *a, int n)
{ for (int i=n-1; i>0; i--) { int j=rand()%(i+1), t=a[i]; a[i]=a[j]; a[j]=t; } }

static Vec *random_error(int n, int t)
{
    if (t > n) t = n;
    int *pos = (int*)malloc(n*sizeof(int));
    for (int i=0; i<n; i++) pos[i] = i;
    shuffle(pos, n);
    Vec *e = vec_alloc(n);
    for (int i=0; i<t; i++) e->data[pos[i]] = 1;
    free(pos);
    return e;
}

int main(int argc, char *argv[])
{
    const char *G_path=NULL, *msg_path=NULL, *out_path=NULL; int t=0;
    for (int i=1; i<argc; i++) {
        if      (!strcmp(argv[i],"--G")   && i+1<argc) G_path   = argv[++i];
        else if (!strcmp(argv[i],"--msg") && i+1<argc) msg_path = argv[++i];
        else if (!strcmp(argv[i],"--t")   && i+1<argc) t        = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--out") && i+1<argc) out_path = argv[++i];
        else usage();
    }
    if (!G_path||!msg_path||!t||!out_path) usage();

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    Matrix *G = mat_read(G_path);
    Vec    *m = vec_read(msg_path);
    if (m->len != G->rows) {
        fprintf(stderr,"encryption: msg len %d != G rows %d\n", m->len, G->rows); exit(1);
    }

    Vec *c0 = vec_mat_mul(m, G);          /* m * G_pub */
    Vec *e  = random_error(G->cols, t);   /* random error weight t */
    vec_xor(c0, e);                        /* c = c0 XOR e */

    vec_write(out_path, c0);
    fprintf(stderr,"[encryption] k=%d n=%d t=%d weight(e)=%d -> %s\n",
            G->rows, G->cols, t, vec_weight(e), out_path);

    vec_free(m); vec_free(c0); vec_free(e); mat_free(G);
    return 0;
}
