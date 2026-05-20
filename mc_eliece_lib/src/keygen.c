/*
 * keygen.c
 * Usage: keygen --q <q> --k <k> --t <t> --outdir <dir>
 *
 * Key insight for correct decryption:
 *   With systematic G_priv = [I_k | R], ciphertext c' = [m' XOR e_k | m'*R XOR e_r]
 *   We recover m' = c'_k XOR e_k.  For this to be feasible with exhaustive
 *   depth-d search, we need E[weight(e_k)] = t * k/n to be small.
 *   So we set n = k + r where r = k * t  (much larger redundancy).
 *   This makes E[errors on info bits] = t * k/n = t*k/(k+k*t) = 1/(1+t) < 1.
 *   Almost always, zero info-bit errors → depth-0 decode works perfectly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "matrix.h"

static void usage(void)
{ fprintf(stderr,"usage: keygen --q <q> --k <k> --t <t> --outdir <dir>\n"); exit(1); }

static void shuffle(int *a, int n)
{ for (int i=n-1; i>0; i--) { int j=rand()%(i+1), tmp=a[i]; a[i]=a[j]; a[j]=tmp; } }

static Matrix *random_invertible_k(int k)
{
    Matrix *m = mat_alloc(k, k);
    for (;;) {
        for (int r=0; r<k; r++)
            for (int c=0; c<k; c++) mat_set(m,r,c,rand()&1);
        Matrix *cp = mat_alloc(k,k);
        memcpy(cp->data, m->data, k*k*sizeof(int));
        int rank = gf2_rref(cp, NULL); mat_free(cp);
        if (rank == k) return m;
    }
}

static Matrix *systematic_generator(int k, int n)
{
    Matrix *G = mat_alloc(k, n);
    for (int i=0; i<k; i++) mat_set(G,i,i,1);
    for (int i=0; i<k; i++)
        for (int j=k; j<n; j++) mat_set(G,i,j,rand()&1);
    return G;
}

static Matrix *random_perm(int n)
{
    int *p = (int*)malloc(n*sizeof(int));
    for (int i=0; i<n; i++) p[i]=i;
    shuffle(p,n);
    Matrix *P = mat_alloc(n,n);
    for (int i=0; i<n; i++) mat_set(P,i,p[i],1);
    free(p);
    return P;
}

int main(int argc, char *argv[])
{
    int q=0,k=0,t=0; const char *outdir=NULL;
    for (int i=1; i<argc; i++) {
        if      (!strcmp(argv[i],"--q")      && i+1<argc) q      = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--k")      && i+1<argc) k      = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--t")      && i+1<argc) t      = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--outdir") && i+1<argc) outdir = argv[++i];
        else usage();
    }
    if (!q||!k||!t||!outdir) usage();
    srand((unsigned)time(NULL)^(unsigned)getpid());

    /*
     * Set redundancy r = k * t so that on average < 1 error hits the info bits.
     * This gives E[info errors] = t * k/(k + k*t) = 1/(1+t) ≪ 1 for t >= 2.
     * Depth-0 decode (assume all errors on redundancy side) succeeds ~e^{-1/(1+t)}
     * fraction of the time, and depth-1 catches the rest.
     */
    int r = k * t;
    int n = k + r;
    fprintf(stderr,"[keygen] q=%d k=%d t=%d n=%d r=%d\n", q, k, t, n, r);

    Matrix *S      = random_invertible_k(k);
    Matrix *G_priv = systematic_generator(k, n);
    Matrix *P      = random_perm(n);
    Matrix *SG     = mat_mul_gf2(S, G_priv);
    Matrix *G_pub  = mat_mul_gf2(SG, P);
    mat_free(SG);

    char path[4096];
#define W(name,mat) snprintf(path,sizeof(path),"%s/%s",outdir,name); mat_write(path,mat)
    W("G_pub.mat",  G_pub);
    W("G_priv.mat", G_priv);
    W("S.mat",      S);
    W("P.mat",      P);
#undef W
    snprintf(path,sizeof(path),"%s/params.txt",outdir);
    FILE *pf=fopen(path,"w");
    fprintf(pf,"q=%d k=%d t=%d n=%d r=%d\n",q,k,t,n,r);
    fclose(pf);

    fprintf(stderr,"[keygen] done. G_pub: %dx%d\n", G_pub->rows, G_pub->cols);
    mat_free(S); mat_free(G_priv); mat_free(P); mat_free(G_pub);
    return 0;
}
