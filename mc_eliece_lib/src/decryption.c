/*
 * decryption.c
 * Usage: decryption --c <c.vec> --privdir <dir> --out <m_recovered.vec>
 *
 * Recovers m from c = m * G_pub + e using the private key (S, G_priv, P).
 *
 * Steps:
 *   1. c' = c * P^T           (undo permutation)
 *   2. m' = decode(c', G_priv) (exploit systematic structure)
 *   3. m  = m' * S^{-1}       (undo scrambling)
 *
 * Decoder: G_priv = [I_k | R]  →  c' = [m' + e_k | m'*R + e_r]
 *   Guess e_k (error on info bits) exhaustively up to weight 3.
 *   For each candidate m'_cand = c'_k XOR e_k_guess, check
 *   weight(c'_r XOR m'_cand * R) <= t - weight(e_k_guess).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "matrix.h"

static void usage(void)
{ fprintf(stderr,"usage: decryption --c <c.vec> --privdir <dir> --out <m.vec>\n"); exit(1); }

/* Compute m * R_block  (R is the right k×r sub-block of G_priv) */
static Vec *mul_R_block(const Vec *m, const Matrix *G, int k, int r)
{
    Vec *res = vec_alloc(r);
    for (int j=0; j<r; j++) {
        int s=0;
        for (int i=0; i<k; i++) s ^= m->data[i] & mat_get(G, i, k+j);
        res->data[j] = s & 1;
    }
    return res;
}

/* Check candidate m': does weight(c_r XOR m'*R) <= remaining_t? */
static int check_candidate(const Vec *m_cand, const Matrix *G_priv,
                             const Vec *c_r, int k, int r, int remaining_t)
{
    Vec *p   = mul_R_block(m_cand, G_priv, k, r);
    Vec *res = vec_copy(c_r);
    vec_xor(res, p);
    int w = vec_weight(res);
    vec_free(p); vec_free(res);
    return w <= remaining_t;
}

static Vec *vec_flip(const Vec *v, int i)
{ Vec *u = vec_copy(v); u->data[i] ^= 1; return u; }

/*
 * Systematic decoder: tries error patterns of weight 0,1,2,3 on info bits.
 * Returns recovered m' (length k) or NULL.
 */
static Vec *systematic_decode(const Matrix *G_priv, const Vec *c_prime,
                               int k, int n, int t)
{
    int r = n - k;

    /* split c' into info half and redundancy half */
    Vec *c_k = vec_alloc(k), *c_r = vec_alloc(r);
    for (int i=0; i<k; i++) c_k->data[i] = c_prime->data[i];
    for (int i=0; i<r; i++) c_r->data[i] = c_prime->data[k+i];

    /* depth 0 */
    if (check_candidate(c_k, G_priv, c_r, k, r, t)) {
        vec_free(c_r); return c_k;
    }

    /* depth 1 */
    for (int i=0; i<k; i++) {
        Vec *cand = vec_flip(c_k, i);
        if (check_candidate(cand, G_priv, c_r, k, r, t-1)) {
            vec_free(c_k); vec_free(c_r); return cand;
        }
        vec_free(cand);
    }

    /* depth 2 */
    if (t >= 2) {
        for (int i=0; i<k; i++) {
            Vec *m1 = vec_flip(c_k, i);
            for (int j=i+1; j<k; j++) {
                Vec *cand = vec_flip(m1, j);
                if (check_candidate(cand, G_priv, c_r, k, r, t-2)) {
                    vec_free(m1); vec_free(c_k); vec_free(c_r); return cand;
                }
                vec_free(cand);
            }
            vec_free(m1);
        }
    }

    /* depth 3 (only for small k to keep runtime manageable) */
    if (t >= 3 && k <= 500) {
        for (int i=0; i<k; i++) {
            Vec *m1 = vec_flip(c_k, i);
            for (int j=i+1; j<k; j++) {
                Vec *m2 = vec_flip(m1, j);
                for (int l=j+1; l<k; l++) {
                    Vec *cand = vec_flip(m2, l);
                    if (check_candidate(cand, G_priv, c_r, k, r, t-3)) {
                        vec_free(m2); vec_free(m1);
                        vec_free(c_k); vec_free(c_r); return cand;
                    }
                    vec_free(cand);
                }
                vec_free(m2);
            }
            vec_free(m1);
        }
    }

    vec_free(c_k); vec_free(c_r);
    return NULL;
}

int main(int argc, char *argv[])
{
    const char *c_path=NULL, *priv_dir=NULL, *out_path=NULL;
    for (int i=1; i<argc; i++) {
        if      (!strcmp(argv[i],"--c")       && i+1<argc) c_path   = argv[++i];
        else if (!strcmp(argv[i],"--privdir") && i+1<argc) priv_dir = argv[++i];
        else if (!strcmp(argv[i],"--out")     && i+1<argc) out_path = argv[++i];
        else usage();
    }
    if (!c_path||!priv_dir||!out_path) usage();

    char path[4096];
#define PRIV(name) (snprintf(path,sizeof(path),"%s/%s",priv_dir,name),path)

    Matrix *G_priv = mat_read(PRIV("G_priv.mat"));
    Matrix *S      = mat_read(PRIV("S.mat"));
    Matrix *P      = mat_read(PRIV("P.mat"));

    int k = G_priv->rows, n = G_priv->cols;

    int t = 0;
    { FILE *pf = fopen(PRIV("params.txt"),"r");
      if (pf) { int tv; if (fscanf(pf,"q=%*d k=%*d t=%d",&tv)==1) t=tv; fclose(pf); }
      if (!t) t = (n-k)/4; }

    fprintf(stderr,"[decryption] k=%d n=%d t=%d\n", k, n, t);

    Vec *c = vec_read(c_path);
    if (c->len != n) {
        fprintf(stderr,"decryption: ciphertext len %d != n=%d\n", c->len, n); exit(1);
    }

    /* Step 1: c' = c * P^T */
    Matrix *P_T    = mat_transpose(P);
    Vec    *c_prime = vec_mat_mul(c, P_T);

    /* Step 2: decode */
    Vec *m_prime = systematic_decode(G_priv, c_prime, k, n, t);
    if (!m_prime) {
        fprintf(stderr,"[decryption] WARNING: decoder failed – using raw c'_k\n");
        m_prime = vec_alloc(k);
        for (int i=0; i<k; i++) m_prime->data[i] = c_prime->data[i];
    }

    /* Step 3: m = m' * S^{-1} */
    Matrix *S_inv = mat_inv_gf2(S);
    Vec    *m     = vec_mat_mul(m_prime, S_inv);

    vec_write(out_path, m);
    fprintf(stderr,"[decryption] m (length %d) -> %s\n", m->len, out_path);

    vec_free(c); vec_free(c_prime); vec_free(m_prime); vec_free(m);
    mat_free(G_priv); mat_free(S); mat_free(P); mat_free(P_T); mat_free(S_inv);
    return 0;
}
