/*
 * matrix.h  –  GF(2) matrix and vector helpers.
 *              Header-only; include in exactly ONE .c file per binary.
 *              Contains ONLY: types, alloc/free, I/O, GF(2) arithmetic.
 *              No main(), no keygen helpers, no application logic.
 */

#ifndef MATRIX_H
#define MATRIX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Types ─────────────────────────────────────────────────────────────────── */

typedef struct { int rows, cols; int *data; } Matrix;
typedef struct { int len;        int *data; } Vec;

/* ── Matrix alloc/free ─────────────────────────────────────────────────────── */

static inline Matrix *mat_alloc(int rows, int cols)
{
    Matrix *m = (Matrix*)malloc(sizeof(Matrix));
    m->rows = rows; m->cols = cols;
    m->data = (int*)calloc(rows * cols, sizeof(int));
    return m;
}
static inline void mat_free(Matrix *m)
{ if (m) { free(m->data); free(m); } }

static inline int  mat_get(const Matrix *m, int r, int c)
{ return m->data[r * m->cols + c]; }
static inline void mat_set(Matrix *m, int r, int c, int v)
{ m->data[r * m->cols + c] = v & 1; }

/* ── Vec alloc/free ────────────────────────────────────────────────────────── */

static inline Vec *vec_alloc(int len)
{
    Vec *v = (Vec*)malloc(sizeof(Vec));
    v->len = len;
    v->data = (int*)calloc(len, sizeof(int));
    return v;
}
static inline void vec_free(Vec *v) { if (v) { free(v->data); free(v); } }

static inline Vec *vec_copy(const Vec *v)
{
    Vec *c = vec_alloc(v->len);
    memcpy(c->data, v->data, v->len * sizeof(int));
    return c;
}
static inline void vec_xor(Vec *a, const Vec *b)
{ for (int i = 0; i < a->len && i < b->len; i++) a->data[i] ^= b->data[i]; }
static inline int vec_weight(const Vec *v)
{ int w = 0; for (int i = 0; i < v->len; i++) w += v->data[i]; return w; }

/* ── I/O ───────────────────────────────────────────────────────────────────── */

static inline void mat_write(const char *path, const Matrix *m)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); exit(1); }
    fprintf(f, "%d %d\n", m->rows, m->cols);
    for (int r = 0; r < m->rows; r++) {
        for (int c = 0; c < m->cols; c++) {
            if (c) fputc(' ', f);
            fputc('0' + mat_get(m, r, c), f);
        }
        fputc('\n', f);
    }
    fclose(f);
}

static inline Matrix *mat_read(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); exit(1); }
    int rows, cols;
    if (fscanf(f, "%d %d", &rows, &cols) != 2) {
        fprintf(stderr, "mat_read: bad header in %s\n", path); exit(1);
    }
    Matrix *m = mat_alloc(rows, cols);
    for (int r = 0; r < rows; r++)
        for (int c = 0; c < cols; c++) {
            int v; fscanf(f, "%d", &v); mat_set(m, r, c, v);
        }
    fclose(f);
    return m;
}

static inline void vec_write(const char *path, const Vec *v)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); exit(1); }
    for (int i = 0; i < v->len; i++) {
        if (i) fputc(' ', f);
        fputc('0' + (v->data[i] & 1), f);
    }
    fputc('\n', f);
    fclose(f);
}

static inline Vec *vec_read(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); exit(1); }
    int cap = 256, len = 0, v;
    int *tmp = (int*)malloc(cap * sizeof(int));
    while (fscanf(f, "%d", &v) == 1) {
        if (len == cap) { cap *= 2; tmp = (int*)realloc(tmp, cap*sizeof(int)); }
        tmp[len++] = v & 1;
    }
    fclose(f);
    Vec *vec = vec_alloc(len);
    memcpy(vec->data, tmp, len * sizeof(int));
    free(tmp);
    return vec;
}

/* ── GF(2) arithmetic ──────────────────────────────────────────────────────── */

/* In-place RREF over GF(2). Returns rank. Fills pivot_cols[] if not NULL. */
static inline int gf2_rref(Matrix *m, int *pivot_cols)
{
    int rank = 0;
    for (int col = 0; col < m->cols && rank < m->rows; col++) {
        int pivot = -1;
        for (int r = rank; r < m->rows; r++)
            if (mat_get(m, r, col)) { pivot = r; break; }
        if (pivot < 0) continue;
        if (pivot != rank)
            for (int c = 0; c < m->cols; c++) {
                int t = mat_get(m, rank, c);
                mat_set(m, rank, c, mat_get(m, pivot, c));
                mat_set(m, pivot, c, t);
            }
        for (int r = 0; r < m->rows; r++)
            if (r != rank && mat_get(m, r, col))
                for (int c = 0; c < m->cols; c++)
                    mat_set(m, r, c, mat_get(m, r, c) ^ mat_get(m, rank, c));
        if (pivot_cols) pivot_cols[rank] = col;
        rank++;
    }
    return rank;
}

/* result = M * v  (M rows×cols, v length cols → result length rows) */
static inline Vec *mat_vec_mul(const Matrix *M, const Vec *v)
{
    Vec *r = vec_alloc(M->rows);
    for (int i = 0; i < M->rows; i++) {
        int s = 0;
        for (int j = 0; j < M->cols; j++) s ^= mat_get(M, i, j) & v->data[j];
        r->data[i] = s & 1;
    }
    return r;
}

/* result = v * M  (v length rows, M rows×cols → result length cols) */
static inline Vec *vec_mat_mul(const Vec *v, const Matrix *M)
{
    Vec *r = vec_alloc(M->cols);
    for (int j = 0; j < M->cols; j++) {
        int s = 0;
        for (int i = 0; i < M->rows; i++) s ^= v->data[i] & mat_get(M, i, j);
        r->data[j] = s & 1;
    }
    return r;
}

/* A * B over GF(2) */
static inline Matrix *mat_mul_gf2(const Matrix *A, const Matrix *B)
{
    Matrix *C = mat_alloc(A->rows, B->cols);
    for (int i = 0; i < A->rows; i++)
        for (int j = 0; j < B->cols; j++) {
            int s = 0;
            for (int l = 0; l < A->cols; l++) s ^= mat_get(A,i,l) & mat_get(B,l,j);
            mat_set(C, i, j, s);
        }
    return C;
}

/* Invert a k×k matrix over GF(2) via augmented RREF */
static inline Matrix *mat_inv_gf2(const Matrix *A)
{
    int k = A->rows;
    Matrix *aug = mat_alloc(k, 2*k);
    for (int r = 0; r < k; r++) {
        for (int c = 0; c < k; c++) mat_set(aug, r, c, mat_get(A, r, c));
        mat_set(aug, r, k+r, 1);
    }
    if (gf2_rref(aug, NULL) != k) {
        fprintf(stderr, "mat_inv_gf2: singular matrix\n"); exit(1);
    }
    Matrix *inv = mat_alloc(k, k);
    for (int r = 0; r < k; r++)
        for (int c = 0; c < k; c++)
            mat_set(inv, r, c, mat_get(aug, r, k+c));
    mat_free(aug);
    return inv;
}

/* Transpose */
static inline Matrix *mat_transpose(const Matrix *M)
{
    Matrix *T = mat_alloc(M->cols, M->rows);
    for (int r = 0; r < M->rows; r++)
        for (int c = 0; c < M->cols; c++)
            mat_set(T, c, r, mat_get(M, r, c));
    return T;
}

#endif /* MATRIX_H */
