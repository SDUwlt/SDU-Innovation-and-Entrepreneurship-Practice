// merkle_demo.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "sm3.h"

/*
  Merkle tree helper using SM3 with RFC6962-style domain separation:
    LeafHash = H(0x00 || leaf_bytes)
    NodeHash = H(0x01 || left_hash || right_hash)
  For odd nodes at a level we duplicate the last node when pairing.
*/

/* utilities */
#define HASHLEN 32

static void print_hex(const uint8_t *p, size_t n){
    for(size_t i=0;i<n;i++) printf("%02x", p[i]);
    printf("\n");
}

static void hash_leaf(const void *leaf, size_t len, uint8_t out[HASHLEN]){
    uint8_t *buf = malloc(len + 1);
    buf[0] = 0x00;
    memcpy(buf+1, leaf, len);
    sm3_hash(buf, len+1, out);
    free(buf);
}

static void hash_node(const uint8_t left[HASHLEN], const uint8_t right[HASHLEN], uint8_t out[HASHLEN]){
    uint8_t buf[1 + HASHLEN + HASHLEN];
    buf[0] = 0x01;
    memcpy(buf+1, left, HASHLEN);
    memcpy(buf+1+HASHLEN, right, HASHLEN);
    sm3_hash(buf, 1 + HASHLEN + HASHLEN, out);
}

/* Build full tree levels.
   Input: array of pointers to leaf bytes and lengths.
   We will store tree as vector of levels; each level is array of hashes.
   Returns pointer to levels array and number of levels via out_levels.
   Caller should free levels and each level array.
*/
typedef struct {
    uint8_t *data; // contiguous array of (node_count * HASHLEN) bytes
    size_t nodes;
} level_t;

static level_t *merkle_build(uint8_t **leaf_bufs, size_t *leaf_lens, size_t n_leaves, size_t *out_levels){
    if(n_leaves == 0) return NULL;
    // maximum levels = ceil(log2(n_leaves)) + 1
    size_t max_levels = 0;
    size_t t = n_leaves;
    while(t){ max_levels++; t >>= 1; }
    max_levels += 2;

    level_t *levels = calloc(max_levels, sizeof(level_t));
    size_t level_idx = 0;

    // level 0: leaves hashed
    levels[level_idx].nodes = n_leaves;
    levels[level_idx].data = malloc(HASHLEN * n_leaves);
    for(size_t i=0;i<n_leaves;i++){
        hash_leaf(leaf_bufs[i], leaf_lens[i], levels[level_idx].data + i*HASHLEN);
    }

    // build upper levels
    while(levels[level_idx].nodes > 1){
        size_t cur_nodes = levels[level_idx].nodes;
        size_t next_nodes = (cur_nodes + 1) / 2;
        levels[level_idx+1].nodes = next_nodes;
        levels[level_idx+1].data = malloc(HASHLEN * next_nodes);

        uint8_t *cur = levels[level_idx].data;
        uint8_t *next = levels[level_idx+1].data;
        for(size_t i=0;i<next_nodes;i++){
            size_t left_idx = i*2;
            size_t right_idx = left_idx + 1;
            uint8_t left[HASHLEN], right[HASHLEN], out[HASHLEN];
            memcpy(left, cur + left_idx*HASHLEN, HASHLEN);
            if(right_idx < cur_nodes){
                memcpy(right, cur + right_idx*HASHLEN, HASHLEN);
            } else {
                // duplicate last if odd
                memcpy(right, left, HASHLEN);
            }
            hash_node(left, right, out);
            memcpy(next + i*HASHLEN, out, HASHLEN);
        }
        level_idx++;
    }

    *out_levels = level_idx + 1;
    return levels;
}

/* free levels */
static void merkle_free(level_t *levels, size_t nlevels){
    if(!levels) return;
    for(size_t i=0;i<nlevels;i++){
        if(levels[i].data) free(levels[i].data);
    }
    free(levels);
}

/* get root */
static void merkle_root(level_t *levels, size_t nlevels, uint8_t out[HASHLEN]){
    memcpy(out, levels[nlevels-1].data, HASHLEN);
}

/* Inclusion proof:
   For leaf index idx (0-based), produce an array of sibling hashes (each HASHLEN bytes) and directions.
   directions: 0 means sibling is right node (i.e., current node was left), 1 means sibling is left.
   Proof length is equal to nlevels-1 (but trailing levels may not be needed). We'll collect exactly the path length.
   Returns malloc'd proof_hashes pointer (proof_len * HASHLEN) and malloc'd directions (proof_len bytes). Caller frees.
*/
static int merkle_inclusion_proof(level_t *levels, size_t nlevels, size_t leaf_index,
                                  uint8_t **out_proof_hashes, uint8_t **out_dirs, size_t *out_len){
    if(!levels || nlevels==0) return -1;
    if(leaf_index >= levels[0].nodes) return -2;
    size_t idx = leaf_index;
    size_t max_proof_len = nlevels - 1;
    uint8_t *proof = malloc(HASHLEN * max_proof_len);
    uint8_t *dirs = malloc(max_proof_len);
    size_t plen = 0;
    for(size_t level=0; level < nlevels - 1; level++){
        size_t sibling;
        if(idx % 2 == 0){ // even -> sibling is idx+1 (right) if exists
            sibling = idx + 1;
            if(sibling >= levels[level].nodes){
                // no sibling -> duplicate ourselves; proof element is our hash (same)
                memcpy(proof + plen*HASHLEN, levels[level].data + idx*HASHLEN, HASHLEN);
                dirs[plen] = 0; // treat as sibling on right
            } else {
                memcpy(proof + plen*HASHLEN, levels[level].data + sibling*HASHLEN, HASHLEN);
                dirs[plen] = 0; // sibling is right
            }
        } else { // odd -> sibling is idx-1 (left)
            sibling = idx - 1;
            memcpy(proof + plen*HASHLEN, levels[level].data + sibling*HASHLEN, HASHLEN);
            dirs[plen] = 1; // sibling is left
        }
        plen++;
        idx = idx / 2;
    }
    *out_proof_hashes = proof;
    *out_dirs = dirs;
    *out_len = plen;
    return 0;
}

/* Verify inclusion:
   Given root, leaf bytes, proof_hashes (array of proof_len*HASHLEN), dirs (proof_len bytes), leaf_index
*/
static int merkle_verify_inclusion(const uint8_t root[HASHLEN],
                                   const void *leaf, size_t leaf_len,
                                   const uint8_t *proof_hashes, const uint8_t *dirs, size_t proof_len,
                                   size_t leaf_index){
    uint8_t cur[HASHLEN];
    hash_leaf(leaf, leaf_len, cur);
    size_t idx = leaf_index;
    for(size_t i=0;i<proof_len;i++){
        uint8_t left[HASHLEN], right[HASHLEN], out[HASHLEN];
        if(dirs[i] == 0){
            // sibling is right -> cur is left
            memcpy(left, cur, HASHLEN);
            memcpy(right, proof_hashes + i*HASHLEN, HASHLEN);
        } else {
            // sibling is left
            memcpy(left, proof_hashes + i*HASHLEN, HASHLEN);
            memcpy(right, cur, HASHLEN);
        }
        hash_node(left, right, out);
        memcpy(cur, out, HASHLEN);
        idx /= 2;
    }
    // compare cur and root
    if(memcmp(cur, root, HASHLEN)==0) return 1;
    return 0;
}

/* Non-membership proof for a sorted list of leaves (lexicographic on their raw bytes):
   If value exists -> return membership (found flag).
   If not found -> find insertion position pos (0..n), and return inclusion proofs for neighbors:
     - if pos==0: provide proof for leaf 0 (first) to show target < first
     - if pos==n: provide proof for leaf n-1 (last) to show target > last
     - else: provide proofs for leaf pos-1 and pos (neighbors). Verifier sees neighbors and concludes target not present.
   The function outputs the neighbor indices and their proofs.
   Note: This assumes the tree was constructed on the same *sorted* sequence of leaves.
*/
typedef struct {
    int found; // 1 if found
    size_t found_index;
    // if not found:
    size_t left_index;  // may be SIZE_MAX if none
    size_t right_index; // may be SIZE_MAX if none
    // proofs:
    uint8_t *left_proof_hashes; uint8_t *left_dirs; size_t left_proof_len;
    uint8_t *right_proof_hashes; uint8_t *right_dirs; size_t right_proof_len;
} nm_proof_t;

static nm_proof_t merkle_non_membership_proof(uint8_t **leaf_bufs, size_t *leaf_lens, size_t n_leaves,
                                              level_t *levels, size_t nlevels,
                                              const void *target, size_t target_len){
    nm_proof_t out;
    memset(&out, 0, sizeof(out));
    out.left_index = out.right_index = SIZE_MAX;

    // binary search on byte arrays (lexicographic)
    size_t lo = 0, hi = n_leaves;
    while(lo < hi){
        size_t mid = (lo + hi) / 2;
        int cmp = memcmp(leaf_bufs[mid], target, (leaf_lens[mid] < target_len) ? leaf_lens[mid] : target_len);
        if(cmp == 0){
            if(leaf_lens[mid] == target_len) { // equal length and contents equal
                out.found = 1; out.found_index = mid; return out;
            }
            // else cmp==0 but lengths differ -> decide by lengths
            if(leaf_lens[mid] < target_len) cmp = -1; else cmp = 1;
        }
        if(cmp < 0) lo = mid + 1; else hi = mid;
    }
    // insertion position is lo
    if(lo == 0){
        out.left_index = SIZE_MAX;
        out.right_index = 0;
        // provide proof for right (first)
        merkle_inclusion_proof(levels, nlevels, 0, &out.right_proof_hashes, &out.right_dirs, &out.right_proof_len);
    } else if(lo == n_leaves){
        out.left_index = n_leaves - 1;
        out.right_index = SIZE_MAX;
        merkle_inclusion_proof(levels, nlevels, n_leaves-1, &out.left_proof_hashes, &out.left_dirs, &out.left_proof_len);
    } else {
        out.left_index = lo - 1;
        out.right_index = lo;
        merkle_inclusion_proof(levels, nlevels, out.left_index, &out.left_proof_hashes, &out.left_dirs, &out.left_proof_len);
        merkle_inclusion_proof(levels, nlevels, out.right_index, &out.right_proof_hashes, &out.right_dirs, &out.right_proof_len);
    }
    out.found = 0;
    return out;
}

static void free_nm_proof(nm_proof_t *p){
    if(!p) return;
    if(p->left_proof_hashes) free(p->left_proof_hashes);
    if(p->left_dirs) free(p->left_dirs);
    if(p->right_proof_hashes) free(p->right_proof_hashes);
    if(p->right_dirs) free(p->right_dirs);
}

/* Example main: build 100000 leaves, test inclusion and non-membership */
int main(void){
    const size_t N = 100000;
    printf("Building %zu leaves...\n", N);

    // allocate leaf buffers and lengths
    uint8_t **leaf_bufs = calloc(N, sizeof(uint8_t*));
    size_t *leaf_lens = calloc(N, sizeof(size_t));
    if(!leaf_bufs || !leaf_lens){ fprintf(stderr,"alloc fail\n"); return 1; }

    // prepare leaves as "leaf-%d" strings (sorted)
    char tmp[64];
    for(size_t i=0;i<N;i++){
        int l = snprintf(tmp, sizeof(tmp), "leaf-%08zu", i);
        leaf_lens[i] = (size_t)l;
        leaf_bufs[i] = malloc(leaf_lens[i]);
        memcpy(leaf_bufs[i], tmp, leaf_lens[i]);
    }

    size_t nlevels;
    level_t *levels = merkle_build(leaf_bufs, leaf_lens, N, &nlevels);
    uint8_t root[HASHLEN];
    merkle_root(levels, nlevels, root);
    printf("Merkle root: "); print_hex(root, HASHLEN);

    // test inclusion for random index
    srand((unsigned)time(NULL));
    size_t idx = rand() % N;
    uint8_t *proof_hashes; uint8_t *dirs; size_t proof_len;
    if(merkle_inclusion_proof(levels, nlevels, idx, &proof_hashes, &dirs, &proof_len)!=0){
        fprintf(stderr,"inclusion proof fail\n"); return 1;
    }
    printf("Testing inclusion for index %zu (leaf='%.*s')... proof_len=%zu\n", idx, (int)leaf_lens[idx], leaf_bufs[idx], proof_len);
    int ok = merkle_verify_inclusion(root, leaf_bufs[idx], leaf_lens[idx], proof_hashes, dirs, proof_len, idx);
    printf("Inclusion verification: %s\n", ok? "OK":"FAIL");
    free(proof_hashes); free(dirs);

    // test non-membership for some value not present
    const char *not_present = "leaf-99999999"; // definitely outside 0..N-1
    nm_proof_t nm = merkle_non_membership_proof(leaf_bufs, leaf_lens, N, levels, nlevels, not_present, strlen(not_present));
    printf("Non-membership test for '%s'\n", not_present);
    if(nm.found){
        printf("Unexpected: found at index %zu\n", nm.found_index);
    } else {
        if(nm.left_index!=SIZE_MAX){
            printf("Left neighbor index %zu (leaf='%.*s') proof_len=%zu verify->%s\n",
                   nm.left_index, (int)leaf_lens[nm.left_index], leaf_bufs[nm.left_index], nm.left_proof_len,
                   merkle_verify_inclusion(root, leaf_bufs[nm.left_index], leaf_lens[nm.left_index],
                                           nm.left_proof_hashes, nm.left_dirs, nm.left_proof_len, nm.left_index) ? "OK":"FAIL");
        } else {
            printf("No left neighbor (target would be before first leaf)\n");
        }
        if(nm.right_index!=SIZE_MAX){
            printf("Right neighbor index %zu (leaf='%.*s') proof_len=%zu verify->%s\n",
                   nm.right_index, (int)leaf_lens[nm.right_index], leaf_bufs[nm.right_index], nm.right_proof_len,
                   merkle_verify_inclusion(root, leaf_bufs[nm.right_index], leaf_lens[nm.right_index],
                                           nm.right_proof_hashes, nm.right_dirs, nm.right_proof_len, nm.right_index) ? "OK":"FAIL");
        } else {
            printf("No right neighbor (target would be after last leaf)\n");
        }
    }

    // cleanup
    free_nm_proof(&nm);
    merkle_free(levels, nlevels);
    for(size_t i=0;i<N;i++){ free(leaf_bufs[i]); }
    free(leaf_bufs); free(leaf_lens);
    return 0;
}
