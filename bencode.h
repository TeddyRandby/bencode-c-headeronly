/* Bencode decoder in ANSI C
 *
 * This library only allocates a small stack, though it expects the
 * entire input at once up front. All returned pointers point into this
 * user-supplied buffer.
 *
 * This is free and unencumbered software released into the public domain.
 */
#ifndef BENCODE_H
#define BENCODE_H

#include <stddef.h>

#define BENCODE_ERROR_OOM        -4
#define BENCODE_ERROR_BAD_KEY    -3
#define BENCODE_ERROR_EOF        -2
#define BENCODE_ERROR_INVALID    -1
#define BENCODE_DONE              0
#define BENCODE_INTEGER           1
#define BENCODE_STRING            2
#define BENCODE_LIST_BEGIN        3
#define BENCODE_LIST_END          4
#define BENCODE_DICT_BEGIN        5
#define BENCODE_DICT_END          6

#define BENCODE_FLAG_FIRST         (1 << 0)
#define BENCODE_FLAG_DICT          (1 << 1)
#define BENCODE_FLAG_EXPECT_VALUE  (1 << 2)

/**
 * Return 1 if next element will be the first element at this nesting.
 * This is a helper macro.
 */
#define BENCODE_FIRST(ctx) \
    ((ctx)->size ? (ctx)->stack[(ctx)->size - 1].flags & BENCODE_FLAG_FIRST \
                 : !ctx->tok)
/**
 * Return 1 if next element is a dictionary value.
 * This is a helper macro.
 */
#define BENCODE_IS_VALUE(ctx) \
    ((ctx)->size && \
     ((ctx)->stack[(ctx)->size - 1].flags & BENCODE_FLAG_DICT) && \
     ((ctx)->stack[(ctx)->size - 1].flags & BENCODE_FLAG_EXPECT_VALUE))

struct bencode {
    const void *tok;
    size_t toklen;
    const void *buf;
    size_t buflen;
    struct {
        void *key;
        size_t keylen;
        int flags;
    } *stack;
    size_t cap;
    size_t size;
};

/**
 * Initialize a new decoder on the given buffer.
 *
 * This function cannot fail.
 */
void bencode_init(struct bencode *, const void *, size_t);

/**
 * Start parsing a fresh data buffer.
 *
 * Use this on an encoder previously initalized with bencode_init(), but
 * never freed with bencode_free(). This will reuse memory allocated for
 * the previous parsing tasks.
 */
void bencode_reinit(struct bencode *, const void *, size_t);

/**
 * Destroy the given encoder by freeing any resources.
 */
void bencode_free(struct bencode *);

/**
 * Return the next token in the input stream.
 *
 * Non-negative return values indicate success, negative return values
 * indicate errors. Errors are not recoverable, including OOM, though
 * bencode_free() and bencode_reset() will still work correctly.
 *
 * Returns one of the following values:
 *
 * BENCODE_DONE: Input parsed to completion without errors, including a
 * check for trailing garbage.
 *
 * BENCODE_INTEGER: Found an integer whose text representation is found
 * in the "tok" and "toklen" members of the parser object. This is
 * guaranteed to contain a valid integer, but you must parse the integer
 * yourself.
 *
 * BENCODE_STRING: Found a string, whose content can be found in the
 * "tok" and "toklen" members of the parser object.
 *
 * BENCODE_LIST_BEGIN: Found the beginning of a list.
 *
 * BENCODE_LIST_END: Found the end of the current list. This will always
 * be correctly paired with a BENCODE_LIST_BEGIN.
 *
 * BENCODE_DICT_BEGIN: Found the beginning of a dictionary. While inside
 * the dictionary, the parser will alternate between a string (key) and
 * another object (value).
 *
 * BENCODE_DICT_END: Found the end of the current dictionary. This will
 * always be correctly paired with a BENCODE_DICT_BEGIN.
 *
 * BENCODE_ERROR_INVALID: Found an invalid byte in the input. The "buf"
 * member of the parser object will point at the invalid byte.
 *
 * BENCODE_ERROR_EOF: The input was exhausted early, indicating
 * truncated input.
 *
 * BENCODE_ERROR_BAD_KEY: An invalid key was found while parsing a
 * dictionary. The key is either a duplicate or not properly sorted. The
 * offending key can be found in the "tok" and "toklen" members.
 *
 * BENCODE_ERROR_OOM: The input was so deeply nested that the parser ran
 * of memory for the stack.
 */
int bencode_next(struct bencode *);

#ifdef BENCODE_IMPL
#include <stdlib.h>
#include <string.h>
#include "bencode.h"

void
bencode_reinit(struct bencode *ctx, const void *buf, size_t len)
{
    ctx->tok = 0;
    ctx->toklen = 0;
    ctx->buf = buf;
    ctx->buflen = len;
    ctx->size = 0;
}

void
bencode_init(struct bencode *ctx, const void *buf, size_t len)
{
    ctx->tok = 0;
    ctx->toklen = 0;
    ctx->buf = buf;
    ctx->buflen = len;
    ctx->stack = 0;
    ctx->cap = 0;
    ctx->size = 0;
}

void
bencode_free(struct bencode *ctx)
{
    free(ctx->stack);
    ctx->stack = 0;
}

static int
bencode_get(struct bencode *ctx)
{
    const unsigned char *p = ctx->buf;
    if (!ctx->buflen)
        return -1;
    ctx->buflen--;
    ctx->buf = p + 1;
    return *p;
}

static int
bencode_peek(struct bencode *ctx)
{
    if (!ctx->buflen)
        return -1;
    return *(unsigned char *)ctx->buf;;
}

static size_t
bencode_push(struct bencode *ctx)
{
    if (ctx->size == ctx->cap) {
        void *newstack;
        size_t bytes, newcap;
        if (!ctx->stack) {
            newcap = 64;
        } else {
            newcap = ctx->cap * 2;
            if (!newcap) return -1;
        }
        bytes = newcap * sizeof(ctx->stack[0]);
        if (!bytes) return -1;
        newstack = realloc(ctx->stack, bytes);
        if (!newstack) return -1;
        ctx->stack = newstack;
    }
    return ctx->size++;
}

static int
bencode_integer(struct bencode *ctx)
{
    int c;

    ctx->tok = ctx->buf;

    c = bencode_get(ctx);
    switch (c) {
        case -1:
            return BENCODE_ERROR_EOF;
        case 0x2d: /* - */
            c = bencode_get(ctx);
            if (c == -1)
                return BENCODE_ERROR_EOF;
            if (c < 0x31 || c > 0x39) /* 1-9 */
                return BENCODE_ERROR_INVALID;
            break;
        case 0x30: /* 0 */
            c = bencode_get(ctx);
            if (c == -1)
                return BENCODE_ERROR_EOF;
            if (c != 0x65) /* e */
                return BENCODE_ERROR_INVALID;
            ctx->toklen = 1;
            return BENCODE_INTEGER;
    }
    if (c < 0x30 || c > 0x39)
        return BENCODE_ERROR_INVALID;

    /* Read until 'e' */
    do
        c = bencode_get(ctx);
    while (c >= 0x30 && c <= 0x39);
    if (c == -1)
        return BENCODE_ERROR_EOF;
    if (c != 0x65) /* e */
        return BENCODE_ERROR_INVALID;
    ctx->toklen = (char *)ctx->buf - (char *)ctx->tok - 1;
    return BENCODE_INTEGER;
}

static int
bencode_string(struct bencode *ctx)
{
    int c;
    const unsigned char *tok = (unsigned char *)ctx->buf - 1;

    /* Consume the remaining digits */
    do
        c = bencode_get(ctx);
    while (c >= 0x30 && c <= 0x39);
    if (c == -1)
        return BENCODE_ERROR_EOF;
    if (c != 0x3a) /* : */
        return BENCODE_ERROR_INVALID;

    /* Decode the length */
    ctx->tok = ctx->buf;
    ctx->toklen = 0;
    for (; tok < (unsigned char *)ctx->buf - 1; tok++) {
        size_t n = ctx->toklen * 10 + (*tok - 0x30);
        if (n < ctx->toklen) {
            /* Overflow: length definitely extends beyond the buffer size */
            return BENCODE_ERROR_EOF;
        }
        ctx->toklen = n;
    }

    /* Advance input to end of string */
    if (ctx->buflen < ctx->toklen)
        return BENCODE_ERROR_EOF;
    ctx->buf = (char *)ctx->buf + ctx->toklen;
    ctx->buflen -= ctx->toklen;
    return BENCODE_STRING;
}

int
bencode_next(struct bencode *ctx)
{
    int c, r;
    size_t i;
    void **keyptr = 0;
    size_t *keylenptr = 0;

    if (ctx->size) {
        int *flags = &ctx->stack[ctx->size - 1].flags;
        *flags &= ~BENCODE_FLAG_FIRST;
        if (*flags & BENCODE_FLAG_DICT) {
            /* Inside a dictionary, validate it */
            int c = bencode_peek(ctx);
            if (*flags & BENCODE_FLAG_EXPECT_VALUE) {
                /* Cannot end dictionary here */
                if (c == 0x65)
                    return BENCODE_ERROR_INVALID;
                *flags &= ~BENCODE_FLAG_EXPECT_VALUE;
            } else {
                /* Next value must look like a string or 'e' */
                if (c != 0x65 && (c < 0x30 || c > 0x39)) /* e, 0-9 */
                    return BENCODE_ERROR_INVALID;
                *flags |= BENCODE_FLAG_EXPECT_VALUE;
                keyptr = &ctx->stack[ctx->size - 1].key;
                keylenptr = &ctx->stack[ctx->size - 1].keylen;
            }
        }
    } else if (ctx->buflen == 0) {
        return ctx->tok ? BENCODE_DONE : BENCODE_ERROR_EOF;
    }

    r = BENCODE_ERROR_INVALID;
    c = bencode_get(ctx);
    switch (c) {
        case -1:
            return BENCODE_ERROR_EOF;
        case 0x64: /* d */
            i = bencode_push(ctx);
            if (i == (size_t)-1)
                return BENCODE_ERROR_OOM;
            ctx->stack[i].key = 0;
            ctx->stack[i].keylen = 0;
            ctx->stack[i].flags = BENCODE_FLAG_DICT | BENCODE_FLAG_FIRST;
            return BENCODE_DICT_BEGIN;
        case 0x65: /* e */
            if (!ctx->size)
                return BENCODE_ERROR_INVALID;
            i = --ctx->size;
            if (ctx->stack[i].flags & BENCODE_FLAG_DICT)
                return BENCODE_DICT_END;
            return BENCODE_LIST_END;
        case 0x69: /* i */
            return bencode_integer(ctx);
        case 0x6c: /* l */
            i = bencode_push(ctx);
            if (i == (size_t)-1)
                return BENCODE_ERROR_OOM;
            ctx->stack[i].flags = BENCODE_FLAG_FIRST;
            return BENCODE_LIST_BEGIN;
        case 0x30: /* 0 */
            c = bencode_get(ctx);
            if (c == -1)
                return BENCODE_ERROR_EOF;
            if (c != 0x3a) /* : */
                return BENCODE_ERROR_INVALID;
            ctx->tok = ctx->buf;
            ctx->toklen = 0;
            r = BENCODE_STRING;
            break;
        case 0x31: /* 1 */
        case 0x32: /* 2 */
        case 0x33: /* 3 */
        case 0x34: /* 4 */
        case 0x35: /* 5 */
        case 0x36: /* 6 */
        case 0x37: /* 7 */
        case 0x38: /* 8 */
        case 0x39: /* 9 */
            r = bencode_string(ctx);
            break;
    }

    if (r == BENCODE_STRING && keyptr) {
        /* Enforce key ordering */
        if (*keyptr) {
            if (ctx->toklen < *keylenptr) {
                if (memcmp(ctx->tok, *keyptr, ctx->toklen) <= 0)
                    return BENCODE_ERROR_BAD_KEY;
            } else if (*keylenptr < ctx->toklen ) {
                if (memcmp(ctx->tok, *keyptr, *keylenptr) < 0)
                    return BENCODE_ERROR_BAD_KEY;
            } else {
                if (memcmp(ctx->tok, *keyptr, ctx->toklen) <= 0)
                    return BENCODE_ERROR_BAD_KEY;
            }
        }
        *keyptr = (void *)ctx->tok;
        *keylenptr = ctx->toklen;
    }

    return r;
}
#endif

#endif
