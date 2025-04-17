# Bencode decoder in ANSI C

> This is an stb-style header-only fork of the original [bencode-c](https://github.com/skeeto/bencode-c).
> To enable implementation, define the macro BENCODE_IMPL *once* in your project.
> -- TR

This is a strict steaming parser for [bencode][bencode]. Inputs are
thoroughly validated and invalid inputs are rejected.

The full API is documented in `bencode.h`. Here's the list of functions:

```c
void bencode_init(struct bencode *, const void *, size_t);
void bencode_reinit(struct bencode *, const void *, size_t);
void bencode_free(struct bencode *);
int  bencode_next(struct bencode *);
```

Run the test suite with `make check`.


[bencode]: https://en.wikipedia.org/wiki/Bencode
