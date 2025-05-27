# Custom Heap Memory Manager

This repository implements a **custom dynamic memory allocator** in C, providing functionality similar to the standard `malloc`, `calloc`, `realloc`, and `free`, but with additional safety features:

* **Fence bytes** (canaries) around allocated blocks to detect buffer overruns.
* **Control sums** (`control_size`) to verify the integrity of block headers.
* Linked-list–based free list management for reusing freed memory.
* Transparent use of system `sbrk()` to grow and shrink the heap.

---

## 📁 Repository Structure

```plain
/ (root)
├── main.c            # Example usage of the custom allocator and entry point
├── heap.c            # Core allocator implementation
└── heap.h            # Public API, data structures, and constants (HEADER_SIZE, FENCE, FENCE_BYTE)
```

---

## ⚙️ Features

### `heap_setup()` / `heap_clean()`
- Initializes the custom heap using `sbrk(0)` and resets its internal state.
- `heap_clean()` releases all allocated memory and clears internal bookkeeping.

### `heap_malloc(size_t size)`
- Allocates a memory block of `size` bytes.
- Inserts **fence bytes** (canaries) before and after the data region.
- Computes and stores a **checksum** (`control_size`) in the block header to detect corruption.

### `heap_calloc(size_t num, size_t size)`
- Allocates memory for an array of `num × size` bytes.
- Zero-initializes the entire block.

### `heap_realloc(void *ptr, size_t new_size)`
- Resizes an existing memory block, preserving content up to the smaller of old and new sizes.
- Expands in place if possible; otherwise, allocates a new block, copies data, and frees the old block.

### `heap_free(void *ptr)`
- Frees a previously allocated block.
- Coalesces adjacent free blocks to reduce fragmentation.

### `heap_validate(void)`
- Scans all heap blocks and verifies:
  - Header checksums (`control_size`).
  - Integrity of fence bytes.
- Returns specific error codes for various corruption scenarios (e.g., fence breach, checksum mismatch).

### `heap_get_largest_used_block_size(void)`
- Returns the size (in bytes) of the largest currently allocated (non-free) block.

### `get_pointer_type(const void *ptr)`
- Classifies the pointer’s status:
  - Valid data pointer
  - Inside fence area
  - Inside block metadata
  - Unallocated region
  - Corrupted or invalid pointer

---

## 📄 Example Usage (main.c)

```c
#include "heap.h"
#include <stdio.h>

int main() {
    if (heap_setup() != 0) {
        fprintf(stderr, "Heap initialization failed!\n");
        return 1;
    }

    int *arr = heap_malloc(sizeof(int) * 5);
    if (!arr) {
        fprintf(stderr, "Allocation failed!\n");
        heap_clean();
        return 1;
    }

    for (int i = 0; i < 5; i++) {
        arr[i] = i * 10;
        printf("arr[%d] = %d\n", i, arr[i]);
    }

    heap_free(arr);
    heap_clean();
    return 0;
}
```


