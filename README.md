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

1. **heap\_setup / heap\_clean**

   * Initialize (`sbrk(0)`) and reset the custom heap.

2. **heap\_malloc(size\_t size)**

   * Allocate a block of memory with `size` bytes.
   * Places `FENCE` bytes before and after the data region.
   * Records a checksum of the header to detect corruption.

3. **heap\_calloc(size\_t num, size\_t size)**

   * Allocate and zero-initialize an array of `num × size` bytes.

4. **heap\_realloc(void *ptr, size\_t new\_size)**

   * Resize an existing block, preserving content up to the smaller of old/new sizes.
   * Expands in-place when possible or moves to a new block if necessary.

5. **heap\_free(void *ptr)**

   * Marks a block as free and coalesces with adjacent free blocks.

6. **heap\_validate(void)**

   * Verifies the integrity of all blocks by checking:

     * Header checksum (`control_size`).
     * Fence bytes sequence.
   * Returns error codes indicating various corruption scenarios.

7. **heap\_get\_largest\_used\_block\_size(void)**

   * Returns the size of the largest allocated (non-free) block.

8. **get\_pointer\_type(const void *ptr)**

   * Identifies pointer types (valid data, inside fences, control block, unallocated, or corrupted).

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


