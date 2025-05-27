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