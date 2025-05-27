#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include "heap.h"

struct memory_manager_t
{
    void *memory_start;
    struct memory_chunk_t *first_memory_chunk;
};

struct memory_chunk_t
{
    struct memory_chunk_t* prev;
    struct memory_chunk_t* next;
    size_t size;
    int free;
    uint64_t control_size;
};

struct memory_manager_t memory_manager;
void *heap_start = NULL;
void *heap_end = NULL;


uint64_t calculate_control_size(struct memory_chunk_t* chunk) {
    uint64_t control = 0;
    uint8_t *test = (uint8_t *)chunk;
    for (size_t i = 0; i < sizeof(struct memory_chunk_t) - sizeof(chunk->control_size); i++) {
        control += *(test + i);
    }
    return control;
}


int heap_validate(void){
    if (memory_manager.memory_start == NULL) {
        return 2;
    }
    if (memory_manager.first_memory_chunk == NULL) return 0;


    struct memory_chunk_t *current = memory_manager.first_memory_chunk;
    while (current != NULL) {
        uint64_t test = calculate_control_size(current);
        if (test != current->control_size) {
            return 3;
        }
        if (current->free != 1) {
            unsigned char *left_fence = (unsigned char *)((char *)current + HEADER_SIZE);
            unsigned char *right_fence = (unsigned char *)((char *)current + HEADER_SIZE + FENCE + current->size);

            for (int i = 0; i < FENCE; i++) {
                if (*(left_fence + i) != FENCE_BYTE) return 1;
            }
            for (int i = 0; i < FENCE; i++) {
                if (*(right_fence + i) != FENCE_BYTE) return 1;
            }
        }

        current = current->next;
    }
    return 0;
}

int heap_setup(void){
    if (heap_start != NULL) return -1;

    heap_start = sbrk(0);

    if (heap_start == (void *)-1) return -1;

    memory_manager.memory_start = heap_start;
    memory_manager.first_memory_chunk = NULL;

    heap_end = heap_start;
    return 0;
}

void heap_clean(void) {
    if (memory_manager.memory_start == NULL) return;

    intptr_t size_to_release = -(intptr_t)((char *)heap_end - (char *)heap_start);
    if (sbrk(size_to_release) == (void *)-1) return;

    heap_start = NULL;
    heap_end = NULL;

    memory_manager.memory_start = NULL;
    memory_manager.first_memory_chunk = NULL;
}

void* heap_malloc(size_t size){
    if (size < 1) return NULL;
    if (heap_validate()) return NULL;
    if (memory_manager.first_memory_chunk == NULL) {

        void *test_size = sbrk((intptr_t)size + HEADER_SIZE + (2 * FENCE));
        if (test_size == (void *)-1) return NULL;
        heap_end = (uint8_t *)test_size + size + HEADER_SIZE + (2 * FENCE);

        memory_manager.first_memory_chunk = (struct memory_chunk_t *)memory_manager.memory_start;

        unsigned char *left_fence = (unsigned char *)((char *)memory_manager.first_memory_chunk + HEADER_SIZE);
        unsigned char *right_fence = (unsigned char *)((char *)memory_manager.first_memory_chunk + HEADER_SIZE + FENCE + size);

        for (int i = 0; i < FENCE; i++) {
            *(left_fence + i) = FENCE_BYTE;
        }
        for (int i = 0; i < FENCE; i++) {
            *(right_fence + i) = FENCE_BYTE;
        }

        memory_manager.first_memory_chunk->size = size;
        memory_manager.first_memory_chunk->free = 0;

        memory_manager.first_memory_chunk->prev = NULL;
        memory_manager.first_memory_chunk->next = NULL;
        memory_manager.first_memory_chunk->control_size = calculate_control_size(memory_manager.first_memory_chunk);

        return (void *)((char *)memory_manager.first_memory_chunk + HEADER_SIZE + FENCE);
    }

    struct memory_chunk_t *current = memory_manager.first_memory_chunk;
    while (current != NULL) {
        if (current->free == 1) {
            if (current->size >= size + (2 * FENCE)) {
                current->size = size;
                current->free = 0;
                unsigned char *left_fence = (unsigned char *)((char *)current + HEADER_SIZE);
                unsigned char *right_fence = (unsigned char *)((char *)left_fence + FENCE + size);
                for (int i = 0; i < FENCE; i++) {
                    *(left_fence + i) = FENCE_BYTE;
                }
                for (int i = 0; i < FENCE; i++) {
                    *(right_fence + i) = FENCE_BYTE;
                }
                struct memory_chunk_t *control_current = memory_manager.first_memory_chunk;
                while (control_current != NULL) {
                    control_current->control_size = calculate_control_size(control_current);
                    control_current = control_current->next;
                }
                return (void *)((char *)current + HEADER_SIZE + FENCE);
            }
        }
        if (current->next == NULL) {

            void *test_size = sbrk((intptr_t)size + HEADER_SIZE + (2 * FENCE));
            if (test_size == (void *)-1) return NULL;
            heap_end = (uint8_t *)test_size + size + HEADER_SIZE + (2 * FENCE);

            struct memory_chunk_t *new_chunk = (struct memory_chunk_t *)((char *)current + current->size + HEADER_SIZE + (2 * FENCE));

            unsigned char *left_fence = (unsigned char *)((char *)new_chunk + HEADER_SIZE);
            unsigned char *right_fence = (unsigned char *)((char *)left_fence + FENCE + size);

            for (int i = 0; i < FENCE; i++) {
                *(left_fence + i) = FENCE_BYTE;
            }
            for (int i = 0; i < FENCE; i++) {
                *(right_fence + i) = FENCE_BYTE;
            }

            new_chunk->size = size;
            new_chunk->free = 0;

            new_chunk->next = NULL;
            new_chunk->prev = current;

            current->next = new_chunk;

            struct memory_chunk_t *control_current = memory_manager.first_memory_chunk;
            while (control_current != NULL) {
                control_current->control_size = calculate_control_size(control_current);
                control_current = control_current->next;
            }

            return (void *)((char *)new_chunk + HEADER_SIZE + FENCE);

        }

        current = current->next;
    }
    return NULL;
}

void* heap_calloc(size_t number, size_t size){
    if (size < 1 || number < 1) return NULL;
    if (heap_validate()) return NULL;

    if (memory_manager.first_memory_chunk == NULL) {

        void *test_size = sbrk((intptr_t)size * number + HEADER_SIZE + (2 * FENCE));
        if (test_size == (void *)-1) return NULL;
        heap_end = (uint8_t *)test_size + (size * number) + HEADER_SIZE + (2 * FENCE);

        memory_manager.first_memory_chunk = (struct memory_chunk_t *)memory_manager.memory_start;

        unsigned char *left_fence = (unsigned char *)((char *)memory_manager.first_memory_chunk + HEADER_SIZE);
        unsigned char *right_fence = (unsigned char *)((char *)memory_manager.first_memory_chunk + HEADER_SIZE + FENCE + (size * number));
        unsigned char *init = (unsigned char *)((char *)memory_manager.first_memory_chunk + HEADER_SIZE + FENCE);

        for (size_t i = 0; i < (size * number); i++) {
            *(init + i) = 0;
        }

        for (int i = 0; i < FENCE; i++) {
            *(left_fence + i) = FENCE_BYTE;
        }
        for (int i = 0; i < FENCE; i++) {
            *(right_fence + i) = FENCE_BYTE;
        }

        memory_manager.first_memory_chunk->size = (size * number);
        memory_manager.first_memory_chunk->free = 0;

        memory_manager.first_memory_chunk->prev = NULL;
        memory_manager.first_memory_chunk->next = NULL;

        memory_manager.first_memory_chunk->control_size = calculate_control_size(memory_manager.first_memory_chunk);

        return (void *)((char *)memory_manager.first_memory_chunk + HEADER_SIZE + FENCE);
    }

    struct memory_chunk_t *current = memory_manager.first_memory_chunk;
    while (current != NULL) {
        if (current->free == 1) {
            if (current->size >= (size * number) + (2 * FENCE)) {
                current->size = (size * number);
                current->free = 0;
                unsigned char *init = (unsigned char *)((char *)current + HEADER_SIZE + FENCE);
                for (size_t i = 0; i < (size * number); i++) {
                    *(init + i) = 0;
                }
                unsigned char *left_fence = (unsigned char *)((char *)current + HEADER_SIZE);
                unsigned char *right_fence = (unsigned char *)((char *)left_fence + FENCE + (size * number));
                for (int i = 0; i < FENCE; i++) {
                    *(left_fence + i) = FENCE_BYTE;
                }
                for (int i = 0; i < FENCE; i++) {
                    *(right_fence + i) = FENCE_BYTE;
                }
                struct memory_chunk_t *control_current = memory_manager.first_memory_chunk;
                while (control_current != NULL) {
                    control_current->control_size = calculate_control_size(control_current);
                    control_current = control_current->next;
                }
                return (void *)((char *)current + HEADER_SIZE + FENCE);
            }
        }
        if (current->next == NULL) {

            void *test_size = sbrk((intptr_t)size * number + HEADER_SIZE + (2 * FENCE));
            if (test_size == (void *)-1) return NULL;

            heap_end = (uint8_t *)test_size + size * number + HEADER_SIZE + (2 * FENCE);

            struct memory_chunk_t *new_chunk = (struct memory_chunk_t *)((char *)current + current->size + HEADER_SIZE + (2 * FENCE));

            unsigned char *left_fence = (unsigned char *)((char *)new_chunk + HEADER_SIZE);
            unsigned char *right_fence = (unsigned char *)((char *)left_fence + FENCE + (size * number));
            unsigned char *init = (unsigned char *)((char *)left_fence + FENCE);

            for (int i = 0; i < FENCE; i++) {
                *(left_fence + i) = FENCE_BYTE;
            }
            for (int i = 0; i < FENCE; i++) {
                *(right_fence + i) = FENCE_BYTE;
            }
            for (size_t i = 0; i < (size * number); i++) {
                *(init + i) = 0;
            }
            new_chunk->size = (size * number);

            new_chunk->free = 0;

            new_chunk->next = NULL;
            new_chunk->prev = current;

            current->next = new_chunk;

            struct memory_chunk_t *control_current = memory_manager.first_memory_chunk;
            while (control_current != NULL) {
                control_current->control_size = calculate_control_size(control_current);
                control_current = control_current->next;
            }

            return (void *)((char *)new_chunk + HEADER_SIZE + FENCE);

        }

        current = current->next;
    }
    return NULL;
}

void* heap_realloc(void* memblock, size_t count){
    if (heap_validate()) return NULL;
    if (memblock == NULL) return heap_malloc(count);
    if (get_pointer_type(memblock) != pointer_valid) return NULL;
    if (count == 0) {
        heap_free(memblock);
        return NULL;
    }
    struct memory_chunk_t *current = memory_manager.first_memory_chunk;
    while (current != NULL) {
        if ((void *)((char *)current + HEADER_SIZE + FENCE) == memblock) {
            break;
        }
        current = current->next;
    }
    if (current == NULL) return NULL;

    size_t pom_size;
    if (current->next != NULL) {
        pom_size = (size_t)((char *)current->next - (char *)current - (FENCE * 2) - HEADER_SIZE);
    } else {
        pom_size = (size_t)((char *)heap_end - (char *)current - (FENCE * 2) - HEADER_SIZE);

    }
    if (count == pom_size) return (void *)((char *)current + HEADER_SIZE + FENCE);
    else if (count < pom_size) {
        current->size = count;
        unsigned char *left_fence = (unsigned char *)((char *)current + HEADER_SIZE);
        unsigned char *right_fence = (unsigned char *)((char *)left_fence + FENCE + current->size);
        for (int i = 0; i < FENCE; i++) {
            *(left_fence + i) = FENCE_BYTE;
        }
        for (int i = 0; i < FENCE; i++) {
            *(right_fence + i) = FENCE_BYTE;
        }

    } else {
        size_t required_size = count - pom_size;
        uint8_t flag = 0;
        if (current->next != NULL && current->next->free == 1) {
            if (current->next->size - 2 * FENCE > required_size) {
                struct memory_chunk_t *pom = current->next;
                struct memory_chunk_t *new_next = (struct memory_chunk_t *)((char *)pom + required_size);
                new_next->next = pom->next;
                new_next->size = pom->size - required_size;
                new_next->free = 1;
                new_next->prev = current;
                new_next->control_size = 0;
                if (new_next->next != NULL) {
                    new_next->next->prev = new_next;
                }
                current->next = new_next;
                current->size = count;
                flag = 1;
            }
            if (current->next->size + HEADER_SIZE >= required_size) {
                if (current->next->next != NULL) {
                    current->next->prev = current;
                }
                current->next = current->next->next;
                current->size = count;
                flag = 1;
            }
            unsigned char *left_fence = (unsigned char *)((char *)current + HEADER_SIZE);
            unsigned char *right_fence = (unsigned char *)((char *)left_fence + FENCE + current->size);
            for (int i = 0; i < FENCE; i++) {
                *(left_fence + i) = FENCE_BYTE;
            }
            for (int i = 0; i < FENCE; i++) {
                *(right_fence + i) = FENCE_BYTE;
            }
        }
        else if (current->next == NULL) {
            void *test_size = sbrk((intptr_t)required_size);
            if (test_size == (void *)-1) return NULL;

            heap_end = (uint8_t *)test_size + required_size;

            current->size = count;
            unsigned char *left_fence = (unsigned char *)((char *)current + HEADER_SIZE);
            unsigned char *right_fence = (unsigned char *)((char *)left_fence + FENCE + current->size);
            for (int i = 0; i < FENCE; i++) {
                *(left_fence + i) = FENCE_BYTE;
            }
            for (int i = 0; i < FENCE; i++) {
                *(right_fence + i) = FENCE_BYTE;
            }
            flag = 1;
        }
        if (flag == 0) {
            char *new_memblock = heap_malloc(count);
            if (new_memblock == NULL) return NULL;
            char *correct_chunk = (void *)((char *)current + HEADER_SIZE + FENCE);
            memcpy(new_memblock, correct_chunk, current->size);
            heap_free(correct_chunk);
            current = (void *)((char *)new_memblock - HEADER_SIZE - FENCE);
        }
    }
    struct memory_chunk_t *control_current = memory_manager.first_memory_chunk;
    while (control_current != NULL) {
        control_current->control_size = calculate_control_size(control_current);
        control_current = control_current->next;
    }
    return (void *)((char *)current + HEADER_SIZE + FENCE);
}

void heap_free(void* memblock){

    if (memblock == NULL || heap_validate() || get_pointer_type(memblock) != pointer_valid) return;
    struct memory_chunk_t *current = memory_manager.first_memory_chunk;
    while (current != NULL) {
        if ((void *)((char *)current + HEADER_SIZE + FENCE) == memblock) {
            break;
        }
        current = current->next;
    }
    if (current == NULL) return;
    current->free = 1;

    if (current->next != NULL) {
        current->size = (size_t)((char *)current->next - (char *)current - HEADER_SIZE);
    }

    if (current->next != NULL && current->next->free == 1) {
        current->size += current->next->size + HEADER_SIZE;
        current->next = current->next->next;
        if (current->next != NULL) {
            current->next->prev = current;
        }
    }
    if (current->prev != NULL && current->prev->free == 1) {
        current->prev->size += current->size + HEADER_SIZE;
        current->prev->next = current->next;
        if (current->next != NULL) {
            current->next->prev = current->prev;
        }
        current = current->prev;
    }

    if (current->next == NULL && current->free == 1) {
        if (current->prev != NULL) {
            current->prev->next = NULL;
        } else {
            memory_manager.first_memory_chunk = NULL;

        }
    }

    struct memory_chunk_t *check = memory_manager.first_memory_chunk;
    int flag = 1;
    while (check != NULL) {
        if (check->free == 0) {
            flag = 0;
            break;
        }
        check = check->next;
    }

    if (flag) {
        memory_manager.first_memory_chunk = NULL;
    }
    struct memory_chunk_t *control_current = memory_manager.first_memory_chunk;
    while (control_current != NULL) {
        control_current->control_size = calculate_control_size(control_current);
        control_current = control_current->next;
    }
}

size_t heap_get_largest_used_block_size(void){
    if (memory_manager.first_memory_chunk == NULL || memory_manager.memory_start == NULL || heap_validate()) return 0;
    size_t max;

    struct memory_chunk_t *current = memory_manager.first_memory_chunk;
    if (current->free != 1) max = current->size;
    else {
        max = current->next->size;
    }
    while (current->next != NULL) {
        if (max < current->size && current->free != 1) max = current->size;
        current = current->next;
    }
    return max;
}

enum pointer_type_t get_pointer_type(const void* const pointer){
    if (pointer == NULL) return pointer_null;
    if (heap_validate()) return pointer_heap_corrupted;
    if (memory_manager.first_memory_chunk == NULL || pointer < memory_manager.memory_start) return pointer_unallocated;

    struct memory_chunk_t *current = memory_manager.first_memory_chunk;
    while (current != NULL) {

        uint8_t *test = (uint8_t *)current;
        for (size_t i = 0; i < sizeof(struct memory_chunk_t); i++) {
            if (test == pointer && current->free == 1) return pointer_unallocated;
            if (test == pointer) return pointer_control_block;
            test++;
        }
        for (int i = 0; i < FENCE; i++) {
            if (test == pointer && current->free == 1) return pointer_unallocated;
            if (test == pointer) return pointer_inside_fences;
            test++;
        }
        if (test == pointer && current->free == 1) return pointer_unallocated;

        if (test == pointer) return pointer_valid;
        test++;

        for (size_t i = 1; i < current->size; i++) {
            if (test == pointer && current->free == 1) return pointer_unallocated;
            if (test == pointer) return pointer_inside_data_block;
            test++;
        }
        for (int i = 0; i < FENCE; i++) {
            if (test == pointer && current->free == 1) return pointer_unallocated;
            if (test == pointer) return pointer_inside_fences;
            test++;
        }
        current = current->next;
    }
    return pointer_unallocated;
}
