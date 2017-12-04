#ifndef ATTACK_GENERATOR_H
#define ATTACK_GENERATOR_H

#include <setjmp.h>

#define BUFFER_SIZE 1024

typedef int boolean;
enum booleans {FALSE = 0, TRUE};

// our implementation currently only works for direct overflows
enum techniques {DIRECT=100, INDIRECT};

// our implementation currently only takes into account return
// address overflows
enum code_ptrs {RET_ADDR=300, STRUCT_FUNC_PTR_STACK, STRUCT_FUNC_PTR_HEAP, STRUCT_FUNC_PTR_DATA, STRUCT_FUNC_PTR_BSS, FUNC_PTR_STACK_PARAM, LONGJMP_BUF_STACK, LONGJMP_BUF_HEAP, LONGJMP_BUF_DATA, LONGJMP_BUF_BSS, LONGJMP_BUF_STACK_PARAM};

// our implementation currently only takes into account stack
// buffer overflows
enum locations {STACK=400, HEAP, DATA, BSS};

// our implementation currently only uses memcpy
enum functions {MEMCPY = 500};

struct jmp_struct {
  char buf[BUFFER_SIZE];
  jmp_buf env_buffer;
};

struct pointer_struct {
  char buf[BUFFER_SIZE];
  int* mem_ptr; 
};

struct attackme {
  char buffer[256];
  void (*func_ptr)();
};

typedef struct char_payload CHARPAYLOAD;
struct char_payload {
  size_t size;
  void* overflow_ptr;
  void* target_addr;
  void* buffer;
  void* contents;
};

typedef struct attack_form ATTACKFORM;
struct attack_form {
  enum techniques technique;
  enum code_ptrs code_ptr;
  enum locations location;
  enum functions function;
};

#endif
