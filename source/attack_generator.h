#ifndef ATTACK_GENERATOR_H
#define ATTACK_GENERATOR_H

#include <setjmp.h>

#define BUFFER_SIZE 1024

typedef int boolean;
enum booleans {FALSE = 0, TRUE};

enum techniques {DIRECT=100, INDIRECT};

enum code_ptrs {RET_ADDR=300, STRUCT_FUNC_PTR_STACK, STRUCT_FUNC_PTR_HEAP, STRUCT_FUNC_PTR_DATA, STRUCT_FUNC_PTR_BSS, FUNC_PTR_STACK_PARAM, LONGJMP_BUF_STACK, LONGJMP_BUF_HEAP, LONGJMP_BUF_DATA, LONGJMP_BUF_BSS, LONGJMP_BUF_STACK_PARAM};

enum locations {STACK=400, HEAP, DATA, BSS};

enum functions {MEMCPY = 500, STRCPY, STRNCPY, SPRINTF, SNPRINTF, STRCAT, STRNCAT, SSCANF};
/*enum functions     {MEMCPY=500, STRCPY, STRNCPY, SPRINTF, SNPRINTF,
                    STRCAT, STRNCAT, SSCANF, FSCANF, HOMEBREW};
*/

/* 2 overflow techniques */
size_t nr_of_techniques = 2;
char *opt_techniques[] = {"direct", "indirect"};

/* 12 code pointers to overwrite */
size_t nr_of_code_ptrs = 16;
char *opt_code_ptrs[] = {"ret", "baseptr", 
			 "funcptrstackvar", "funcptrstackparam",
			 "funcptrheap", "funcptrbss", "funcptrdata",
			 "longjmpstackvar", "longjmpstackparam",
			 "longjmpheap", "longjmpbss", "longjmpdata",
			 "structfuncptrstack","structfuncptrheap",
                         "structfuncptrdata","structfuncptrbss"
};

/* 4 memory locations */
size_t nr_of_locations = 4;
char *opt_locations[] = {"stack", "heap", "bss", "data"};

/* 10 vulnerable functions */
size_t nr_of_funcs = 10;
char *opt_funcs[] = {"memcpy", "strcpy", "strncpy", "sprintf", "snprintf",
		     "strcat", "strncat", "sscanf", "fscanf", "homebrew"};
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

int main(int argc, char **argv);
void perform_attack(void (*stack_func_ptr_param)(),
                    jmp_buf stack_jmp_buf_param);

char* generate_payload();
boolean is_attack_possible();

void set_technique(char *choice);
void set_code_ptr(char *choice);
void set_location(char *choice);
void set_function(char *choice);

#endif
