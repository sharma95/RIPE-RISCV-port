#!/usr/bin/python2
# Developed by Nick Nikiforakis to assist the automated testing
# using the RIPE evaluation tool
#
# Released under the MIT license (see file named LICENSE)
#
# This program is part the paper titled
# RIPE: Runtime Intrusion Prevention Evaluator 
# Authored by: John Wilander, Nick Nikiforakis, Yves Younan,
#              Mariam Kamkar and Wouter Joosen
# Published in the proceedings of ACSAC 2011, Orlando, Florida
#
# Please cite accordingly.

import os
import sys
import argparse

parser = argparse.ArgumentParser(description=
                                 'Run RIPE experiments on spike or gem5.',
                                 formatter_class=
                                 argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('--sim', action='store', default='spike',
                    help='Name of simulator (gem5 or spike)')
parser.add_argument('--attack', action='store', default='direct',
                    help='Direct or indirect attack or both')
parser.add_argument('-n', '--num-iterations', action='store', default='1',
                    help='Number of times to repeat attack')

args = parser.parse_args()

spike_path = "spike"
pk_path = "pk"
gem5_path = os.environ['GEM5_ROOT'] + '/build/RISCV/gem5.opt '
gem5_cfg = os.environ['GEM5_ROOT'] + '/configs/example/se.py'
gem5_opts = ' --cpu-type=TimingSimpleCPU --mem-size=1GB '


code_ptr = ["ret", "funcptrstackparam", "longjmpstackvar", \
            "longjmpstackparam", "longjmpheap", "longjmpbss", "longjmpdata", \
            "structfuncptrstack", "structfuncptrheap", "structfuncptrdata", \
            "structfuncptrbss"]

funcs = ["memcpy"]
#funcs = ["memcpy", "strcpy", "strncpy", "sprintf", "snprintf", "strcat", \
#         "strncat", "sscanf", "fscanf", "homebrew"]


locations = ["stack", "heap", "bss", "data"]
attacks = ["createfile"]#, "returnintolibc", "rop"]

techniques = []
repeat_times = 0


if args.attack == "both":
   techniques = ["direct","indirect"];
else:
   techniques = [args.attack]

repeat_times = int(args.num_iterations)


i = 0
if not os.path.exists("./output/" + args.sim):
    os.system("mkdir -p output/" + args.sim);

total_ok=0;
total_fail=0;
total_some=0;
total_np = 0;


for attack in attacks:
    for tech in techniques:
        for loc in locations:
            for ptr in code_ptr:
                for func in funcs:
                    i = 0
                    s_attempts = 0
                    attack_possible = 1
                    while i < repeat_times:
                        i += 1

                        logName = "output/" + args.sim + "/ripe_log_" + tech + "_" + ptr + "_" + loc + "_" + func
                        os.system("rm " + logName)
                        if args.sim == 'spike':
                           cmdline = spike_path + " " + pk_path +  " ./build/attack_generator -t "+tech+" -c " + ptr + "  -l " + loc +" -f " + func + ">> " + logName + " 2>&1"
                        else:
                           cmdline = gem5_path + gem5_cfg + gem5_opts + " -c build/attack_generator -o '-t " + tech + " -c " + ptr + " -l " + loc + " -f " + func + "' >> " + logName + " 2>&1"
                        #cmdline = "./build/ripe_attack_generator -t "+tech+" -i "+attack+" -c " + ptr + "  -l " + loc +" -f " + func + " > /tmp/ripe_log 2>&1"
                        os.system(cmdline)
                        log = open(logName,"r")


                        if log.read().find("Impossible") != -1:
                            print cmdline,"\t\t","NOT POSSIBLE"
                            attack_possible = 0;
                            break;  #Not possible once, not possible always :)


                        if os.path.exists("urhacked"):
                            s_attempts += 1
                            os.system("rm -f urhacked")


                    if attack_possible == 0:
                        total_np += 1;
                        continue

                    if s_attempts == repeat_times:
                        print cmdline,"\t\tOK\t", s_attempts,"/",repeat_times
                        total_ok += 1;
                    elif s_attempts == 0:
                        print cmdline,"\t\tFAIL\t",s_attempts,"/",repeat_times
                        total_fail += 1;
                    else:
                        print cmdline,"\t\tSOMETIMES\t", s_attempts,"/",repeat_times
                        total_some +=1;

total_attacks = total_ok + total_some + total_fail + total_np;
print "\n||Summary|| OK: ",total_ok," ,SOME: ",total_some," ,FAIL: ",total_fail," ,NP: ",total_np," ,Total Attacks: ",total_attacks


