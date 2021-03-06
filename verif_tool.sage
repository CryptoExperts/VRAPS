# coding=utf-8
###############################################################################
#
# Implementation of VRAPS (Verifier for Random Probing Security) in SageMath
#
# VRAPS is a formal verification tool for random probing security and random 
# probing expandability (RPE) that was introduced in the following publication:
# 
#    "Random Probing Security: Verification, Composition, Expansion and New 
#    Constructions"
#    By Sonia Belaïd, Jean-Sébastien Coron, Emmanuel Prouff, Matthieu Rivain, 
#    and Abdul Rahman Taleb
#    In the proceedings of CRYPTO 2020.
#
# Copyright (C) 2020 CryptoExperts
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
###############################################################################

import sys
import copy
import bisect
import time
import re
import numpy as np
import itertools
import math
import argparse

BATCH_SIZE = 200000

############################################### Generate a lookup table for binomial coefficients ###############################################
table_coeff=[[0 for x in range(150)] for y in range(150)] 
def table_coeff_bin():
    for n in range(100):
        for k in range(n+1):
            table_coeff[n][k]=binomial(n, k)
			
			
			
############################################### Update Coefficients of function given a failure tuple ###############################################
def compute_tree(current_uple, nb_occ_tuple):
    nb_occ_current = current_uple[0]
    new_coeff_c = np.zeros(nb_occ_tuple+1).tolist()
    if len(current_uple)==1:
        for i in range(1,nb_occ_current+1):
            new_coeff_c[i]=table_coeff[nb_occ_current][i]
    else:
        new_uple = current_uple[1:]
        rem_occ = nb_occ_tuple-nb_occ_current
        new_coeff_c_next = compute_tree(new_uple,rem_occ)
        bound_j=rem_occ+1
        for i in range(1,nb_occ_current+1):
            for j in range(1,bound_j):
                new_coeff_c[i+j]+=new_coeff_c_next[j]*table_coeff[nb_occ_current][i]
    return new_coeff_c
    
def update_coeff_c(coeff_c,list_tuples_flawed):
    for uple in list_tuples_flawed:
        nb_occ_tuple=sum(uple)
        new_coeff_c = compute_tree(uple,nb_occ_tuple)
        for i in range(len(uple)-1,nb_occ_tuple+1):
            coeff_c[i] += new_coeff_c[i]
            

############################################### eliminate non-incompressible tuples tool optimization ###############################################
def eliminate_from_smaller(list_int_prev_flawed, sums, nb_wires):
    e = np.any([list_int_prev_flawed&t==list_int_prev_flawed for t in sums], axis=1)
    return e


############################################### compute pmax value given a function f such that (f(pmax) < pmax) ###############################################
def find_pmax(fs):
    eps = 2**(-13)
    pmax = 1
    val = max([f(p = pmax) for f in fs])
    
    if(val == 0):
        return 0
    
    limit = (2**(-40))
    while( (val >= pmax) and (pmax >= limit) ):
        pmax  = pmax/2
        val = max([f(p = pmax) for f in fs])
    
    if( pmax < limit ):
        if(val >= pmax):
            return 0
        else:
            return pmax
        
    while( val < pmax ):
        pmax += eps
        val = max([f(p = pmax) for f in fs])
        
    return (pmax-eps)


############################################### compute sage functions fmin and fmax from given coefficients array ###############################################
### Lower bound on f(p)
def get_fmin(coeff_c):
    s = ""
    for i in range(0,len(coeff_c)):
        s = s + str(int(coeff_c[i])) + "*p**" + str(i) + " + "
    return eval(s[:-2])
    
    
### Upper bound on f(p)  by replacing all ci > cmax by binom(s)(i)
def get_fmax(coeff_c, coeff_max):
    s = ""
    for i in range(0,len(coeff_c[:coeff_max+1])):
        s = s + str(int(coeff_c[i])) + "*p**" + str(i) + " + "
    for i in range(coeff_max+1, len(coeff_c)):
        s = s + str(binomial(len(coeff_c)-1, i)) + "*p**" + str(i) + " + "
        coeff_c[i] = binomial(len(coeff_c)-1, i)
    return eval(s[:-2])
    

############################################################################################################
#### 		MAIN
############################################################################################################
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("File", help="Name of gadget's input file")
    parser.add_argument("Property", help="Property among P, RP, RPE, RPC to verify", choices=["P", "RP", "RPE", "RPC"])
    parser.add_argument("-c", "--coeff_max", help="Number of Coefficients (default: -1 to compute all coefficients)", type=int)
    parser.add_argument("-v", "--verbose", help="Verbosity During Execution", type=int, default=0, choices = [0,1,2])
    parser.add_argument("-t", help="Number of input/output shares required for properties P, RPE and RPC", type=int)
    parser.add_argument("-t_output", help="Number of output shares required for properties RPE and RPC", type=int)
    
    args = parser.parse_args()
    if((args.Property in ["RPE", "RPC", "P"]) and not(args.t)):
        parser.error("Value of t is required when property is " + str(args.Property))
        
    if((args.Property in ["RPE", "RPC", "RP"]) and not(args.coeff_max)):
        parser.error("Value of c is required when property is " + str(args.Property))
        
    verbosity = args.verbose
    
    folder = "./verif_files/"
    load(folder+"verification_rules.py")
    load(folder+"read_gadget.py")
    
    ####	Analysis of input file
    print ("Reading file...")
    (order,nb_shares,list_int_var,list_out_var, complexity) = compute_input_file(args.File, verbosity)
    write_exps_file(list_int_var, list_out_var)
    
    #print(str(list_int_var))
    
    #Creating Numpy Arrays for intermediate variables only
    (indices, exps, secret_deps, random_deps, nb_occs, weights, exps_str) = return_numpy_arrays(list_int_var)

    coeff_max = args.coeff_max
    if coeff_max == -1:
        coeff_max = len(list_int_var)
        args.coeff_max = sum([v[4] for v in list_int_var])
        
    if coeff_max > len(list_int_var):
        coeff_max = len(list_int_var)
        args.coeff_max = sum([v[4] for v in list_int_var])
        
    if((args.t) and (args.t >= nb_shares)):
        print("Error : t (=" + str(args.t) + ") >= nb_shares (=" + str(nb_shares) + ")")
        exit()

    print("Gadget with " + str(len(secret_deps[0])) + " input(s),  " + str(len(list_out_var)) + " output(s),  " + str(nb_shares) + " share(s)")
    print ("Total number of intermediate variables : "+str(len(list_int_var)))
    print ("Total number of output variables : " + str(sum(1 for l in list_out_var)))
    print ("Total number of Wires : " + str(sum([v[4] for v in list_int_var])) + "\n")
    time.sleep(1.5)
	
    table_coeff_bin()
        
    ##########################  Case of Copy Gadget (if property is RPE and is a copy gadget, special verification is needed)
    if((args.Property not in ["RP", "RPC", "P"]) and (len(list_out_var) == 2) and (len(secret_deps[0]) == 1)):
        print("Execution of RPE for a Copy Gadget...\n")
        args.Property = "RPEC"
        
        
    #####################################  Case of Probing P #####################################
    if(args.Property == 'P'):
		load(folder+"probing_func.py")
		verification_probing(indices, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, args.t, verbosity)

    #####################################  End of Case of Probing P #####################################
		
    #####################################  Case of Random Probing RP #####################################
    elif(args.Property == 'RP'):      
        load(folder+"random_probing_func.py")
        
        if(verbosity == 0):
            print("Verifying Random Probing Security ...\n")
        
        if(verbosity > 0):
            print ("----     Verification of Random Probing Security     ----")
        start = time.time()
        coeff_c = verification_random_probing(indices, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, verbosity)
        end = time.time()
        if(verbosity > 0):
            print("\n----     End of Verification of Random Probing Security     ----\n")
        
        #Lower bound on f(p)
        var("p")
        fmin = get_fmin(coeff_c)
        print("\nCoefficients fmin(p) = " + str(coeff_c) + "\n")
        
        #Upper bound on f(p)
        fmax = get_fmax(coeff_c, args.coeff_max)
        print("Coefficients fmax(p) = " + str(coeff_c) + "\n")
        
        #Printing outputs
        print("Verification Time = " + str(end-start) + " seconds\n")
        
        print("Complexity (Nadd, Ncopy, Nmult, Nrand) = " + str(complexity) + "\n")

        print("")
    #####################################  End of Case of Random Probing RP #####################################
    
    
    #####################################  Case of Random Probing COMP #####################################
    elif(args.Property == 'RPC'):
        (indices_o, exps_o, secret_deps_o, random_deps_o, nb_occs_o, weights_o, exps_str_o) = return_numpy_arrays(list_out_var[0])
        indices_o = indices_o + len(exps) 
        weights = np.append(weights, weights_o)
        exps = np.append(exps, exps_o)
        exps_str = np.append(exps_str, exps_str_o)
        secret_deps = np.append(secret_deps, secret_deps_o, 0)
        random_deps = np.append(random_deps, random_deps_o, 0)
        nb_occs = np.append(nb_occs, nb_occs_o)
        del weights_o;   del exps_o;   del exps_str_o;   del secret_deps_o;   del random_deps_o;   del nb_occs_o
        
        total_time = 0
        load(folder+"random_probing_comp_func.py") 
        
        if(verbosity == 0):
            print("Verifying Random Probing Composability ( t = " + str(args.t) + " ) ...\n")
        
        if(verbosity > 0):
            print("----     Verification of Random Probing Composability ( t = "+str(args.t)+" )    ----")
        start = time.time()
        out = verification_random_probing_comp(indices, indices_o, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, args.t, verbosity, t_output = args.t_output)
        end = time.time()
        if(verbosity > 0):
            print("\n----     End of Verification of Random Probing Composability     ----\n\n")
        total_time += (end-start)

        var("p")
        
        coeffs = out
        fmin = get_fmin(coeffs)
        print("\nCoefficients Prop_COMP fmin(p) = " + str(coeffs) + "\n")  
        fmax = get_fmax(coeffs, args.coeff_max)
        print("Coefficients Prop_COMP fmax(p) = " + str(coeffs)) 
        
        print("\nTotal Verification Time = " + str(total_time) + " seconds\n")
            
        print("Complexity (Nadd, Ncopy, Nmult, Nrand) = " + str(complexity) + "\n")
        
        #Amplification Order
        d = next((i for i, x in enumerate(coeffs) if x), 0)
        print("Amplification Order d = " + str(d) + "\n")
        print("Coeff c" + str(d)+" = " + str(coeffs[d]) + "\n")
        
        pmin = find_pmax([fmax])
        print("Log2 of Lower Bound on p : pmin = " + str(N(log(pmin, 2))) + " , Log2 fmax(pmin) = " + str(N(log(fmax(p = pmin), 2))))
        
        pmax = find_pmax([fmin])
        print("Log2 of Upper Bound on p : pmax = " + str(N(log(pmax, 2))) + " , Log2 fmin(pmax) = " + str(N(log(fmin(p = pmax), 2))))
        print("")
    
    
    #####################################  End of Case of Random Probing COMP #####################################
    
    
    #####################################  Case of Random Probing EXP (EXP1 & EXP2) #####################################
    elif(args.Property == 'RPE'):        
    
        if(len(list_out_var) != 1):
            print("Not applicable yet, not 1 output.\n")
            exit()
            
        (indices_o, exps_o, secret_deps_o, random_deps_o, nb_occs_o, weights_o, exps_str_o) = return_numpy_arrays(list_out_var[0])
        indices_o = indices_o + len(exps) 
        weights = np.append(weights, weights_o)
        exps = np.append(exps, exps_o)
        exps_str = np.append(exps_str, exps_str_o)
        secret_deps = np.append(secret_deps, secret_deps_o, 0)
        random_deps = np.append(random_deps, random_deps_o, 0)
        nb_occs = np.append(nb_occs, nb_occs_o)
        del weights_o;   del exps_o;   del exps_str_o;   del secret_deps_o;   del random_deps_o;   del nb_occs_o
        
        ##########################  Executing Verification Methods
        total_time = 0
        load(folder+"random_probing_exp1_func.py") 
        if(verbosity == 0):
            print("Verifying Random Probing Expandability ( t = " + str(args.t) + " ) ...\n")
        
        if(verbosity > 0):
            print("----     Verification of Random Probing Expandability Property 1 ( t = "+str(args.t)+" )    ----")
        start = time.time()
        out1 = verification_random_probing_exp_1(indices, indices_o, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, args.t, verbosity, t_output = args.t_output)
        end = time.time()
        if(verbosity > 0):
            print("\n----     End of Verification of Random Probing Expandability Property 1     ----\n\n")
        total_time += (end-start)

        load(folder+"random_probing_exp2_func.py") 
        if(verbosity > 0):
            print("----     Verification of Random Probing Expandability Property 2 ( t = "+str(args.t)+" )    ----")
        start = time.time()
        out2 = verification_random_probing_exp_2(indices, indices_o, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, args.t, verbosity)
        end = time.time()
        if(verbosity > 0):
            print("\n----     End of Verification of Random Probing Expandability Property 2     ----\n\n")
        total_time += (end-start)

        var("p")
        
        #####################################  Case of Gadgets with 1 input, 1 output #####################################
        if(len(secret_deps[0]) == 1):
        
            coeffs1 = out1
            coeffs2 = out2  
            coeffs = [max(coeffs1[i], coeffs2[i]) for i in range(len(coeffs1))]
            if(verbosity > 0):
                print("\nCoefficients Prop_EXP1 fmin_I1(p) = " + str(coeffs1))  
                print("Coefficients Prop_EXP2 fmin_I1(p) = " + str(coeffs2)) 
                
            print("Coefficients Prop_EXP fmin_I1(p) = " + str(coeffs)) 
            print("") 
               
            get_fmax(coeffs1, args.coeff_max)
            get_fmax(coeffs2, args.coeff_max)
            fmin = get_fmin(coeffs)
            fmax = get_fmax(coeffs, args.coeff_max)
                
            if(verbosity > 0):    
                print("Coefficients Prop_EXP1 fmax_I1(p) = " + str(coeffs1)) 
                print("Coefficients Prop_EXP2 fmax_I1(p) = " + str(coeffs2)) 
                
            print("Coefficients Prop_EXP fmax_I1(p) = " + str(coeffs)) 


            print("\nTotal Verification Time = " + str(total_time) + " seconds\n")
            
            print("Complexity (Nadd, Ncopy, Nmult, Nrand) = " + str(complexity) + "\n")
            
            #Amplification Order
            d = next((i for i, x in enumerate(coeffs) if x), 0)
            print("Amplification Order d = " + str(d) + "\n")
            
            pmin = find_pmax([fmax])
            print("Log2 of Lower Bound on p : pmin = " + str(N(log(pmin, 2))) + " , Log2 fmax(pmin) = " + str(N(log(fmax(p = pmin), 2))))
            
            pmax = find_pmax([fmin])
            print("Log2 of Upper Bound on p : pmax = " + str(N(log(pmax, 2))) + " , Log2 fmin(pmax) = " + str(N(log(fmin(p = pmax), 2))))
            print("")
        #####################################  End of Case of Gadgets with 1 input, 1 output ##################################### 
            
        #####################################  Case of Gadgets with 2 inputs, 1 output #####################################
        else:
            liste_fmin = []
            liste_fmax = []
            
            coeffs1_I1, coeffs1_I2, coeffs1_I1_and_I2, coeffs1_I1_or_I2 = out1
            coeffs2_I1, coeffs2_I2, coeffs2_I1_and_I2, coeffs2_I1_or_I2 = out2
            
            coeffs_I1 = [max(coeffs1_I1[i], coeffs2_I1[i]) for i in range(len(coeffs1_I1))]
            coeffs_I2 = [max(coeffs1_I2[i], coeffs2_I2[i]) for i in range(len(coeffs1_I2))]
            coeffs_I1_and_I2 = [max(coeffs1_I1_and_I2[i], coeffs2_I1_and_I2[i]) for i in range(len(coeffs1_I1_and_I2))]
            
            d1 = next((i for i, x in enumerate(coeffs_I1) if x), 0)
            d2 = next((i for i, x in enumerate(coeffs_I2) if x), 0)
            d12 = next((i for i, x in enumerate(coeffs_I1_and_I2) if x), 0)
            if(d1 < d2):
                d = d1
                cd = coeffs_I1[d]
            elif(d1 > d2):
                d = d2
                cd = coeffs_I2[d]
            else:
                d = d1
                cd = max(coeffs_I1[d], coeffs_I2[d])
                
            if(d > d12/2):
                d = d12/2
                cd = sqrt(coeffs_I1_and_I2[d12])
                
            elif(d == (d12/2)):
                cd = max(cd, sqrt(coeffs_I1_and_I2[d12]))
                
            if(verbosity > 0):
                #EXP1
                print("Coefficients Prop_EXP1 fmin_I1(p) = " + str(coeffs1_I1))
                print("Coefficients Prop_EXP1 fmin_I2(p) = " + str(coeffs1_I2))
                print("Coefficients Prop_EXP1 fmin_I1_and_I2(p) = " + str(coeffs1_I1_and_I2))
                print("")
                    
            liste_fmin.append(get_fmin(coeffs1_I1))
            liste_fmax.append(get_fmax(coeffs1_I1, args.coeff_max))
            liste_fmin.append(get_fmin(coeffs1_I2))
            liste_fmax.append(get_fmax(coeffs1_I2, args.coeff_max))
            liste_fmin.append(sqrt(get_fmin(coeffs1_I1_and_I2)))
            liste_fmax.append(sqrt(get_fmax(coeffs1_I1_and_I2, args.coeff_max)))
            
            if(verbosity > 0):
                
                print("Coefficients Prop_EXP1 fmax_I1(p) = " + str(coeffs1_I1))
                print("Coefficients Prop_EXP1 fmax_I2(p) = " + str(coeffs1_I2))
                print("Coefficients Prop_EXP1 fmax_I1_and_I2(p) = " + str(coeffs1_I1_and_I2) + "\n")  
                
                #EXP2
                print("Coefficients Prop_EXP2 fmin_I1(p) = " + str(coeffs2_I1))
                print("Coefficients Prop_EXP2 fmin_I2(p) = " + str(coeffs2_I2))
                print("Coefficients Prop_EXP2 fmin_I1_and_I2(p) = " + str(coeffs2_I1_and_I2))
                print("")
                    
            liste_fmin.append(get_fmin(coeffs2_I1))
            liste_fmax.append(get_fmax(coeffs2_I1, args.coeff_max))
            liste_fmin.append(get_fmin(coeffs2_I2))
            liste_fmax.append(get_fmax(coeffs2_I2, args.coeff_max))
            liste_fmin.append(sqrt(get_fmin(coeffs2_I1_and_I2)))
            liste_fmax.append(sqrt(get_fmax(coeffs2_I1_and_I2, args.coeff_max)))
            
            if(verbosity > 0):
                
                print("Coefficients Prop_EXP2 fmax_I1(p) = " + str(coeffs2_I1))
                print("Coefficients Prop_EXP2 fmax_I2(p) = " + str(coeffs2_I2))
                print("Coefficients Prop_EXP2 fmax_I1_and_I2(p) = " + str(coeffs2_I1_and_I2) + "\n") 
                
            #EXP BOTH
            print("Coefficients Prop_EXP fmin_I1(p) = " + str(coeffs_I1))
            print("Coefficients Prop_EXP fmin_I2(p) = " + str(coeffs_I2))
            print("Coefficients Prop_EXP fmin_I1_and_I2(p) = " + str(coeffs_I1_and_I2))
            print("")
            
            get_fmax(coeffs_I1, args.coeff_max)
            get_fmax(coeffs_I2, args.coeff_max)
            get_fmax(coeffs_I1_and_I2, args.coeff_max)
            
            print("Coefficients Prop_EXP fmax_I1(p) = " + str(coeffs_I1))
            print("Coefficients Prop_EXP fmax_I2(p) = " + str(coeffs_I2))
            print("Coefficients Prop_EXP fmax_I1_and_I2(p) = " + str(coeffs_I1_and_I2))
                
            print("\nTotal Verification Time = " + str(total_time) + " seconds\n")
            
            print("Complexity (Nadd, Ncopy, Nmult, Nrand) = " + str(complexity) + "\n")
            
            #Amplification Order
            print("Amplification Order d = " + str(d))
            print("Coeff c" + str(d)+" = " + str(cd) + "\n")
            
            pmin = find_pmax(liste_fmax)
            print("Log2 of Lower Bound on p : pmin = " + str(N(log(pmin, 2))) + " , Log2 fmax(pmin) = " + str(N(log(max([f(p = pmin) for f in liste_fmax]), 2))))
            
            #print(str(liste_fmin))
            pmax = find_pmax(liste_fmin)
            print("Log2 of Upper Bound on p : pmax = " + str(N(log(pmax, 2))) + " , Log2 fmin(pmax) = " + str(N(log(max([f(p = pmax) for f in liste_fmin]), 2))))
            print("")
        #####################################  End of Case of Gadgets with 2 inputs, 1 output #####################################
        
    #####################################  Case of Random Probing EXP (EXP1 & EXP2) #####################################
    
    #####################################  Case of RPE for Copy Gadgets with 1 input, 2 outputs #####################################
    else:
        (indices_o1, exps_o, secret_deps_o, random_deps_o, nb_occs_o, weights_o, exps_str_o) = return_numpy_arrays(list_out_var[0])
        indices_o1 = indices_o1 + len(exps) 
        weights = np.append(weights, weights_o)
        exps = np.append(exps, exps_o)
        exps_str = np.append(exps_str, exps_str_o)
        secret_deps = np.append(secret_deps, secret_deps_o, 0)
        random_deps = np.append(random_deps, random_deps_o, 0)
        nb_occs = np.append(nb_occs, nb_occs_o)
        del weights_o;   del exps_o;   del exps_str_o;   del secret_deps_o;   del random_deps_o;   del nb_occs_o
        
        (indices_o2, exps_o, secret_deps_o, random_deps_o, nb_occs_o, weights_o, exps_str_o) = return_numpy_arrays(list_out_var[1])
        indices_o2 = indices_o2 + len(exps) 
        weights = np.append(weights, weights_o)
        exps = np.append(exps, exps_o)
        exps_str = np.append(exps_str, exps_str_o)
        secret_deps = np.append(secret_deps, secret_deps_o, 0)
        random_deps = np.append(random_deps, random_deps_o, 0)
        nb_occs = np.append(nb_occs, nb_occs_o)
        del weights_o;   del exps_o;   del exps_str_o;   del secret_deps_o;   del random_deps_o;   del nb_occs_o
        
        indices_o = np.asarray([indices_o1, indices_o2])
        
        #print(str(indices_o))
        
        #exit()
        
        ##########################  Executing Verification Method
        total_time = 0
        
        load(folder+"random_probing_exp1_func.py") 
        load(folder+"random_probing_exp2_func.py") 
        load(folder+"random_probing_exp_copy_func.py") 
        if(verbosity > 0):
            print("----     Verification of Random Probing Expandability Copy    ----\n")
        start = time.time()
        
        if(verbosity == 0):
            print("Verifying Random Probing Expandability ( t = " + str(args.t) + " ) ...\n")
        
        if(verbosity > 0):
            print("\n----     Verification of EXP Copy 1    ----\n")
        c1 = verification_random_probing_exp_1(indices, indices_o, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, args.t, verbosity, copy = True)
        
        if(verbosity > 0):
            print("\n----     Verification of EXP Copy 2    ----\n")
        c2 = verification_random_probing_exp_2(indices, indices_o, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, args.t, verbosity, copy = True)
        
        if(verbosity > 0):
            print("\n----     Verification of EXP Copy 12   ----\n")
        c12 = verification_random_probing_exp_copy_12(indices, indices_o, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, args.t, verbosity, 0)
        
        if(verbosity > 0):
            print("\n----     Verification of EXP Copy 21    ----\n")
        c21 = verification_random_probing_exp_copy_12(indices, indices_o, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, args.t, verbosity, 1)
        end = time.time()
        
        if(verbosity > 0):
            print("\n----     End of Verification of Random Probing Expandability Copy     ----\n\n")
        total_time += (end-start)
        
        var("p")
        c = [max(c1[i], max(c2[i], max(c12[i], c21[i]))) for i in range(len(c1))]
        liste_fmin = []
        liste_fmax = []
        
        if(verbosity > 0):
            print("Coeffs f1_min(p) =  " + str(c1))
            print("Coeffs f2_min(p) =  " + str(c2))
            print("Coeffs f12_min(p) =  " + str(c12))
            print("Coeffs f21_min(p) =  " + str(c21)+"\n")
            
        liste_fmin.append(get_fmin(c1))
        liste_fmin.append(get_fmin(c2))
        liste_fmin.append(get_fmin(c12))
        liste_fmin.append(get_fmin(c21))
        
        liste_fmax.append(get_fmax(c1, args.coeff_max))
        liste_fmax.append(get_fmax(c2, args.coeff_max))
        liste_fmax.append(get_fmax(c12, args.coeff_max))
        liste_fmax.append(get_fmax(c21, args.coeff_max))
            
        if(verbosity > 0):
            print("Coeffs f1_max(p) =  " + str(c1))
            print("Coeffs f2_max(p) =  " + str(c2))
            print("Coeffs f12_max(p) =  " + str(c12))
            print("Coeffs f21_max(p) =  " + str(c21) + "\n")
            
            
        d = next((i for i, x in enumerate(c) if x), 0)
            
        fmin = get_fmin(c)
        print("coeffs f_min(p) : " + str(c))
        
        fmax = get_fmax(c, args.coeff_max)
        print("\ncoeffs f_max(p) : " + str(c))
        
        print("\nTotal Verification Time = " + str(total_time) + " seconds\n")
            
        print("Complexity (Nadd, Ncopy, Nmult, Nrand) = " + str(complexity) + "\n")
        
        #Amplification Order
        print("Amplification Order d = " + str(d) + "\n")
        
        pmin = find_pmax(liste_fmax)
        print("Log2 of Lower Bound on p : pmin = " + str(N(log(pmin, 2))) + " , Log2 fmax(pmin) = " + str(N(log(max([f(p = pmin) for f in liste_fmax]), 2))))
        
        #print(str(liste_fmin))
        pmax = find_pmax(liste_fmin)
        print("Log2 of Upper Bound on p : pmax = " + str(N(log(pmax, 2))) + " , Log2 fmin(pmax) = " + str(N(log(max([f(p = pmax) for f in liste_fmin]), 2))))
        print("")


if __name__ == "__main__":
    main()