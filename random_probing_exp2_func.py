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

import numpy as np
import itertools

##############################################################################
#
# Verification of RPE 2 property
#	OUTPUT:
#		- the coefficients of the function f(p) for RPE2
#
##############################################################################

####################### Batching Version #######################
def verification_random_probing_exp_2(indices, indices_o, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, t, verbosity, copy = False):
    if(t >= nb_shares):
        print("t (= " + str(t) +  ") >= nb_shares (= " + str(nb_shares) + ")")
        exit()
    if((len(secret_deps[0]) != 1) and (len(secret_deps[0]) != 2)) :
        print("Not applicable yet, not 1 or 2 inputs\n")
        exit()
    
    nb_inputs = len(secret_deps[0])
    nb_wires = len(exps)
    batch_size = BATCH_SIZE

    nb_occ = int(np.sum(nb_occs))
    coeff_c_I1_or_I2 = np.zeros(nb_occ+1).tolist()
    if(nb_inputs > 1):
        coeff_c_I1 = np.zeros(nb_occ+1).tolist();  coeff_c_I2 = np.zeros(nb_occ+1).tolist();  coeff_c_I1_and_I2 = np.zeros(nb_occ+1).tolist()      
        
    list_int_prev_flawed = np.asarray([], dtype="int64")
    upd = 0
    if(copy):
        out_combs = []
        out_combs1 = combs(indices_o[0], nb_shares - 1)
        out_combs2 = combs(indices_o[1], nb_shares - 1)
        for o1 in out_combs1:
            for o2 in out_combs2:
                out_combs.append(np.concatenate((o1,o2)))
        out_combs = np.asarray(out_combs)
        del out_combs1; del out_combs2
    else:
        out_combs = combs(indices_o, nb_shares - 1)

    #####################################  Iterating Over Tuples of hamming weight 1 to coeff_max  #####################################
    for i in range(1, coeff_max+1):
        if(verbosity == 2):
            print ("\n\nTransform tuples in list elements..")
            
        list_tuples_orig = itertools.combinations(indices, i)
        
        if(verbosity >= 1):
            print ('\n   ***   '+str(i)+"-uples : " + str(binomial(len(indices), i)))
            
        list_int_prev_flawed_tmp = np.asarray([], dtype="int64")
        list_tuples = np.asarray(list(itertools.islice(list_tuples_orig, 0, batch_size)))
        nb_b = (binomial(len(indices), i)//batch_size)+1
        b = 0
        #####################################  BATCHING  #####################################
        while(len(list_tuples) != 0):      
            b += 1
            if(verbosity >= 1):
                print("----------- Batch " + str(b) + "/" + str(nb_b) + " -----------")
                
            ########## Compute binary value for each tuple in list_tuples
            sums = np.bitwise_or.reduce(weights[list_tuples], axis=1)
            sums_args = np.argsort(sums)
            
            mask_I1_or_I2 = np.asarray([], dtype="int64")
            if(nb_inputs > 1):
                mask_I1 = np.asarray([], dtype="int64");   mask_I2 = np.asarray([], dtype="int64")
                
            mask_I1_or_I2_flawed = np.asarray([], dtype="int64")
            if(nb_inputs > 1):
                mask_I1_flawed = np.asarray([], dtype="int64"); mask_I2_flawed = np.asarray([], dtype="int64")
    
            itera = 0
            #####################################  Iterating Over all combinations of output shares of size (nb_shares - 1)  #####################################
            for list_out in out_combs:
            
                if(verbosity == 2):
                    print("********************************************")
                sums_sub = np.copy(sums)
                
                ########## Adding output comb of shares to each tuple
                list_tuples_sub = np.hstack((np.copy(list_tuples), np.repeat([list_out], len(list_tuples), axis=0)))
                
                ####################################  Eliminating Non-Incompressible Tuples  #####################################
                if(list_int_prev_flawed.size != 0):
                    start = time.time()
                    e =  eliminate_from_smaller(list_int_prev_flawed, sums_sub, nb_wires-len(indices_o))
                    end = time.time()
                    if(verbosity == 2):
                        print("Time to eliminate = " + str(end-start)+ " seconds")
                        
                    s = sums_sub[e]
                    
                    if(itera == 0):
                        mask_I1_or_I2_flawed = s
                    else:
                        mask_I1_or_I2_flawed = np.intersect1d(mask_I1_or_I2_flawed, s)
                    
                    if((nb_inputs > 1) and (len(s) > 0)):
                        l = list_tuples_sub[e, :]
                        secret_deps_tuple = np.bitwise_or.reduce(secret_deps[l, :], axis=1, dtype=np.int8)
                        mask_I1_tmp, mask_I2_tmp = classify_rule_1(secret_deps_tuple, t)
                        del secret_deps_tuple; del l
                        s1 = s[mask_I1_tmp]
                        s2 = s[mask_I2_tmp]
                        
                        if(itera == 0):
                            mask_I1_flawed = s1
                            mask_I2_flawed = s2
                        else:
                            mask_I1_flawed = np.intersect1d(mask_I1_flawed, s1)
                            mask_I2_flawed = np.intersect1d(mask_I2_flawed, s2)
    
                        del mask_I1_tmp; del mask_I2_tmp; del s1; del s2
                        
                    list_tuples_sub = list_tuples_sub[~e, :]
                    sums_sub = sums_sub[~e]
                    del e
                    
                    if(len(list_tuples_sub) == 0):
                        mask_I1_or_I2 = np.asarray([], dtype="int64")
                        if(nb_inputs > 1):
                            mask_I1 = np.asarray([], dtype="int64");  mask_I2 = np.asarray([], dtype="int64")
                        del sums_sub
                        del list_tuples_sub
                        itera += 1
                        continue
                #####################################  Done Eliminating Non-Incompressible Tuples  #####################################
                
                #####################################  Apply Probing Rules (1, 2 and 3) !!  #####################################
                list_tuples_sub, sums_sub, nb_occs_tuple, secret_deps, l, time4, time3 = apply_all_rules(list_tuples_sub, secret_deps, random_deps, exps, exps_str, None, sums_sub, i+1, None, t=t, verbosity=verbosity)
                
                ########### Eliminating from previous flawed tuples, the ones that are not flawed for the considered output (computing intersection of flaws for all outputs)
                if(itera == 0):
                    mask_I1_or_I2 = sums_sub
                else:
                    mask_I1_or_I2 = np.intersect1d(mask_I1_or_I2, sums_sub)
                
                if(nb_inputs > 1):
                    if(len(sums_sub) > 0):
                        secret_deps_tuple = np.bitwise_or.reduce(secret_deps[list_tuples_sub, :], axis=1, dtype=np.int8)                
                        mask_I1_tmp, mask_I2_tmp = classify_rule_1(secret_deps_tuple, t)
    
                        s1 = sums_sub[mask_I1_tmp]
                        s2 = sums_sub[mask_I2_tmp]
                        if(itera == 0):
                            mask_I1 = s1
                            mask_I2 = s2
                        else:
                            mask_I1 = np.intersect1d(mask_I1, s1)
                            mask_I2 = np.intersect1d(mask_I2, s2)
                        
                        del mask_I1_tmp; del mask_I2_tmp; del s1; del s2
                    else:
                        mask_I1 = np.asarray([], dtype="int64")
                        mask_I2 = np.asarray([], dtype="int64")
                    
                del list_tuples_sub;  del sums_sub
                ########### To delete added wires from the application of rule 3
                secret_deps = secret_deps[:nb_wires, :]
                itera += 1
            #####################################  Done Iterating Over all combinations of output shares of size (nb_shares - 1)  #####################################
            
            #list_int_prev_flawed_tmp = np.append(list_int_prev_flawed_tmp, mask_I1_or_I2)
            
            #####################################  Updating Coefficients  #####################################
            if(verbosity == 2):
                print("Updating c coefficients...")
    
            if(len(mask_I1_or_I2_flawed) > 0):
                search = sums_args[np.searchsorted(sums, mask_I1_or_I2_flawed, sorter=sums_args)]
                l = list_tuples[search, :]
                start = time.time()
                update_coeff_c(coeff_c_I1_or_I2, nb_occs[l].tolist())
                end = time.time()
                upd += (end - start)
            
            if(len(mask_I1_or_I2) > 0):
                search = sums_args[np.searchsorted(sums, mask_I1_or_I2, sorter=sums_args)]
                l = list_tuples[search, :]
                start = time.time()
                update_coeff_c(coeff_c_I1_or_I2, nb_occs[l].tolist())
                end = time.time()
                upd += (end - start)
                
            if(nb_inputs > 1):
                if(len(mask_I1_flawed) > 0):
                    search = sums_args[np.searchsorted(sums, mask_I1_flawed, sorter=sums_args)]
                    l = list_tuples[search, :]
                    start = time.time()
                    update_coeff_c(coeff_c_I1, nb_occs[l].tolist())
                    end = time.time()
                    upd += (end - start)
                if(len(mask_I1) > 0):
                    search = sums_args[np.searchsorted(sums, mask_I1, sorter=sums_args)]
                    l = list_tuples[search, :]
                    start = time.time()
                    update_coeff_c(coeff_c_I1, nb_occs[l].tolist())
                    end = time.time()
                    upd += (end - start)
                    
                if(len(mask_I2_flawed) > 0):
                    search = sums_args[np.searchsorted(sums, mask_I2_flawed, sorter=sums_args)]
                    l = list_tuples[search, :]
                    start = time.time()
                    update_coeff_c(coeff_c_I2, nb_occs[l].tolist())
                    end = time.time()
                    upd += (end - start)
                if(len(mask_I2) > 0):
                    search = sums_args[np.searchsorted(sums, mask_I2, sorter=sums_args)]
                    l = list_tuples[search, :]
                    start = time.time()
                    update_coeff_c(coeff_c_I2, nb_occs[l].tolist())
                    end = time.time()
                    upd += (end - start)
                flawed12 = np.intersect1d(mask_I1_flawed, mask_I2_flawed)
                if(len(flawed12) > 0):
                    search = sums_args[np.searchsorted(sums, flawed12, sorter=sums_args)]
                    l = list_tuples[search, :]
                    start = time.time()
                    update_coeff_c(coeff_c_I1_and_I2, nb_occs[l].tolist())
                    end = time.time()
                    upd += (end - start)
                flawed12 = np.intersect1d(mask_I1, mask_I2)
                if(len(flawed12) > 0):
                    search = sums_args[np.searchsorted(sums, flawed12, sorter=sums_args)]
                    l = list_tuples[search, :]
                    start = time.time()
                    update_coeff_c(coeff_c_I1_and_I2, nb_occs[l].tolist())
                    end = time.time()
                    upd += (end - start)
            
            #####################################  Done Updating Coefficients  ##################################### 
            list_tuples = np.asarray(list(itertools.islice(list_tuples_orig, 0, batch_size)))
            
        #####################################  Done BATCHING  #####################################
        
        list_int_prev_flawed = np.append(list_int_prev_flawed, list_int_prev_flawed_tmp)
        
        if(verbosity == 2):
            if(nb_inputs > 1):
                print("coefficients c (|I1|>t) : " + str(coeff_c_I1))
                print("coefficients c (|I2|>t) : " + str(coeff_c_I2))
                print("coefficients c (|I1|>t and |I2|>t) : " + str(coeff_c_I1_and_I2))
                print("coefficients c (|I1|>t or |I2|>t) : " + str(coeff_c_I1_or_I2))
            else:
                print("coefficients c (|I1|>t) : " + str(coeff_c_I1_or_I2))
    #####################################  Done Iterating Over Tuples of hamming weight 1 to coeff_max  #####################################
    if(verbosity == 2):
        print("Total update Time = " + str(upd))
    if(nb_inputs > 1):
        if(verbosity == 2):
            print("\n\ncoefficients c (|I1|>t) : " + str(coeff_c_I1))
            print("coefficients c (|I2|>t) : " + str(coeff_c_I2))
            print("coefficients c (|I1|>t and |I2|>t) : " + str(coeff_c_I1_and_I2))
            print("coefficients c (|I1|>t or |I2|>t) : " + str(coeff_c_I1_or_I2))

        return coeff_c_I1, coeff_c_I2, coeff_c_I1_and_I2, coeff_c_I1_or_I2
    else:
        if(verbosity == 2):
            print("coefficients c (|I1|>t) : " + str(coeff_c_I1_or_I2))
        return coeff_c_I1_or_I2