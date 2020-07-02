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
import time
import math
import itertools

##############################################################################
#
# Verification of Random Probing RP property
#	OUTPUT:
#		- the coefficients of the function f(p)
#
##############################################################################

####################### Batching Version #######################
def verification_random_probing(indices, weights, exps, exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, verbosity):

    nb_occ = int(np.sum(nb_occs))
    coeff_c = np.zeros(nb_occ+1).tolist()
    nb_wires = len(exps)

    list_int_prev_flawed = np.asarray([], dtype="int64")
    val_max = (1<<nb_shares) - 1
    
    batch_size = BATCH_SIZE

    #####################################  Iterating Over Tuples of hamming weight 1 to coeff_max  #####################################
    for i in range(1, coeff_max+1):
        if(verbosity > 0):
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
        
            #Compute binary value for each tuple in list_tuples
            sums = np.bitwise_or.reduce(weights[list_tuples], axis=1)
            
            #####################################  Eliminating Non-Incompressible Tuples  #####################################
            if(list_int_prev_flawed.size != 0):
                start = time.time()
                
                e = eliminate_from_smaller(list_int_prev_flawed, sums, nb_wires)
                
                end = time.time()
                if(verbosity == 2):
                    print("Time to eliminate = " + str(end-start)+ " seconds")
    
                list_tuples_flawed = list_tuples[e, :]
                nb_occ_tuple_flawed = nb_occs[list_tuples_flawed].tolist()
                
                if(verbosity == 2):
                    print( "Eliminated : " + str(len(list_tuples_flawed)) + " tuples")
                    
                list_tuples = list_tuples[~e, :]
                sums = sums[~e]
    
                update_coeff_c(coeff_c,nb_occ_tuple_flawed)
                del list_tuples_flawed
                del e
                del nb_occ_tuple_flawed
                
                if(len(list_tuples) == 0):
                    if(verbosity == 2):
                        print("coefficients c :" + str(coeff_c))
                    list_tuples = np.asarray(list(itertools.islice(list_tuples_orig, 0, batch_size)))
                    continue
            #####################################  Done Eliminating Non-Incompressible Tuples  #####################################
    
            nb_occs_tuple = nb_occs[list_tuples]
    
            #####################################  Apply Probing Rules (1, 2, 3 and 4)  #####################################
            list_tuples, sums, nb_occs_tuple, secret_deps, l, time4, time3 = apply_all_rules(list_tuples, secret_deps, random_deps, exps, exps_str, nb_occs_tuple, sums, i, val_max, t = None, verbosity=verbosity)
    
            secret_deps = secret_deps[:nb_wires, :]
            
            if(verbosity > 1):
                print("Updating c coefficients...")
                
#            print("coeff = " + str(i))
#            print(str(exps_str[l]))
                
            #####################################  Updating Coefficients  #####################################
            update_coeff_c(coeff_c, nb_occs_tuple.tolist())
            
            if(verbosity == 2):
                print("coefficients c :" + str(coeff_c))	
    
            list_int_prev_flawed_tmp = np.append(list_int_prev_flawed_tmp, sums)
            del sums
            
            list_tuples = np.asarray(list(itertools.islice(list_tuples_orig, 0, batch_size)))
            
        #####################################  Done BATCHING  #####################################
            
        list_int_prev_flawed = np.append(list_int_prev_flawed, list_int_prev_flawed_tmp) 
        
    #####################################  Done Iterating Over Tuples of hamming weight 1 to coeff_max  #####################################
        
    return coeff_c