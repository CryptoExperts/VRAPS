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
# Verification of t-Probing P security
#	OUTPUT:
#		- Checks whether the given circuit is t-probing secure
#
##############################################################################

####################### Batching Version #######################
def verification_probing(indices, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, t, verbosity):

    nb_wires = len(exps)

    val_max = (1<<nb_shares) - 1
    
    list_tuples_orig = itertools.combinations(indices, t)
    
    batch_size = BATCH_SIZE
        
    list_tuples = np.asarray(list(itertools.islice(list_tuples_orig, 0, batch_size)))
    nb_b = (binomial(len(indices), t)//batch_size)+1
    b = 0
    #####################################  BATCHING  #####################################
    while(len(list_tuples) != 0):            
        b += 1
        if(verbosity >= 1):
            print("----------- Batch " + str(b) + "/" + str(nb_b) + " -----------")

        nb_occs_tuple = nb_occs[list_tuples]
        sums = np.bitwise_or.reduce(weights[list_tuples], axis=1)
    
        #####################################  Apply Probing Rules (1, 2, 3 and 4)  #####################################
        list_tuples, sums, nb_occs_tuple, secret_deps, l, time4, time3 = apply_all_rules(list_tuples, secret_deps, random_deps, exps, exps_str, nb_occs_tuple, sums, t, val_max, t = None, verbosity=verbosity)
    
        secret_deps = secret_deps[:nb_wires, :]

        if(len(list_tuples) > 0):
            print("Gadget is NOT " + str(t) + "-Probing Secure !\n")
            print("Failure Tuples :")
            for elem in l:
                print(str(exps_str[elem]))
            return
        
        list_tuples = np.asarray(list(itertools.islice(list_tuples_orig, 0, batch_size)))
        
    print("Gadget is " + str(t) + "-Probing Secure !\n")
        
        
####################### No Batching Version #######################
def verification_probing_(indices, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, t, verbosity):

    nb_wires = len(exps)

    val_max = (1<<nb_shares) - 1
    
    list_tuples = combs(indices, t)
    
    nb_occs_tuple = nb_occs[list_tuples]
    sums = np.bitwise_or.reduce(weights[list_tuples], axis=1)
    
    #####################################  Apply Probing Rules (1, 2, 3 and 4)  #####################################
    list_tuples, sums, nb_occs_tuple, secret_deps, l, time4, time3 = apply_all_rules(list_tuples, secret_deps, random_deps, exps, exps_str, nb_occs_tuple, sums, t, val_max, t = None, verbosity=verbosity)

    secret_deps = secret_deps[:nb_wires, :]

    if(len(list_tuples) > 0):
        print("Gadget is NOT " + str(t) + "-Probing Secure !\n")
    else:
        print("Gadget is " + str(t) + "-Probing Secure !\n")