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


# **************************************************
#	Verification of random probing Composability
# **************************************************

def verification_random_probing_comp(indices, indices_o, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, t, verbosity, copy = False, t_output = None):
    if(t >= nb_shares):
        print("t (= " + str(t) +  ") >= nb_shares (= " + str(nb_shares) + ")")
        exit()
    if((t_output) and (t_output >= nb_shares)):
        print("t_output (= " + str(t_output) +  ") >= nb_shares (= " + str(nb_shares) + ")")
        exit()
    if((len(secret_deps[0]) != 1) and (len(secret_deps[0]) != 2)) :
        print("Not applicable yet, not 1 or 2 inputs\n")
        exit()

    nb_wires = len(exps)
    upd = 0
    batch_size = BATCH_SIZE
    total_time = 0
    total_time3 = 0
    
    #Creating maximum Coefficients function for I1, I2, I1_and_I2, I1_or_I2
    nb_occ = int(np.sum(nb_occs))
    coeff_c_max_I1_or_I2 = np.zeros(nb_occ+1).tolist()
        
    #####################################  Iterating Over all combinations of output shares of size t  #####################################
    if(t_output):
        tp = t_output
    else:
        tp = t
    if(copy):
        out_combs = []
        out_combs1 = combs(indices_o[0], tp)
        out_combs2 = combs(indices_o[1], tp)
        for o1 in out_combs1:
            for o2 in out_combs2:
                out_combs.append(np.concatenate((o1,o2)))
        out_combs = np.asarray(out_combs)
        del out_combs1; del out_combs2
    else:
        out_combs = combs(indices_o, tp)

    for list_out in out_combs:
    
        list_int_prev_flawed = np.asarray([], dtype="int64")
        
        #Creating temporary Coefficients function for I1, I2, I1_and_I2, I1_or_I2 (we take maximum amongst all of them for max coefficient functions)
        coeff_c_I1_or_I2 = np.zeros(nb_occ+1).tolist()

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
                 
                ########## Adding output comb of shares to each tuple
                list_tuples = np.hstack((list_tuples, np.repeat([list_out], len(list_tuples), axis=0)))
    
                #####################################  Eliminating Non-Incompressible Tuples  #####################################
                if(list_int_prev_flawed.size != 0):
                    start = time.time()
                    e =  eliminate_from_smaller(list_int_prev_flawed, sums, nb_wires)
                    end = time.time()
                    if(verbosity == 2):
                        print("Time to eliminate = " + str(end-start)+ " seconds")
                        
                    list_tuples_flawed = list_tuples[e, :]
                    nb_occs_tuple_flawed = nb_occs[list_tuples_flawed]
                    nb_occs_tuple_flawed = nb_occs_tuple_flawed[:, :i]
                    if(verbosity == 2):
                        print( "Eliminated : " + str(len(list_tuples_flawed)) + " tuples")
                        
                    
                    update_coeff_c(coeff_c_I1_or_I2, nb_occs_tuple_flawed.tolist())

                    list_tuples = list_tuples[~e, :]
                    sums = sums[~e]
                    del list_tuples_flawed;  del nb_occs_tuple_flawed;  del e  
        
                    if(len(list_tuples) == 0):
                        del sums;  del list_tuples
                        list_tuples = np.asarray(list(itertools.islice(list_tuples_orig, 0, batch_size)))
                        continue
                #####################################  Done Eliminating Non-Incompressible Tuples  #####################################
                
                nb_occs_tuple = nb_occs[list_tuples]
                nb_occs_tuple = nb_occs_tuple[:, :i]
                
                #####################################  Apply Probing Rules (1, 2 and 3) !!  #####################################
                list_tuples, sums, nb_occs_tuple, secret_deps, l, time4, time3 = apply_all_rules(list_tuples, secret_deps, random_deps, exps, exps_str, nb_occs_tuple, sums, i+1, None, t=t, verbosity = verbosity)
                #####################################  Done Apply Probing Rules (1, 2 and 3) !!  #####################################
                total_time += time4
                total_time3 += time3
                #####################################  Updating Coefficients  #####################################
                if(verbosity == 2):
                    print("Updating c coefficients...")
    
                
                if(len(list_tuples) > 0):
                    #list_int_prev_flawed_tmp = np.append(list_int_prev_flawed_tmp, sums)  
                    
                    update_coeff_c(coeff_c_I1_or_I2, nb_occs_tuple.tolist())
                
                #####################################  Done Updating Coefficients  #####################################
                del nb_occs_tuple
                del sums
                secret_deps = secret_deps[:nb_wires, :]
                list_tuples = np.asarray(list(itertools.islice(list_tuples_orig, 0, batch_size)))
                
            #####################################  Done BATCHING  #####################################
            
            list_int_prev_flawed = np.append(list_int_prev_flawed, list_int_prev_flawed_tmp)  
            if(verbosity >= 1):
                    print("coefficients c (|I1|>t) : " + str(coeff_c_I1_or_I2))
                    
        #####################################  Done Iterating Over Tuples of hamming weight 1 to coeff_max  #####################################
        
        ########## Updating coeff_c_max(s) ##########
        if(verbosity == 2):
            print("coefficients c (|I1|>t) : " + str(coeff_c_I1_or_I2))
                
        for c in range(nb_occ+1):
            coeff_c_max_I1_or_I2[c] = max(coeff_c_max_I1_or_I2[c],coeff_c_I1_or_I2[c])
                
        ########## Done Updating coeff_c_max(s) ##########
                
    #####################################  Done Iterating Over all combinations of output shares of size t  #####################################
    if(verbosity == 2):
        print("Total update Time = " + str(upd))
        print("\n\n")
    print("\n\nRule 4 time = " + str(total_time))
    print("\n\nRule 3 time = " + str(total_time3))
    if(verbosity == 2):
        print("MAX coefficients c (|I1|>t) : " + str(coeff_c_max_I1_or_I2))
    return coeff_c_max_I1_or_I2
