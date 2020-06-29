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


def verification_random_probing_exp_copy_12(indices, indices_o, weights, exps,  exps_str, secret_deps, random_deps, nb_occs, coeff_max, nb_shares, t, verbosity, bit):
    
    out_combs1 = combs(indices_o[bit], t)
    
    out_combs2 = combs(indices_o[1-bit], nb_shares - 1)
    
    nb_inputs = len(secret_deps[0])
    nb_wires = len(exps)
    upd = 0
    batch_size = BATCH_SIZE
    
    #Creating maximum Coefficients function for I1, I2, I1_and_I2, I1_or_I2
    nb_occ = int(np.sum(nb_occs))
    coeff_c_max_I1_or_I2 = np.zeros(nb_occ+1).tolist()
    
    #####################################  Iterating Over Tuples of size t of output b  #####################################
    for list_out1 in out_combs1:
    
        list_int_prev_flawed = np.asarray([], dtype="int64")
        coeff_c_I1_or_I2 = np.zeros(nb_occ+1).tolist()
        
        #####################################  Iterating Over Tuples of hamming weight 1 to coeff_max  #####################################
        for i in range(1, coeff_max+1):
            
            if(verbosity == 2):
                print ("\n\nTransform tuples in list elements..")
            
            list_tuples_orig = itertools.combinations(indices, i)
            #list_tuples = combs(indices, i)
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
                
                list_tuples_c = np.hstack((list_tuples, np.repeat([list_out1], len(list_tuples), axis=0)))
                
                mask_I1_or_I2 = np.asarray([], dtype="int64")
                mask_I1_or_I2_flawed = np.asarray([], dtype="int64")
                itera = 0
                
                
                #####################################  Iterating Over Tuples of size (nb_shares - 1) of output (1-b) #####################################
                for list_out2 in out_combs2:
            
                    if(verbosity == 2):
                        print("********************************************")
                    sums_sub = np.copy(sums)
                    
                    ########## Adding output comb of shares to each tuple
                    list_tuples_sub = np.hstack((np.copy(list_tuples_c), np.repeat([list_out2], len(list_tuples), axis=0)))
                    
                    ####################################  Eliminating Non-Incompressible Tuples  #####################################
                    if(list_int_prev_flawed.size != 0):
                        start = time.time()
                        e =  eliminate_from_smaller(list_int_prev_flawed, sums_sub, nb_wires - len(indices_o[0]) - len(indices_o[1]))
                        end = time.time()
                        if(verbosity == 2):
                            print("Time to eliminate = " + str(end-start)+ " seconds")
                            
                        s = sums_sub[e]
                        
                        if(itera == 0):
                            mask_I1_or_I2_flawed = s
                        else:
                            mask_I1_or_I2_flawed = np.intersect1d(mask_I1_or_I2_flawed, s)
                            
                        list_tuples_sub = list_tuples_sub[~e, :]
                        sums_sub = sums_sub[~e]
                        del e
                        
                        if(len(list_tuples_sub) == 0):
                            mask_I1_or_I2 = np.asarray([], dtype="int64")
                            del sums_sub
                            del list_tuples_sub
                            itera += 1
                            #list_tuples = np.asarray(list(itertools.islice(list_tuples_orig, 0, batch_size)))
                            continue
                    #####################################  Done Eliminating Non-Incompressible Tuples  #####################################
                    
                    #####################################  Apply Probing Rules (1, 2 and 3) !!  #####################################
                    list_tuples_sub, sums_sub, nb_occs_tuple, secret_deps, l, time4, time3 = apply_all_rules(list_tuples_sub, secret_deps, random_deps, exps, exps_str, None, sums_sub, i+1, None, t=t, verbosity=verbosity)
                
                    ########### Eliminating from previous flawed tuples, the ones that are not flawed for the considered output (computing intersection of flaws for all outputs)
                    if(itera == 0):
                        mask_I1_or_I2 = sums_sub
                    else:
                        mask_I1_or_I2 = np.intersect1d(mask_I1_or_I2, sums_sub)
                    
                    del list_tuples_sub;  del sums_sub
                    ########### To delete added wires from the application of rule 3
                    secret_deps = secret_deps[:nb_wires, :]
        
                    itera += 1
                #####################################  Done Iterating Over Tuples of size (nb_shares - 1) of output (1-b)  #####################################
                
                #list_int_prev_flawed = np.append(list_int_prev_flawed, mask_I1_or_I2)
                list_int_prev_flawed_tmp = np.append(list_int_prev_flawed_tmp, mask_I1_or_I2)
                
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
                    
                #####################################  Done Updating Coefficients  #####################################
                list_tuples = np.asarray(list(itertools.islice(list_tuples_orig, 0, batch_size)))
            
            #####################################  Done BATCHING  #####################################
            
            list_int_prev_flawed = np.append(list_int_prev_flawed, list_int_prev_flawed_tmp)
        
        #####################################  Done Iterating Over Tuples of hamming weight 1 to coeff_max  #####################################
        
        ########## Updating coeff_c_max(s) ##########
        if(verbosity == 2):
            print("coefficients c (|I1|>t) : " + str(coeff_c_I1_or_I2))
            
        for c in range(nb_occ+1):
            coeff_c_max_I1_or_I2[c] = max(coeff_c_max_I1_or_I2[c],coeff_c_I1_or_I2[c])
        ########## Done Updating coeff_c_max(s) ##########
        
    #####################################  Done Iterating Over Tuples of size t of output b  #####################################
    
    if(verbosity == 2):
        print("Total update Time = " + str(upd))
        print("\n\n")
        print("MAX coefficients c (|I1|>t) : " + str(coeff_c_max_I1_or_I2))
        
    return coeff_c_max_I1_or_I2