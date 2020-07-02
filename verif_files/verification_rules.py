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

import itertools
import numpy as np
import time

def combs(a, r):
    """
    Return successive r-length combinations of elements in the array a.
    Should produce the same output as array(list(combinations(a, r))), but 
    faster.
    """
    a = np.asarray(a)
    dt = np.dtype([('', a.dtype)]*r)
    b = np.fromiter(itertools.combinations(a, r), dt)
    return b.view(a.dtype).reshape(-1, r)

##############################################################################
#
# apply_rule_1
#	OUTPUT:
#		- mask: boolean mask to extract from list_tuples the tuples which
#                 contain all the shares of at least
#				one secret variable
#
##############################################################################

def rule_1_f(liste, val_max):
    return liste == val_max
r1 = np.vectorize(rule_1_f)
    
def apply_rule_1(secret_deps_tuple, val_max):
    mask = np.any(r1(secret_deps_tuple, val_max), axis=1)
    return mask    

#################### Hamming Weight Lookup Table ####################
def count_one(x):
    c = 0
    while x:
        x &= x - 1
        c += 1
    return c

# The value 2048 means that the number of shares does not exceed 
#  11 (log2(2048)). For higher number of shares n, the value should be
# changed to 2^n
HW = np.asarray([count_one(i) for i in range(2048)], dtype=np.int)


##############################################################################
#
# apply_rule_1_exp 
#	OUTPUT:
#		- mask: boolean mask to extract from list_tuples the tuples which
#                 contain t+1 or more shares of at least
#				one secret variable
#
##############################################################################
def rule_1_f_exp(liste, t):
    return (liste > t)
r1exp = np.vectorize(rule_1_f_exp)

def apply_rule_1_exp(secret_deps_tuple, t):
    hammingw = HW[secret_deps_tuple]
    mask = np.any(r1exp(hammingw, t), axis=1)
    del hammingw
    return mask    
    

##############################################################################
#
# classify_rule_1 
#	OUTPUT:
#		- mask_I1, mask_I2: boolean masks to extract from list_tuples
#                    the tuples which contain t+1 or more shares of the first
#                    secret variable (mask_I1) or the second (mask_I2)
#
##############################################################################
def classify_rule_1(secret_deps_tuple, t):
    hammingw = HW[secret_deps_tuple]
    #I1_or_I2
    mask = r1exp(hammingw, t)
    del hammingw
    #I1
    mask_I1 = mask[:, 0]
    #I2
    mask_I2 = mask[:, 1]
    #I1_and_I2
    del mask
    return mask_I1, mask_I2
    

##############################################################################
#
# apply_rule_2
#	OUTPUT:
#		- modifies list_tuples such that for 
#				each tuple which contains only one occurrence of a random 
#				variable, then the corresponding expression is replaced by the 
#				random variable itself
#
##############################################################################

def apply_rule_2(list_tuples,random_deps, verbosity):
    #First, reduce add all random deps from all wires in each tuple
    nb = 0
    for r in range(len(random_deps[0])):
        
        rands = np.add.reduce(random_deps[list_tuples, r], axis=1)
        
        mask = (rands==1)             #This will filter from list_tuples only the ones where we can replace a wire by the random (value == 1)
        liste = list_tuples[mask, :]        #This will select the corresponding tuples in list_tuples
        
        varsi = (random_deps[liste, r] == 1) #This will contain the exact wire index in each tuple to modify its value by the random r
        
        #liste = list_tuples[mask, :]
        liste[varsi] = r
        list_tuples[mask, :] = liste
        
        nb += len(liste)
        del liste
        del varsi
        del rands
        
    if(verbosity == 2):
        print("After rule 2 : " + str(nb) + " modified Tuples")
    
##############################################################################
#
# apply_rule_3
#	OUTPUT:
#		- return a modification of list_tuples such that at most one
#			couple of intermediate variables (a,b) is turned into (a+b,b)
#			(resp. (a,a+b)) if a+b contains less variables than a (resp. b) 
#
##############################################################################
	
def vecto_comb(uple):
    return combs(uple, 2)
def test_len(a):
    return len(a)
def test_len_eval(a):
    return len(str(a))
vectest = np.vectorize(test_len)
vectest_eval = np.vectorize(test_len_eval)

#################### updates exp (in str format) random and secret dependencies after modifications using rule 3 ####################
def vecto_random_secret_deps(exp, nb_secrets, nb_randoms):
    exp_split = [elem.split("*") for elem in exp.split(" + ")]

    secret_dep = [0 for i in range(nb_secrets)]
    random_dep = [0 for i in range(nb_randoms)]
    for e in exp_split:
        for v in e:
            if((v == '0') or (v == '1')):
                continue
            if(v[-1] == '_'):
                if((exp.count(v) == 1) and (len(e) == 1)):
                    random_dep[int(v[1:-1])] = 1 
                else:
                    random_dep[int(v[1:-1])] = 2
                #if(str(eval(exp)+eval(v)).count(v)==0):
                #    random_dep[int(v[1:-1])] = 1
                #elif(exp.count(v) >= 1):
                #    random_dep[int(v[1:-1])] = 2
            else:
                secret_dep[ord(v[0])-97] |= (1 << int(v[1:]))
    return np.asarray([secret_dep, random_dep], dtype=object)

vect_variables = np.vectorize(vecto_random_secret_deps)
vect_str = np.vectorize(str)
    

########## This is an auxiliary function, it is not used in the execution, check the next function
def apply_rule_3_(list_tuples, exps, exps_str, verbosity):
    comb_2_elems = np.apply_along_axis(func1d=vecto_comb, axis=1, arr=list_tuples)  #np.asarray([combs(uple, 2) for uple in list_tuples]) 

    expressions = exps[comb_2_elems]
    expressions_str = exps_str[comb_2_elems]
    
    #Computing number of variables for each couple of comb for each tuple
    nb_var_couple = vectest(expressions_str)
    m,n = nb_var_couple.shape[:2]
    
    nb_var_arg_max = np.argmax(nb_var_couple, axis=2)    
    nb_var_max = nb_var_couple[np.arange(m)[:,None] ,np.arange(n), nb_var_arg_max]
        
    s = np.sum(expressions, axis=2)
    nb_var_summed_couple = vectest_eval(s)
    
    del expressions
    del expressions_str
    del nb_var_couple
    
    less_than_max = nb_var_summed_couple < nb_var_max
    
    #TUPLES TO MODIFY
    mask_tuples_to_modify = np.any(less_than_max, axis=1)
    choice_combs_to_modify = np.argmax(less_than_max[mask_tuples_to_modify, :], axis=1)     #Choose the first comb for each tuple
    
    #Final lists to modify
    tuples_to_modify = list_tuples[mask_tuples_to_modify, :]
    s = s[mask_tuples_to_modify, choice_combs_to_modify]
    if(len(s) > 0):
        s_str = vect_str(s)
        
    else:
        s_str = np.asarray([])
        if(verbosity == 2):
            print ("After Rule 3 : 0 Modified Tuples")
        return s, s_str
    
    
    vars_max = comb_2_elems[np.arange(m)[:,None] ,np.arange(n), nb_var_arg_max]
    vars_ = np.reshape(vars_max[mask_tuples_to_modify, choice_combs_to_modify], (-1,1))
    vars_to_modify_mask = np.argmax((tuples_to_modify == vars_), axis=1)
    
    tuples_to_modify[np.arange(len(tuples_to_modify)), vars_to_modify_mask] = np.arange(len(exps),len(exps)+len(s))
    list_tuples[mask_tuples_to_modify, :] = tuples_to_modify
    
    if(verbosity == 2):
        print ("After Rule 3 : " + str(len(vars_to_modify_mask)) + " Modified Tuples")
    
    return s, s_str


def apply_rule_3(list_tuples, exps, exps_str, verbosity):
    comb_2_elems = np.apply_along_axis(func1d=vecto_comb, axis=1, arr=list_tuples)  #np.asarray([combs(uple, 2) for uple in list_tuples]) 
    
    expressions = exps[comb_2_elems]
    expressions_str = exps_str[comb_2_elems]
    
    #Computing number of variables for each couple of comb for each tuple
    nb_var_couple = vectest(expressions_str)
    m,n = nb_var_couple.shape[:2]

    s = np.sum(expressions, axis=2)
    nb_var_summed_couple = vectest_eval(s)
    
    del expressions
    del expressions_str
    
    less_than_1 = nb_var_summed_couple < nb_var_couple[:, :, 0]
    less_than_2 = (nb_var_summed_couple < nb_var_couple[:, :, 1])
    less_than_1_or_2 = less_than_1 | less_than_2

    del nb_var_couple

    #TUPLES TO MODIFY
    mask_tuples_to_modify =  np.any(less_than_1_or_2, axis=1)
    choice_combs_to_modify = np.argmax(less_than_1_or_2[mask_tuples_to_modify, :], axis=1)
    
    less_than_1 = np.reshape(less_than_1[mask_tuples_to_modify, choice_combs_to_modify], (-1, 1))
    less_than_2 = np.reshape(less_than_2[mask_tuples_to_modify, choice_combs_to_modify], (-1, 1))  & (~less_than_1)
    less_than_1_or_2 = np.concatenate((less_than_1, less_than_2), axis=1)
    del less_than_1;   del less_than_2
    
    #Final lists to modify
    tuples_to_modify = list_tuples[mask_tuples_to_modify, :]
    s = s[mask_tuples_to_modify, choice_combs_to_modify]
    if(len(s) > 0):
        s_str = vect_str(s)
        
    else:
        s_str = np.asarray([])
        if(verbosity == 2):
            print ("After Rule 3 : 0 Modified Tuples")
        return s, s_str

    vars_ = np.reshape(comb_2_elems[mask_tuples_to_modify, choice_combs_to_modify][less_than_1_or_2], (-1,1))
    vars_to_modify_mask = np.argmax(tuples_to_modify == vars_, axis=1)
    
    tuples_to_modify[np.arange(len(tuples_to_modify)), vars_to_modify_mask] = np.arange(len(exps),len(exps)+len(s))
    list_tuples[mask_tuples_to_modify, :] = tuples_to_modify
    
    if(verbosity == 2):
        print ("After Rule 3 : " + str(len(vars_to_modify_mask)) + " Modified Tuples")
    
    return s, s_str
    

##############################################################################
#
# apply_rule_4
#	OUTPUT:
#		- modifies list_tuples such that for 
#				each tuple which contains only one occurrence of a random 
#				variable, then the corresponding expression is replaced by the 
#				random variable itself (considers sub-expressions after
#                  factorization unlike rule 2 which only considers the whole
#                   developped expression, this rule is useful for 
#                   multiplication gadgets)
#
##############################################################################

#################### checks if a sub-expression in exp (in str format) may be replaced by the random variable ra, and replace it ####################
def vect_rule_4_exps(exp, ra, nb_randoms, nb_secrets):
    secret_dep = [0 for i in range(nb_secrets)]
    random_dep = [0 for i in range(nb_randoms)]
    if(exp == '0' or exp == '1'):
        return np.asarray([exp, secret_dep, random_dep], dtype=object)

    exp_split = exp.split(" + ")
    e = []
    e_final = []
    var = []
    bo_one = False
    for elem in exp_split:
        if("*" in elem):
            tmp = elem.split("*")
            
            if(tmp[0] == ra):
                var.append(tmp[1])       
                e_final.append(elem)
            elif(tmp[1] == ra):
                var.append(tmp[0])
                e_final.append(elem)
            else:
                e.append(elem)
        elif(elem == ra):
            bo_one = True
            e_final.append(elem)
        else:
            e.append(elem)       
    
    inter = []
    v = var[0]
    for elem in e:
        if(("*" in elem) and (v in elem)):
            
            tmp = elem.split("*")
            if(v == tmp[0]):
                inter.append(tmp[1])
            else:
                inter.append(tmp[0])
            
    for v in var[1:]:
        l = []
        
        for elem in e:
            if(("*" in elem) and (v in elem)):
                tmp = elem.split("*")
                if(v == tmp[0]):
                    l.append(tmp[1])
                else:
                    l.append(tmp[0])
                    
        inter = [el for el in inter if el in l]
        
    if(bo_one):
        l = []
        for elem in e:
            if(not("*" in elem)):
                l.append(elem)
                
        inter = [el for el in inter if el in l]       
        
        
    for elem in e:
        if("*" in elem):
            tmp = elem.split("*")
            
            if((tmp[0] in var and tmp[1] in inter) or (tmp[1] in var and tmp[0] in inter)):
                continue
            else:
                e_final.append(elem)
                
        elif((bo_one) and (elem in inter)):
            continue
        else:
            e_final.append(elem)
    
    exp = " + ".join(e_final)
    exp_split = [elem.split("*") for elem in exp.split(" + ")]

    for e in exp_split:
        for v in e:
            if((v == '0') or (v == '1')):
                continue
            
            if(v[-1] == '_'):
                if((exp.count(v) == 1) and (len(e) == 1)):
                    random_dep[int(v[1:-1])] = 1
                    
                else:
                    random_dep[int(v[1:-1])] = 2

            else:
                secret_dep[ord(v[0])-97] |= (1 << int(v[1:]))
                
    return np.asarray([exp, secret_dep, random_dep], dtype=object)

vect_rule_4 = np.vectorize(vect_rule_4_exps)

def fo(exp):
    return eval(exp)
vect_eval = np.vectorize(fo)


def apply_rule_4(list_tuples, random_deps, exps, exps_str, secret_deps, verbosity):
    #First, reduce add all random deps from all wires in each tuple
    nb = 0
    total = 0
    for r in range(len(random_deps[0])):
        
        rands1 = np.add.reduce(random_deps[list_tuples, r], axis=1) #This is to make sure that the sum is equal 2 (so either one wire =2 or 2 wires = 1)
        rands2 = np.bitwise_or.reduce(random_deps[list_tuples, r], axis=1)  #This is to make sure that from rands1, only one wire = 2, which is the one we need
    
        mask = np.logical_and((rands1==2), (rands2 == 2))             #This will filter from list_tuples only the ones that we need to replace
        liste = list_tuples[mask, :]        #This will select the corresponding tuples in list_tuples
        
        if(len(liste) == 0):
            continue
        
        varsi = (random_deps[liste, r] == 2) #This will contain the exact wire index in each tuple to modify its value
                
        exps_str_to_append = exps_str[liste[varsi]]
                
        liste[varsi] = np.arange(len(exps), len(exps)+len(exps_str_to_append))
        
        list_tuples[mask, :] = liste
        
        
        start = time.time()
        variables = vect_rule_4(exps_str_to_append, "r"+str(r)+"_", len(random_deps[0]), len(secret_deps[0]))
        end = time.time()        
        exps_str_to_append = np.asarray([elem[0] for elem in variables])
        
        secret_deps_append = np.asarray([elem[1] for elem in variables])
        random_deps_append = np.asarray([elem[2] for elem in variables])

        exps_str = np.append(exps_str, exps_str_to_append)
        exps = np.append(exps, vect_eval(exps_str_to_append))
        secret_deps = np.append(secret_deps, secret_deps_append, axis=0)
        random_deps = np.append(random_deps, random_deps_append, axis=0)
        
        total += (end - start)
        
    return list_tuples, exps, exps_str, secret_deps, random_deps, total
        
##############################################################################
#
# apply rules 1, 2, 3 and 4 in a loop to extract remaining failure tuples
#
##############################################################################
def apply_all_rules(list_tuples, secret_deps, random_deps, exps, exps_str, nb_occs_tuple, sums, i, val_max, t=None, verbosity=0):
    total_time = 0
    total_time3 = 0
    #################### Rule 1 ####################      
    l = np.copy(list_tuples)
    secret_deps_tuple = np.bitwise_or.reduce(secret_deps[list_tuples, :], axis=1, dtype=np.uint)
    if(t is None):   
        r1_mask = apply_rule_1(secret_deps_tuple, val_max)
    else:
        r1_mask = apply_rule_1_exp(secret_deps_tuple, t)
    list_tuples = list_tuples[r1_mask, :]
    l = l[r1_mask, : ]
    sums = sums[r1_mask]
    if(not(nb_occs_tuple is None)):
        nb_occs_tuple = nb_occs_tuple[r1_mask, :]
        
    if(verbosity == 2):
        print ('Rule 1 applied'+'... '+str(len(list_tuples))+' tuples')
    del r1_mask
    
    ln = len(list_tuples) + 1
    #Loop on all rules
    count = 0
    
    while((len(list_tuples)>0) and (len(list_tuples) < ln)):
        if(verbosity == 2):
            print ('Iteration '+str(count+1)+'... '+str(len(list_tuples))+' tuples')
        
        while( (len(list_tuples)>0) and (len(list_tuples) < ln) ):
            ln = len(list_tuples)
            #################### Rule 2 ####################     
            apply_rule_2(list_tuples, random_deps, verbosity)
            
            #################### Rule 1 ####################     
            secret_deps_tuple = np.bitwise_or.reduce(secret_deps[list_tuples, :], axis=1, dtype=np.uint)
            if(t is None):   
                r1_mask = apply_rule_1(secret_deps_tuple, val_max)
            else:
                r1_mask = apply_rule_1_exp(secret_deps_tuple, t)
            list_tuples = list_tuples[r1_mask, :]
            l = l[r1_mask, : ]
            sums = sums[r1_mask]
            if(not(nb_occs_tuple is None)):
                nb_occs_tuple = nb_occs_tuple[r1_mask, :]
            del r1_mask
            if(verbosity == 2):
                print ('Rule 1 applied'+'... '+str(len(list_tuples))+' tuples')
                
        if(len(list_tuples) > 0):
            #################### Rule 4 ####################
            if(verbosity == 2):
                print("Rule 4")
            ini = len(exps)
            start = time.time()
            list_tuples, exps, exps_str, secret_deps, random_deps, ti = apply_rule_4(list_tuples, random_deps, exps, exps_str, secret_deps, verbosity)
            end = time.time()
            total_time += ti
            if(verbosity == 2):
                print ("After Rule 4 : " + str(len(exps)-ini) + " Modified Tuples")
            
            #################### Rule 2 ####################     
            apply_rule_2(list_tuples, random_deps, verbosity)
            
            #################### Rule 1 ####################     
            secret_deps_tuple = np.bitwise_or.reduce(secret_deps[list_tuples, :], axis=1, dtype=np.uint)
            if(t is None):   
                r1_mask = apply_rule_1(secret_deps_tuple, val_max)
            else:
                r1_mask = apply_rule_1_exp(secret_deps_tuple, t)
            list_tuples = list_tuples[r1_mask, :]
            l = l[r1_mask, : ]
            sums = sums[r1_mask]
            if(not(nb_occs_tuple is None)):
                nb_occs_tuple = nb_occs_tuple[r1_mask, :]
            del r1_mask
            if(verbosity == 2):
                print ('Rule 1 applied'+'... '+str(len(list_tuples))+' tuples')
         
        if(len(list_tuples) > 0):
            for anyvar in range(3):
                #if(len(list_tuples)>0):
                #################### Rule 3 ####################     
                start = time.time()
                exps_to_append, exps_str_to_append = apply_rule_3(list_tuples, exps, exps_str, verbosity)
                if(len(exps_to_append) > 0):
                    random_secret = vect_variables(exps_str_to_append, len(secret_deps[0]), len(random_deps[0])).tolist()
                    secret_deps_append = np.asarray([elem[0] for elem in random_secret])
                    random_deps_append = np.asarray([elem[1] for elem in random_secret])
    
                    exps = np.append(exps, exps_to_append)
                    exps_str = np.append(exps_str, exps_str_to_append)
                    secret_deps = np.append(secret_deps, secret_deps_append, axis=0)
                    random_deps = np.append(random_deps, random_deps_append, axis=0)
                    del random_secret
                    del secret_deps_append
                    del random_deps_append
                end = time.time()
                total_time3 += (end - start)
                
            #################### Rule 2 ####################     
            apply_rule_2(list_tuples, random_deps, verbosity)
        
            #################### Rule 1 ####################     
            secret_deps_tuple = np.bitwise_or.reduce(secret_deps[list_tuples, :], axis=1, dtype=np.uint)
            if(t is None):   
                r1_mask = apply_rule_1(secret_deps_tuple, val_max)
            else:
                r1_mask = apply_rule_1_exp(secret_deps_tuple, t)
            list_tuples = list_tuples[r1_mask, :]
            l = l[r1_mask, : ]
            sums = sums[r1_mask]
            if(not(nb_occs_tuple is None)):
                nb_occs_tuple = nb_occs_tuple[r1_mask, :]
            del r1_mask
            if(verbosity == 2):
                print ('Rule 1 applied'+'... '+str(len(list_tuples))+' tuples')
            
        count += 1
        
    return list_tuples, sums, nb_occs_tuple, secret_deps, l, total_time, total_time3