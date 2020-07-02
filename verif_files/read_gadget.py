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

##############################################################################
#
# compute_input_file
#
# 	INPUTS:
#		- circuit_file: pseudo-code
#
#	OUTPUT:
#		- rewritten pseudo-code such that each instruction output is unique
#			and random variables names end with '_', along with the 
#             list of descriptions for each variable
#
##############################################################################

def compute_input_file(circuit_file, verbosity):
    #result output circuit file after modification
    output_circuit = open("sage_tmp1.sage", "w")
    
    output_pol_ring = open("sage_tmp2.sage", "w")
    output_pol_ring.write('P.<')
    
    f1 = open(circuit_file)
    lines = f1.readlines()
    f1.close()
    
    if("ORDER" in lines[0]):
        lines = lines[1:]
    
    #Copying first 5 files for ORDER, SHARES, IN, RANDOMS, OUT in the specified order
    output_circuit.write(lines[0])  #SHARES  
    nb_shares = int(lines[0].split()[1])
    
    output_circuit.write(lines[1])  #IN
    
    #Writing Sage_tmp2 File for polynomial Ring
    varss = lines[1].split()[1:]
    for v in varss:
        for i in range(nb_shares):
            output_pol_ring.write(v+str(i)+",")
    
    #RANDOMS with _
    args = lines[2].split()
    output_circuit.write(args[0])
    randoms = []
    randoms_dict = dict()
    tmp = 0
    for r in args[1:-1]:
        output_circuit.write(" r"+str(tmp)+"_")
        output_pol_ring.write("r"+str(tmp)+"_,")
        randoms.append("r"+str(tmp)+"_")
        randoms_dict[r] = "r"+str(tmp)+"_"
        tmp += 1
    
    ri = args[-1]
    output_circuit.write(" r"+str(tmp)+"_")
    output_pol_ring.write("r"+str(tmp)+"_")
    randoms.append("r"+str(tmp)+"_")
    randoms_dict[ri] = "r"+str(tmp)+"_"
    tmp += 1
    output_circuit.write("\n")
    
    output_circuit.write(lines[3])  #OUT
    #Finishing file sage_tmp2
    output_pol_ring.write('>=BooleanPolynomialRing()')
    output_pol_ring.close()
    
    output_letters = lines[3].split()[1:]
    
    #Copying the rest of the file by writing unique instructions outputs
    lines = lines[4:]
    used_out_vars = dict()
    new_lines = []
    #Variables _var counter
    var_counter = 1
    for line in lines:
        if line == '\n':
            new_lines.append(line)
            continue
        args = line.split()
        new_line = []
        token_index = 1
        while(token_index < len(args)):
            new_line.append(args[token_index])
            token_index += 1
            
            if(args[token_index][:1] in output_letters):
                new_line.append(args[token_index])
            elif(args[token_index] in used_out_vars):
                new_line.append(used_out_vars[args[token_index]])
            elif(args[token_index] in randoms_dict.keys()):
                new_line.append(randoms_dict[args[token_index]])
            else:
                new_line.append(args[token_index])
            token_index += 1
        
        if(args[0] in used_out_vars):
            used_out_vars[args[0]] = "_var"+str(var_counter)
            var_counter += 1
        elif(args[0][:1] in output_letters):
            new_line.insert(0, args[0])
            new_line.append("\n")
            new_lines.append(" ".join(new_line))
            continue
        else:
            used_out_vars[args[0]] = args[0]
            
        new_line.insert(0, used_out_vars[args[0]])
        new_line.append("\n")
        new_lines.append(" ".join(new_line))
        
    lines = new_lines
    new_lines = []
    used_out_vars = dict()
    
    for line in reversed(lines):
        if line == '\n':
            new_lines.insert(0, line)
            continue
        
        args = line.split()
        new_line = []
        
        if(args[0] in used_out_vars):
            new_line.append(used_out_vars[args[0]])
        else:
            new_line.append(args[0])
        
        token_index = 1
        while(token_index < len(args)):
            new_line.append(args[token_index])
            token_index += 1
            
            if(args[token_index][:1] in output_letters):
                used_out_vars[args[token_index]] = "_var"+str(var_counter)
                var_counter += 1
                new_line.append(used_out_vars[args[token_index]])
            else:
                new_line.append(args[token_index])
                
            token_index += 1
            
        new_line.append("\n")
        new_lines.insert(0, " ".join(new_line))
        
    for line in new_lines:
        output_circuit.write(line)

    output_circuit.close()
    
    if(verbosity > 0):
        print ("Succesfully Created sage_tmp1 and sage_tmp2 intermediate files !\n")
    
    return generate_list_inv_var_from_file()
    

##############################################################################
#
# generate_list_inv_var_from_file
#
#	OUTPUT:
#		- returns the list of descriptions for each variable
#       Each variable is represented as [name_of_variable, 
#       algebraic_expression, secret_dependencies, random_dependencies,
#       nb_occurrences, binary_repr, nb_variables]
#
##############################################################################
def generate_list_inv_var_from_file():
    # load file
    load("sage_tmp2.sage")
    load("sage_tmp1.sage")

    dict_int_var = dict()
    dict_out_var = dict()
    list_int_var = []
    list_out_var = []
    list_secret_var = []
    list_random_var = []
    count_int_var = 1   #This is for the binary representation of each wire in the tuples
    
    f = open("sage_tmp1.sage")
    lines = f.readlines()
    f.close()
        
    nb_shares = int(lines[0].split()[1])    #SHARES
    
    #Adding Input Variables
    varss = lines[1].split()[1:]
    for v in varss:
        list_secret_var.append(v)
    rands = lines[2].split()[1:]
    for r in rands:
        list_random_var.append(r)
        
        
    #Adding Random Variables
    index = 0
    for r in rands:
        secret_dep = [0 for i in range(len(list_secret_var))]
        random_dep = [0 for i in range(len(list_random_var))]
        random_dep[index] = 1
        dict_int_var[r] = [str(eval(r)), secret_dep, random_dep, 0, count_int_var, 1]
        count_int_var = count_int_var << 1
        index += 1
    Nrand = len(rands)
    index = 0
    for v in varss:
        for i in range(nb_shares):
            secret_dep = [0 for j in range(len(list_secret_var))]
            random_dep = [0 for j in range(len(list_random_var))]
            sh = v+str(i)
            secret_dep[index] = (1 << int(i))
            dict_int_var[sh] = [str(eval(sh)), secret_dep, random_dep, 0, count_int_var, 1]
            count_int_var = count_int_var << 1
        index += 1
        
    #Adding Output Variables
    outs = lines[3].split()[1:]
            
    lines = lines[4:]
    Nadd = 0
    Nmult = 0
    #Updating intermediate variables wires
    for line in lines:
        if line == '\n':
            continue
        args = line.split()
        Nadd += line.count("+")
        Nmult += line.count("*")
        expression = eval(args[0])
        token_index = 1
        while(token_index < len(args)):
            token_index += 1
            s = args[token_index]
            if((s != '0') and (s != '1')):
                dict_int_var[s][3] += 1
            token_index += 1
            
        secret_dep = [0 for i in range(len(list_secret_var))]
        random_dep = [0 for i in range(len(list_random_var))]
        nb_var = 0
        for v in expression.variables():
            stri = str(v)
            nb_var += 1
            try:
                index = list_random_var.index(stri)
                if(str(expression+eval(list_random_var[index])).count(list_random_var[index])==0):
                    random_dep[index] = 1
                elif(str(expression).count(list_random_var[index]) >= 1):
                    random_dep[index] = 2
            except:
                index = list_secret_var.index(stri[0])
                secret_dep[index] += (1 << int(stri[1:]))
            
        if(args[0][0] in outs):
            dict_out_var[args[0]] = [str(expression), secret_dep, random_dep, 0, 0, nb_var]
            #count_int_var = count_int_var << 1
        else:
            dict_int_var[args[0]] = [str(expression), secret_dep, random_dep, 0, count_int_var, nb_var]
            count_int_var = count_int_var << 1
            
    Ncopy = 0
    for x, y in dict_int_var.items():
        if(y[3] > 1):
            Ncopy += (y[3] - 1)
            y[3] = 2*y[3] - 1
        list_int_var.append((x, eval(y[0]), y[1], y[2], y[3], y[4], y[5]))
        
    for v in outs:
        shares = []
        for i in range(nb_shares):
            value = dict_out_var[v+str(i)]
            shares.append((v+str(i), eval(value[0]), value[1], value[2], value[3], count_int_var, value[4]))
            count_int_var = count_int_var << 1
                            
        list_out_var.append(shares)
    
    complexity = (Nadd, Ncopy, Nmult, Nrand)
    list_int_var.sort(key=lambda c: c[5])
    return (order,nb_shares,list_int_var,list_out_var, complexity)
    

def write_exps_file(list_int_var, list_out_var):
    f = open("sage_tmp2_exps.sage", "w")
    
    for var in list_int_var:
        f.write(var[0] + " = " + str(var[1]) + "\n")
    f.write("\n")
    for out in list_out_var:
        for var in out:
            f.write(var[0] + " = " + str(var[1]) + "\n")

    f.close()

def return_numpy_arrays(list_int_var):
    indices = np.asarray([i for i in range(len(list_int_var))], dtype = np.uint16)
    #~names = np.asarray([var[0] for var in list_int_var])
    exps = np.asarray([var[1] for var in list_int_var])
    exps_str = np.asarray([str(var[1]) for var in list_int_var])
    secret_deps = np.asarray([var[2] for var in list_int_var], dtype = np.uint)
    random_deps = np.asarray([var[3] for var in list_int_var], dtype = np.uint8)
    nb_occs = np.asarray([var[4] for var in list_int_var], dtype = np.uint16)
    weights = np.asarray([var[5] for var in list_int_var], dtype = object)
    
    return (indices, exps, secret_deps, random_deps, nb_occs, weights, exps_str)
