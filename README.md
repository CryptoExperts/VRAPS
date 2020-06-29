# VRAPS: (V)erifier of (RA)ndom (P)robing (S)ecurity

VRAPS is a formal verification tool for the random probing security of masked implementations, as well as for the probing security. The verified properties are :

- t-Probing Security (P)

* (p, &epsilon;)-Random Probing (RP)
* (t, p, &epsilon;)-Random Probing Composability (RPC)
* (t, f)-Random Probing Expandability (RPE)

VRAPS was introduced in the following publication :

> [Random Probing Security: Verification, Composition, Expansion and New Constructions](https://eprint.iacr.org/2020/786)  
> By Sonia Belaïd, Jean-Sébastien Coron, Emmanuel Prouff, Matthieu Rivain and Abdul Rahman Taleb 
> In the proceedings of CRYPTO 2020.

## Content

This repository contains the code of __VRAPS__ implemented in SageMath and Python3:

- **verif_tool.sage:** contains the main program that runs the tool.
- **read_gadget.py:** contains the function that reads a gadget in an input file with the correct format, and outputs information needed for the tool to apply verification rules, converting variables and expressions in numpy arrays format (when the tool reads a gadget, it outputs three temporary files **sage_tmp1.sage**, **sage_tmp2.sage** and **sage_tmp2_exps.sage**).
- **verification_rules.py:** contains the simplification rules (1, 2, 3 and 4), and the function that loops over all these rules and applies them to given tuples.
- **probing_func.py:** contains the verification function for P property. 
- **random_probing_func.py:** contains the verification function for RP property. 
- **random_probing_exp1_func.py:** contains the verification function for RPE1 property (First part of RPE property). 
- **random_probing_exp2_func.py:** contains the verification function for RPE2 property (Second part of RPE property). 
- **random_probing_exp_copy_func.py:** in case of an RPE verification for copy gadgets, there are 4 functions that are computed. This file contains the function that computes f<sup>12</sup> and f<sup>21</sup> (f<sup>1</sup> and f<sup>2</sup> are respectively computed using **random_probing_exp1_func.py** and **random_probing_exp2_func.py**).
- **random_probing_comp_func.py:** contains the verification function for RPC property.

## Usage

Using the tool requires having [SageMath](http://www.sagemath.org/) installed and Python (3 or higher). The main function of the tool is in the file `verif_tool.sage`. To get all options, run the following command:

```
sage verif_tool.sage -h
```

This outputs :

```
usage: verif_tool.sage.py [-h] [-c COEFF_MAX] [-v {0,1,2}] [-t T]
                          [-t_output T_OUTPUT]
                          File {P,RP,RPE,RPC}

positional arguments:
  File                  Name of gadget's input file
  {P,RP,RPE,RPC}        Property among P, RP, RPE, RPC to verify

optional arguments:
  -h, --help            show this help message and exit
  -c COEFF_MAX, --coeff_max COEFF_MAX
                        Number of Coefficients (default: -1 to compute all
                        coefficients)
  -v {0,1,2}, --verbose {0,1,2}
                        Verbosity During Execution
  -t T                  Number of input/output shares required for properties
                        P, RPE and RPC
  -t_output T_OUTPUT    Number of output shares required for properties RPE
                        and RPC

```

The parameter `t` is only necessary for the properties RPC, RPE, RPE1 and RPE2. When `t_output` is specified, the value of `t` is taken for input shares and the value of `t_output` for output shares. Otherwise, `t` is used for input shares and output shares.

The parameter `coeff_max` specifies the maximum size of tuples to test during the verification (which is also the maximum coefficient in the evaluation of &epsilon; which will be computed exactly). This parameter is not needed for probing verification .

The argument `-v` lets the user specify the amount of output he desires to follow the pace of the execution. The default value `-v 0` means that only the final output will be displayed. The value `-v 1` will output current size of tuples tested and iteration numbers. While the value `-v 2` will output all of the above, as well as every rule that is applied and the number of tuples that are being eliminated after each iteration.

#### Execution Examples

- The following command executes P verification on the gadget `gadget.sage`, checking if it is 2​-Probing secure:

  ```
  sage verif_tool.sage gadget.sage P -t 2
  ```

* The following command executes RP verification on the gadget `gadget.sage`, and stops at the maximum coefficient of 5:

  ```
  sage verif_tool.sage gadget.sage RP -c 5
  ```

* The following command executes RPE verification on the gadget `gadget.sage` with a value of `t = 2` for input and output shares, and stops at the maximum coefficient of 5:

  ```
  sage verif_tool.sage gadget.sage RPE -c 5 -t 1 -v 0
  ```

  If t<sub>in</sub> = 2​ and t<sub>out</sub> = 1​ :

  ```
  sage verif_tool.sage gadget.sage RPE -c 5 -t 2 -t_output 1 -v 1
  ```

* The following command executes RPC verification on the gadget `gadget.sage` with a value of `t = 2` for input and output shares, and stops at the maximum coefficient of 5:

  ```
  sage verif_tool.sage gadget.sage RPC -c 5 -t 2 -v 2
  ```

### Notes

* The verification functions for all of the properties process the tuples through the simplification rules in batches instead of all at once, for memory and speed issues. The batch size is experimentally fixed at a maximum of 200000 tuples per batch. This value can be modified at any time by modifying the global variable `BATCH_SIZE` in the main file `verif_tool.sage`.

* In the file __verification_rules.py__, there is a hamming weight lookup table, of default size 2048. This size means that the number of shares for any gadget is at most log<sub>2</sub>(2048) = 11 shares. If gadgets of higher number of shares are to be used with the program, the size of this table should be increased. Namely, for n-share gadgets, the table should be of size at least 2<sup>n</sup>. We consider the approach of the lookup table of size 2<sup>n</sup> since we use the tool to verify the security of relatively small gadgets, which makes the lookup table of reasonable size.

  # changed to 2^n

## Input Format

Input gadget file have to be sage files in the following format :

```
#ORDER 1
#SHARES 2
#IN a b
#RANDOMS r0
#OUT d

c0 = a0 * b0	
d0 = c0 + r0

c1 = a1 * b1
c1 = c1 + r0
tmp = a0 * b1
c1 = c1 + tmp
tmp = a1 * b0

d1 = c1 + tmp
```

Above is an example of the ISW​ multiplication gadget with 2 shares. 

* `#ORDER 1`  is the order of the gadget (1-Probing Secure)
* `#SHARES 2` is the number of shares used in the gadget
* `#IN a b` are the input variables of the gadget
* `#RANDOMS r0` are all of the random variables used in the gadget
* `#OUT d` is the output variable of the gadget

The next lines are the instructions (or gates) of the gadget. Allowed operations are `+` and `*`. The shares of input/output variables range from 0 to \#shares - 1 . To specify the share for each variable, simply use the variable name suffixed by the share number `(eg. a0, b1, d0, ...)​`.  Input variables should be one letter variables in an alphabetical order starting from `a` (`a, b, c, ...`). Output variables should also be one letter variables.

__The variable names of the format `r#_` where `#` is a number `(eg. r0_, r15_, ...)`, are reserved formats for the tool processing and should not be used in the gadget description.__



## Output Format

### Output of P Verification

For probing security verification, the tool simply outputs if for the considered value of t, whether the gadget is or is not t-Probing secure.

### Output of RP Verification

```
$ sage verif_tool.sage ../GADGETS/ISW/isw_mult_3_shares.sage RP -c 4
Reading file...
Succesfully Created sage_tmp1 and sage_tmp2 intermediate files !

Gadget with 2 input(s),  1 output(s),  3 share(s)
Total number of intermediate variables : 27
Total number of output variables : 1
Total number of Wires : 57

----     Verification of Random Probing Security     ----

----     End of Verification of Random Probing Security     ----


Coefficients fmin(p) = [0.0, 0.0, 0.0, 1252.0, 57109.0, 244566.0, 626271.0, 1149896.0, 1642971.0, 1902112.0, 1823082.0, 1462534.0, 985372.0, 555820.0, 260050.0, 99242.0, 30078.0, 6948.0, 1146.0, 120.0, 6.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

Coefficients fmax(p) = [0.0, 0.0, 0.0, 1252.0, 57109.0, 4187106, 36288252, 264385836, 1652411475, 8996462475, 43183019880, 184509266760, 707285522580, 2448296039700, 7694644696200, 22057981462440, 57902201338905, 139646485582065, 310325523515700, 636983969321700, 1210269541711230, 2132379668729310, 3489348548829780, 5309878226480100, 7522327487513475, 9929472283517787, 12220888964329584, 14031391033119152, 15033633249770520, 15033633249770520, 14031391033119152, 12220888964329584, 9929472283517787, 7522327487513475, 5309878226480100, 3489348548829780, 2132379668729310, 1210269541711230, 636983969321700, 310325523515700, 139646485582065, 57902201338905, 22057981462440, 7694644696200, 2448296039700, 707285522580, 184509266760, 43183019880, 8996462475, 1652411475, 264385836, 36288252, 4187106, 395010, 29260, 1596, 57, 1]

Verification Time = 0.32769203186 seconds

Complexity (Nadd, Ncopy, Nmult, Nrand) = (12, 15, 9, 3)

```

Above is an output example of RP verification for the ISW​ 3-share multiplication gadget, with default verbosity `-v 0` and `Coeff_max = 4`.  The tool starts by outputting the description of the gadget :

```
Gadget with 2 input(s),  1 output(s),  3 share(s)
Total number of intermediate variables : 27
Total number of output variables : 1
Total number of Wires : 57
```

and then outputs the coefficients for the function f(p) computed by the tool (See paper for details on the function f). These coefficients are a lower bound on the function (`Coefficients fmin(p)`). The tool also outputs an upper bound on f(p) (`Coefficients fmax(p)`) by replacing each c<sub>i</sub> > Coeff_max by <img src="https://latex.codecogs.com/svg.latex?\small\binom{s}{i}"/>where s is the total number of wires in the gadget (check the paper for more details).

The tool also outputs the total verification time as well as the gadget's complexity in terms of number of addition, copy, multiplication and randomness gates needed.

### Output of RPE Verification

```
$ sage verif_tool.sage ./isw_mult_o1.sage RPE -c 4 -t 1
Reading file...
Succesfully Created sage_tmp1 and sage_tmp2 intermediate files !

Gadget with 2 input(s),  1 output(s),  2 share(s)
Total number of intermediate variables : 11
Total number of output variables : 1
Total number of Wires : 21

----     Verification of Random Probing Expandability Property 1 ( t = 1 )    ----

----     End of Verification of Random Probing Expandability Property 1     ----


----     Verification of Random Probing Expandability Property 2 ( t = 1 )    ----

----     End of Verification of Random Probing Expandability Property 2     ----


Coefficients Prop_EXP fmin_I1(p) = [0.0, 4.0, 105.0, 975.0, 5220.0, 10548.0, 12048.0, 8874.0, 4488.0, 1583.0, 385.0, 60.0, 5.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
Coefficients Prop_EXP fmin_I2(p) = [0.0, 4.0, 104.0, 965.0, 5175.0, 10482.0, 12000.0, 8856.0, 4485.0, 1583.0, 385.0, 60.0, 5.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
Coefficients Prop_EXP fmin_I1_and_I2(p) = [0.0, 4.0, 78.0, 767.0, 4585.0, 9554.0, 11117.0, 8321.0, 4279.0, 1536.0, 380.0, 60.0, 5.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

Coefficients Prop_EXP fmax_I1(p) = [0.0, 4.0, 105.0, 975.0, 5220.0, 20349, 54264, 116280, 203490, 293930, 352716, 352716, 293930, 203490, 116280, 54264, 20349, 5985, 1330, 210, 21, 1]
Coefficients Prop_EXP fmax_I2(p) = [0.0, 4.0, 104.0, 965.0, 5175.0, 20349, 54264, 116280, 203490, 293930, 352716, 352716, 293930, 203490, 116280, 54264, 20349, 5985, 1330, 210, 21, 1]
Coefficients Prop_EXP fmax_I1_and_I2(p) = [0.0, 4.0, 78.0, 767.0, 4585.0, 20349, 54264, 116280, 203490, 293930, 352716, 352716, 293930, 203490, 116280, 54264, 20349, 5985, 1330, 210, 21, 1]

Total Verification Time = 0.233469963074 seconds

Complexity (Nadd, Ncopy, Nmult, Nrand) = (4, 5, 4, 1)

Amplification Order d = 1/2
Coeff c1/2 = 2.0

Log2 of Lower Bound on p : pmin = -infinity , Log2 fmax(pmin) = -infinity
Log2 of Upper Bound on p : pmax = -infinity , Log2 fmin(pmax) = -infinity

```

Above is an output example of RPE verification for the ISW​ 2-share multiplication gadget, with default verbosity `-v 0` and `-t 1`.  The tool starts by outputting the description of the gadget :

```
Gadget with 2 input(s),  1 output(s),  2 share(s)
Total number of intermediate variables : 11
Total number of output variables : 1
Total number of Wires : 21
```

and ends by outputting the functions f<sup>1</sup>, f<sup>2</sup>, f<sup>12</sup>​ computed by the tool with the value `Coeff_max = 4`. The first three lines

```
Coefficients Prop_EXP fmin_I1(p) = [0.0, 4.0, 105.0, 975.0, 5220.0, 10548.0, 12048.0, 8874.0, 4488.0, 1583.0, 385.0, 60.0, 5.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
Coefficients Prop_EXP fmin_I2(p) = [0.0, 4.0, 104.0, 965.0, 5175.0, 10482.0, 12000.0, 8856.0, 4485.0, 1583.0, 385.0, 60.0, 5.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
Coefficients Prop_EXP fmin_I1_and_I2(p) = [0.0, 4.0, 78.0, 767.0, 4585.0, 9554.0, 11117.0, 8321.0, 4279.0, 1536.0, 380.0, 60.0, 5.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
```

are respectively the coefficients computed for f<sup>1</sup>, f<sup>2</sup> and f<sup>12</sup>, which provide a lower bound on these functions since all coefficients c<sub>i</sub> > Coeff_max are not exactly computed. An upper bound on these functions are given in the next three lines 

```
Coefficients Prop_EXP fmax_I1(p) = [0.0, 4.0, 105.0, 975.0, 5220.0, 20349, 54264, 116280, 203490, 293930, 352716, 352716, 293930, 203490, 116280, 54264, 20349, 5985, 1330, 210, 21, 1]
Coefficients Prop_EXP fmax_I2(p) = [0.0, 4.0, 104.0, 965.0, 5175.0, 20349, 54264, 116280, 203490, 293930, 352716, 352716, 293930, 203490, 116280, 54264, 20349, 5985, 1330, 210, 21, 1]
Coefficients Prop_EXP fmax_I1_and_I2(p) = [0.0, 4.0, 78.0, 767.0, 4585.0, 20349, 54264, 116280, 203490, 293930, 352716, 352716, 293930, 203490, 116280, 54264, 20349, 5985, 1330, 210, 21, 1]
```

where each c<sub>i</sub> > Coeff_max is replaced by <img src="https://latex.codecogs.com/svg.latex?\small\binom{s}{i}"/> where s is the total number of wires in the gadget (check the paper for more details).

The tool also outputs the total verification time, the complexity of the gadget in number of gates for each operation (add, copy, multiplication, random), the amplification order d and the corresponding coefficient c<sub>d</sub>​, and finally outputs lower and upper bounds on the tolerated leakage probability :

```
Log2 of Lower Bound on p : pmin = -infinity , Log2 fmax(pmin) = -infinity
Log2 of Upper Bound on p : pmax = -infinity , Log2 fmin(pmax) = -infinity
```

When the amplification order d &leq; 1​, the tolerated probability is equal to 0, which is why the output log<sub>2</sub> value is `-infinity`. 

To output all of the intermediate functions coefficients, the argument `-v 1` or `-v 2` should be specified.

__When the amplification order output is `d = 0`, this means that the chosen value for `Coeff_max` is not enough to determine the amplification order, so the user has to test bigger coefficient values to get the right amplification order. __



### Output of RPC Verification

```
$ sage verif_tool.sage ./isw_mult_o1.sage RPC -c 4 -t 1
Reading file...
Succesfully Created sage_tmp1 and sage_tmp2 intermediate files !

Gadget with 2 input(s),  1 output(s),  2 share(s)
Total number of intermediate variables : 11
Total number of output variables : 1
Total number of Wires : 21

----     Verification of Random Probing Composability ( t = 1 )    ----

----     End of Verification of Random Probing Composability     ----



Coefficients Prop_COMP fmin(p) = [0.0, 4.0, 131.0, 1173.0, 5810.0, 11476.0, 12931.0, 9409.0, 4694.0, 1630.0, 390.0, 60.0, 5.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

Coefficients Prop_COMP fmax(p) = [0.0, 4.0, 131.0, 1173.0, 5810.0, 20349, 54264, 116280, 203490, 293930, 352716, 352716, 293930, 203490, 116280, 54264, 20349, 5985, 1330, 210, 21, 1]

Total Verification Time = 0.157685041428 seconds

Complexity (Nadd, Ncopy, Nmult, Nrand) = (4, 5, 4, 1)

Amplification Order d = 1

Coeff c1 = 4.0

Log2 of Lower Bound on p : pmin = -infinity , Log2 fmax(pmin) = -infinity
Log2 of Upper Bound on p : pmax = -infinity , Log2 fmin(pmax) = -infinity

```

Above is an output example of RPE verification for the ISW 2-share multiplication gadget, with default verbosity `-v 0` and `-t 1`.  The tool gives almost the same output information as for the RPE verification, except for the upper and lower bounds on the coefficients. In the case of RPC verification, there is only one function f instead of f<sup>1</sup>, f<sup>2</sup>, f<sup>12</sup> for RPE, and the tool outputs the computed coefficients for f​ with the corresponding value for `Coeff_max` :

```
Coefficients Prop_COMP fmin(p) = [0.0, 4.0, 131.0, 1173.0, 5810.0, 11476.0, 12931.0, 9409.0, 4694.0, 1630.0, 390.0, 60.0, 5.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
```

and outputs an upper bound on f by replacing each each c<sub>i</sub> > Coeff_max is replaced by <img src="https://latex.codecogs.com/svg.latex?\small\binom{s}{i}"/> where s is the total number of wires in the gadget (check the paper for more details) :

```
Coefficients Prop_COMP fmax(p) = [0.0, 4.0, 131.0, 1173.0, 5810.0, 20349, 54264, 116280, 203490, 293930, 352716, 352716, 293930, 203490, 116280, 54264, 20349, 5985, 1330, 210, 21, 1]
```

To output all of the intermediate functions coefficients, the argument `-v 1` or `-v 2` should be specified.

__When the amplification order output is `d = 0`, this means that the chosen value for `Coeff_max` is not enough to determine the amplification order, so the user has to test bigger coefficient values to get the right amplification order. __



### Output of RPE Verification for Copy Gadgets (1 input, 2 outputs)

The output for RPE verification of copy gadgets is slightly different than for other gadgets. Consider the following example of a simple 2-share copy gadget

```
#ORDER 1
#SHARES 2
#IN a
#RANDOMS r1 r2
#OUT d e

d0 = a0 + r1
d1 = a1 + r1

e0 = a0 + r2
e1 = a1 + r2
```

The RPE verification of the tool with `t = 1` and `Coeff_max = 4` for the above gadget outputs :

```
$ sage verif_tool.sage ./gadget_jsc_copy_o1.sage RPE2 -c 4 -t 1
Reading file...
Succesfully Created sage_tmp1 and sage_tmp2 intermediate files !

Gadget with 1 input(s),  2 output(s),  2 share(s)
Total number of intermediate variables : 4
Total number of output variables : 2
Total number of Wires : 12

Execution of RPE for a Copy Gadget...

----     Verification of Random Probing Expandability Copy    ----

----     Verification of EXP Copy 1    ----

----     Verification of EXP Copy 2    ----

----     Verification of EXP Copy 12   ----

----     Verification of EXP Copy 21    ----

----     End of Verification of Random Probing Expandability Copy     ----


coeffs f_min(p) : [0.0, 0.0, 36.0, 180.0, 465.0, 780.0, 922.0, 792.0, 495.0, 220.0, 66.0, 12.0, 1.0]

coeffs f_max(p) : [0.0, 0.0, 36.0, 180.0, 465.0, 792, 924, 792, 495, 220, 66, 12, 1]

Total Verification Time = 0.0475420951843 seconds

Complexity (Nadd, Ncopy, Nmult, Nrand) = (4, 4, 0, 2)

Amplification Order d = 2

Log2 of Lower Bound on p : pmin = -5.34894830882107 , Log2 fmax(pmin) = -5.35063899326025
Log2 of Upper Bound on p : pmax = -5.34894830882107 , Log2 fmin(pmax) = -5.35064530083635

```

In particular, RPE verification for copy gadget gives a function f​ where :

​																				f = max(f<sup>12</sup>, f<sup>21</sup>, f<sup>1</sup>, f<sup>2</sup>)

See paper for more details.

The tool outputs the lower and upper bounds on f​ using the same procedure as for the other outputs. To output all of the functions coefficients, the argument `-v 1` or `-v 2` should be specified.

## License

[GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)