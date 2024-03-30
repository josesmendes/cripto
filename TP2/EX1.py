#p = pow(2,255) - 19
#d = -121665/121666
p = (pow(2, 448) - pow(2, 224)) - 1
d = (-39081 * pow(39080,-1, p)) % p

print("P: ", p)
print("D: ", d)


u=9
x=15112221349535400772501151409588531511454012693041857206046113283949847762202
y=((u-1) * pow(u+1, -1, p)) % p




curve_equation = ((-1 * x*x + y*y) % p)
curve_equation2 = ((1 * d * pow(x,2) * pow(y,2)) % p) 

print("CURVA: ", curve_equation)
print("CURVA2: ", curve_equation2)
