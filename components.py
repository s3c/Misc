import math

def inductor(f, l):
    return 1j*2*math.pi*f*l
    
def capacitor(f, c):
    return 1/(1j*2*math.pi*f*c)
    
def parallel(x, y):
    return (x*y)/(x+y)
    
def magnitude(x):
    return math.sqrt(x.real**2 + x.imag**2)
