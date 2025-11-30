

n = 275621053


print(n**(1/2))

p = 16601
q = 16601

for i in range(15501, 17501, 2):
    for j in range (15501, 17501, 2):
        if (i * j == n):
            print(f"p = {i} +  and q + {j}")
            break


#Quicker method!

for i in range(16000, 17000):
    if n % i == 0:
        print(f"p = {i} and q = {n//i}")
        break

#Using difference of squares
import math
a = math.ceil(n**(1/2))
found = False
while not found:
    b2 = a*a - n
    b = int(b2**(1/2))
    if b*b == b2:
        found = True
    else:
        a += 1
p = a - b
q = a + b
print(f"p = {p} and q = {q}")

