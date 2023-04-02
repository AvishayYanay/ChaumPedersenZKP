

import gmpy2
import random
import os
import secrets

# Set the precision to 2048 bits
gmpy2.get_context().precision = 2048

def miller_rabin(n, k=10):
    # Check some simple cases
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Compute r and s such that n-1 = 2^s * r
    r, s = n - 1, 0
    while r % 2 == 0:
        r //= 2
        s += 1

    # Perform k rounds of the Miller-Rabin test
    for i in range(k):
        a = random.randint(2,n-2)
        a = gmpy2.mpz(a)
        # a = int.from_bytes(a, byteorder='big')
        # a %= n - 2
        # a += 2
        # a = gmpy2.mpz(a)
        x = gmpy2.powmod(a, r, n)
        if x == 1 or x == n - 1:
            continue
        for j in range(s - 1):
            x = gmpy2.powmod(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_safe_prime(bit_length):
    while True:
        # Generate a random prime p
        q = random.randint(2**bit_length,2**(bit_length+1))
        if miller_rabin(q,40):
            print(".", end='', flush=True)
            p = 2*q+1
            if miller_rabin(p,40):
                print("\n")
                return q

def find_generators(p,q):
    e = random.randint(1,p-1)
    e2 = gmpy2.powmod(e, 2, p)
    g = e2
    e = random.randint(1,p-1)
    e2 = gmpy2.powmod(e, 2, p)
    h = e2
    # order_e2 = gmpy2.powmod(e2, q, p)
    # print("order of e2 =  ", order_e2)
    # if order_e2 == 1:
    #     print("good generator")
    return g,h


# q = generate_safe_prime(1024)
# print("q: ", q)
# print("p: ", q*2+1)

# result:
q = 209029927115828403386810952696967163980318312066095279899029952627092411912063878751958462389324353976308585301230245759282751982187974570384912978520141092685483885396812657392164015843532185790823411797167921261671903619835361512338760317249950380249852357633730763318976763056021225613232360053843806780701
p = 418059854231656806773621905393934327960636624132190559798059905254184823824127757503916924778648707952617170602460491518565503964375949140769825957040282185370967770793625314784328031687064371581646823594335842523343807239670723024677520634499900760499704715267461526637953526112042451226464720107687613561403


# g,h = find_generators(p,q)
# print("g: ", g)
# print("h: ", h)

# result:
g = 68385373268825386496621014982270107267408040057860093779345041243137532223854743249147759654089106222810303087916297689234956771859181723460676690896472830574277008060097562353856463028247437260670124221444384125969123225040457092359400398275738784463753426031138407349907186681719428815791946465958461402909
h = 393785364724507076351339252369533057983945164615661098811219681357554198522023418943796180186638778968163393281129234148272001296083113152980339156732724818942196795090685837552169445604298532719696597548922995923958977974002823815367643611795605859946974883985367902226779515098800883763139800229178086933735


class ZZp_star:
    def __init__(self):
        self.p = p
        self.q = q
    
    def sub_modq(self, x, y):
        yy = q-y
        z = gmpy2.add(x, yy)
        sub_mod_q = gmpy2.f_mod(z, self.q)
        return z

    def mul_modq(self, x,y):
        z = gmpy2.mul(x, y)
        prod_mod_q = gmpy2.f_mod(z, self.q)  # (x*y) % q
        return prod_mod_q

    def mul(self, x,y):
        z = gmpy2.mul(x, y)
        prod_mod_p = gmpy2.f_mod(z, self.p)  # (x*y) % p
        return prod_mod_p
    
    def exp(self, x,e):
        exp_mod_p = gmpy2.powmod(x, e, self.p)  # x^e % p
        return exp_mod_p
    
    def inv(self, x):
        inv_mod_p = gmpy2.powmod(x, self.q-1, self.p)
        return inv_mod_p
    
    def rand(self):
        rand_mod_p = random.randint(1,p-1)
        x = gmpy2.powmod(rand_mod_p, 2, p)
        return x
    
    def is_valid(self, x):
        if x<1 or x >= self.p:
            return False
        return True


def client_gen_register_values():
    G = ZZp_star()
    x = random.randint(1,q)
    y1 = G.exp(g, x)
    y2 = G.exp(h, x)
    return x,y1,y2

def client_gen_ephemeral():
    G = ZZp_star()
    k = random.randint(1,q)
    r1 = G.exp(g, k)
    r2 = G.exp(h, k)
    return k,r1,r2

def client_prove(x,k, c):
    # s = k-cx
    G = ZZp_star()
    cx = G.mul_modq(c,x)
    s = G.sub_modq(k, cx)
    return s

def server_verify_proof(y1, y2, r1, r2, c, s):
    # r1 = g^s * y1^c
    G = ZZp_star()
    gs = G.exp(g, s)
    y1c = G.exp(y1, c)
    gsy1c = G.mul(gs,y1c)
    print("r1 =? gsy1c", r1 == gsy1c)

    # r2 = h^s * y2^c
    G = ZZp_star()
    hs = G.exp(h, s)
    y2c = G.exp(y2, c)
    hsy2c = G.mul(hs,y2c)
    print("r2 =? hsy2c", r2 == hsy2c)

    return r1 == gsy1c and r2 == hsy2c

def client_store_login_params(fname, username, x, y1, y2):
    with open(fname, "w") as file:
        file.write(username+"\n")
        file.write(str(x)+"\n")
        file.write(str(y1)+"\n")
        file.write(str(y2)+"\n")

def server_store_login_params(fname, username, y1, y2):
    with open(fname, "w") as file:
        file.write(username+"\n")
        file.write(str(y1)+"\n")
        file.write(str(y2)+"\n")

def client_load_reg_params(fname):
    with open(fname, "r") as file:
        lines = file.readlines()
        username = lines[0].strip()
        reg_x = lines[1].strip()
        reg_y1 = lines[2].strip()
        reg_y2 = lines[3].strip()
        return True, username, reg_x, reg_y1, reg_y2
    return False, 0, 0, 0, 0

def server_load_reg_params(fname):
    with open(fname, "r") as file:
        lines = file.readlines()
        username = lines[0].strip()
        reg_y1 = lines[1].strip()
        reg_y2 = lines[2].strip()
        return True, username, reg_y1, reg_y2
    return False, 0, 0, 0

def server_get_random_nonce():
    nonce = random.randint(0,2**64-1)
    return nonce

def server_store_session(fname, y1, y2, r1, r2):
    print("Session name: ", fname)
    with open(fname, "w") as file:
        file.write(str(y1)+"\n")
        file.write(str(y2)+"\n")
        file.write(str(r1)+"\n")
        file.write(str(r2)+"\n")

def server_load_session(fname):
    with open(fname, "r") as file:
        print("found!")
        lines = file.readlines()
        reg_y1 = lines[0].strip()
        reg_y2 = lines[1].strip()
        eph_r1 = lines[2].strip()
        eph_r2 = lines[3].strip()
        return True, reg_y1, reg_y2, eph_r1, eph_r2
    return False, 0, 0, 0, 0

def server_generate_session_id():
    session_id = secrets.token_hex(16)
    return session_id

# server register errors
ERR_USER_EXISTS = 1
ERR_INVALID_POINTS = 2
ERR_SESSION_DOESNT_EXISTS = 3


def test_proof_system():
    x,y1,y2 = client_gen_register_values()
    x = gmpy2.mpz(x)
    y1 = gmpy2.mpz(y1)
    y2 = gmpy2.mpz(y2)

    k,r1,r2 = client_gen_ephemeral()
    k = gmpy2.mpz(k)
    r1 = gmpy2.mpz(r1)
    r2 = gmpy2.mpz(r2)

    c = server_get_random_nonce()
    c = gmpy2.mpz(c)

    s = client_prove(x,k, c)
    s = gmpy2.mpz(s)

    accept = server_verify_proof(y1, y2, r1, r2, c, s)
    return accept

if __name__ == "__main__":
    print("test proof system = ", test_proof_system())