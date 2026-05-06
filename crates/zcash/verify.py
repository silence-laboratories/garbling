import struct
import hashlib

# Bristol Blake2b modular circuit generator
def generate_blake2b_512_bristol_modular():
    gates = []
    wire_count = 2048 
    IV = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
          0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
    sigma = [[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
             [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],[7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
             [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
             [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
             [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],[10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
             [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3]]

    def get_wires(n=64):
        nonlocal wire_count
        start, wire_count = wire_count, wire_count + n
        return list(range(start, wire_count))

    zero_w = wire_count; gates.append(f"2 1 0 0 {zero_w} XOR"); wire_count += 1
    one_w = wire_count; gates.append(f"1 1 {zero_w} {one_w} INV"); wire_count += 1

    def make_const_word(val): return [one_w if (val >> i) & 1 else zero_w for i in range(64)]
    def xor_64(a, b):
        res = get_wires(64)
        for i in range(64): gates.append(f"2 1 {a[i]} {b[i]} {res[i]} XOR")
        return res
    def add_64(a, b):
        nonlocal wire_count
        res, c = get_wires(64), zero_w
        for i in range(64):
            x1, a1, a2, c_out = range(wire_count, wire_count + 4); wire_count += 4
            gates.append(f"2 1 {a[i]} {b[i]} {x1} XOR")
            gates.append(f"2 1 {x1} {c} {res[i]} XOR")
            gates.append(f"2 1 {a[i]} {b[i]} {a1} AND")
            gates.append(f"2 1 {c} {x1} {a2} AND")
            gates.append(f"2 1 {a1} {a2} {c_out} XOR")
            c = c_out
        return res
    def rot_64(w, n): return w[n:] + w[:n]
    def G(v, a, b, c, d, x, y):
        v[a] = add_64(add_64(v[a], v[b]), x)
        v[d] = rot_64(xor_64(v[d], v[a]), 32)
        v[c] = add_64(v[c], v[d]); v[b] = rot_64(xor_64(v[b], v[c]), 24)
        v[a] = add_64(add_64(v[a], v[b]), y)
        v[d] = rot_64(xor_64(v[d], v[a]), 16)
        v[c] = add_64(v[c], v[d]); v[b] = rot_64(xor_64(v[b], v[c]), 63)
        return v

    h_in = [list(range(i*64, (i+1)*64)) for i in range(8)]
    v = [word[:] for word in h_in]
    v += [make_const_word(IV[0]), make_const_word(IV[1]), make_const_word(IV[2]), make_const_word(IV[3])]
    v += [xor_64(make_const_word(IV[4]), list(range(512, 576))), make_const_word(IV[5])] # v12 XOR t0
    v += [xor_64(make_const_word(IV[6]), list(range(576, 640))), make_const_word(IV[7])] # v14 XOR f0

    m = [list(range(1024 + i*64, 1024 + (i+1)*64)) for i in range(16)]
    for r in range(12):
        s = sigma[r]
        v = G(v,0,4,8,12,m[s[0]],m[s[1]]); v = G(v,1,5,9,13,m[s[2]],m[s[3]])
        v = G(v,2,6,10,14,m[s[4]],m[s[5]]); v = G(v,3,7,11,15,m[s[6]],m[s[7]])
        v = G(v,0,5,10,15,m[s[8]],m[s[9]]); v = G(v,1,6,11,12,m[s[10]],m[s[11]])
        v = G(v,2,7,8,13,m[s[12]],m[s[13]]); v = G(v,3,4,9,14,m[s[14]],m[s[15]])

    a = []
    for i in range(8):
        a.append(xor_64(h_in[i], v[i]))

    out = []
    for i in range(8):
        res = xor_64(a[i], v[i+8])
        out.extend(res)

    return "\n".join([f"{len(gates)} {wire_count}", "2 1024 1024", "1 512"] + gates)

# Bristol Blake2b modular circuit simulator
def simulate_bristol(circuit_str, in1, in2):
    lines = circuit_str.strip().split('\n')
    header = lines[0].split()
    wires = [0] * int(header[1])
    for i in range(1024): wires[i] = in1[i]
    for i in range(1024): wires[1024+i] = in2[i]
    for line in lines[3:]:
        p = line.split()
        op = p[-1]
        if op == "XOR": wires[int(p[4])] = wires[int(p[2])] ^ wires[int(p[3])]
        elif op == "AND": wires[int(p[4])] = wires[int(p[2])] & wires[int(p[3])]
        elif op == "INV": wires[int(p[3])] = 1 - wires[int(p[2])]
        elif op == "EQ": wires[int(p[3])] = wires[int(p[2])]
    return wires[-512:]

def bits_to_hex(bits):
    hb = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8): b |= (bits[i+j] << j)
        hb.append(b)
    return hb.hex()

def verify_hash(message):
    circuit = generate_blake2b_512_bristol_modular()
    h_words = [0x6a09e667f3bcc908 ^ 0x01010040, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
    pers_0 = 0x78455f687361635a
    pers_1 = 0x64656553646e6170
    h_words[6] = h_words[6] ^ pers_0
    h_words[7] = h_words[7] ^ pers_1
    blocks = [message[i:i+128] for i in range(0, len(message), 128)] or [b""]
    bytes_processed = 0
    final_bits = []
    for i, block in enumerate(blocks):
        is_last = (i == len(blocks) - 1)
        bytes_processed += len(block)
        in1 = []
        for w in h_words: in1.extend([(w >> j) & 1 for j in range(64)])
        in1.extend([(bytes_processed >> j) & 1 for j in range(64)]) # t0
        in1.extend([1 if is_last else 0] * 64) # f0
        in1.extend([0] * (1024 - len(in1)))
        in2 = []
        for w in struct.unpack("<16Q", block.ljust(128, b'\x00')): 
            in2.extend([(w >> j) & 1 for j in range(64)])
        res_bits = simulate_bristol(circuit, in1, in2)
        final_bits = res_bits
        final_hex = bits_to_hex(final_bits)
        h_words = struct.unpack("<8Q", bytes.fromhex(final_hex))
    final_hex = bits_to_hex(final_bits)
    print(final_bits)
    print(final_hex)
    # print(f"Simulated: {final_hex}\nExpected:  {hashlib.blake2b(message).hexdigest()}")
    # if final_hex == hashlib.blake2b(message).hexdigest(): print("correct")
    # else: print("fail")

if __name__ == "__main__":
    verify_hash(b"\xff" * (128 + 16))

    # circuit = generate_blake2b_512_bristol_modular()
    # print(circuit)
