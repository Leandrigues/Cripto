
from sage.all import *

import sys

# Parâmetro público PRIME: a característica do corpo finito usado para instanciar
# a curva elíptica
EC = EllipticCurve([0, 0, 0, 2, 3])
PRIME = 263
EC = EC.change_ring(GF(PRIME))
POLY = EC.defining_polynomial()

# Geração das chaves secreta e pública
def MV_keygen(s, P):
    s = s % PRIME
    Q = s*P
    public_key = (Q, P)
    secret_key = s

    return public_key, secret_key

# Escolha de um k que faça c1 e c2 inversíveis
def choose_k(P):
    while True:
        k = randint(1, PRIME)
        c1, c2, _ = k*P 
        if gcd(c1, PRIME) == 1 and gcd(c2, PRIME):
            return k, c1, c2 
# Função de encriptação simples (DE UM BLOCO)
def MV_encrypt(X, public_key):
    k, c1, c2 = choose_k(public_key[0])
    y0 = int(k) * public_key[1]
    y1 = (int(c1)*X[0]) % PRIME
    y2 = (int(c2)*X[1]) % PRIME

    return (y0, y1, y2)


# Função de encriptação usando modo CBC
# (quebra uma mensagem grande em blocos e encripta sequencialmente sob o regime
# CBC - cipher block chaining)
def CBC_MV_encrypt(big_message_bin, public_key):
    length = len(big_message_bin)
    remainder = length % 16
    if remainder != 0:
        padding = '0'*(16 - remainder)
        big_message_bin = big_message_bin + padding 

    blocks = [big_message_bin[i:i+16] for i in range(0, length, 16)]
    last_block = ['00000000', '00000000']
    cipher = []
    y0s = []

    for block in blocks:
        xB1 = int(block[:8], 2).__xor__(int(last_block[0], 2) % 256)
        xB2 = int(block[8:], 2).__xor__(int(last_block[1], 2) % 256)
        (y0, yB1, yB2) = MV_encrypt([xB1, xB2], public_key)
        last_block = [bin(yB1)[2:].zfill(9), bin(yB2)[2:].zfill(9)]
        cipher.append(last_block)
        y0s.append(y0)

    return cipher, y0s

# Calcula o valor de X = (x1, x2) como descrito no enunciado
def MV_decrypt(Y, secret_key):
    (c1, c2, z) = secret_key * Y[0]
    x1 = (Y[1] * inverse_mod(int(c1), PRIME)) % PRIME
    x2 = (Y[2] * inverse_mod(int(c2), PRIME)) % PRIME

    X = (x1, x2)

    return X


# Função de decriptação usando modo CBC
# (quebra uma mensagem grande em blocos e decripta sequencialmente na ordem
# certa sob o regime CBC - cipher block chaining)
def CBC_MV_decrypt(blocks, secret_key, y0s):
    decipher = []
    blocks.insert(0, ['00000000', '00000000'])
    y0s.insert(0, 0)

    for i in range(1, len(blocks)):
        (yA1, yA2) = blocks[i] 
        (xA1, xA2) = MV_decrypt([y0s[i], int(yA1,2), int(yA2,2)], secret_key)
        plain_A1 = xA1.__xor__(int(blocks[i-1][0], 2) % 256) 
        plain_A2 = xA2.__xor__(int(blocks[i-1][1], 2) % 256) 
        plain = [bin(plain_A1)[2:].zfill(8), bin(plain_A2)[2:].zfill(8)]
        decipher.append(plain)

    return decipher


def get_binary_representation_512_bits_of_hex(h):
    '''
    Recebe uma string h representando um hexadecimal.
    Devolve a representação binária de h com EXATAMENTE 512 bits
    '''

    bin_h = bin(int(h, 16))[2:]  # [2:] Tira o 0b da frente
    bin_h_512bits = '0' * (512 - len(bin_h)) + bin_h

    return bin_h_512bits


def hamming_distance_with_hex_strings(h1, h2):
    """
    Calcula a distância de hamming entre dois hashes em STRINGS representando
    hexadecimais
    """

    bin_h1 = get_binary_representation_512_bits_of_hex(h1)
    bin_h2 = get_binary_representation_512_bits_of_hex(h2)

    distance = 0
    for x1, x2 in zip(bin_h1, bin_h2):
        if x1 != x2:
            distance += 1
    return distance

# Retona os n primeiros pontos da curva
def first_elements(n):
    P = EC.an_element()
    point_list = []
    for i in range(1, n + 1):
        point_list.append(i*P)

    return point_list

# Soma de dois pontos, estando ou não na curva, utilizando a regra de soma de pontos
# na curva elíptica
def sum_points_with_EC_rule(P, Q):
    t = (Q[1] - P[1]) / (Q[0] - P[0]) 
    xR = t ** 2  - P[0] - Q[0]
    yR = t*(P[0] - xR) - P[1]

    return (xR, yR)

# Escreve random_bytes + nUSP em um arquivo
def write_file_with_nusp(name, random_bytes, nUSP):
    f = open(name, "w")
    f.write(nUSP + random_bytes)
    first_bytes = nUSP + random_bytes[:92]
    result = nUSP + first_bytes
    f.close()

    return result

# Gera n bytes aleatórios e retorna sua representação hexadecimal
def generate_random_bytes(n):
    return os.urandom(n).hex()

# Lê e retorna o texto de um arquivo
def read_file(name):
    f = open(name, "r")
    text = f.read()
    f.close()
    return text

# Adiciona um padding de 0s no final da string para ter tamanho múltiplo de 16
def correct_size(string):
    remainder = len(string) % 16
    if remainder != 0:
        string = string + '0' * (16 - remainder)
    return string

# Printa hífens do tamanho do terminal para separar as respostas
def print_separator():
    rows, columns = os.popen("stty size", "r").read().split()
    for i in range(int(columns)):
        print("-", sep="", end="")
        
def main():
    """
    Função principal que ordena as chamadas de funções para realizar o que foi
    pedido no EP.
    """
    print_separator()
    # 1
    print("Exercício 1")
    print("EC = ", EC)
    print_separator()
    # 2 
    P = EC(200, 39)
    print("Exercício 2")
    print("(200, 39) pertence à curva?", POLY.substitute(x = 200, y = 39, z = 1) == 0)
    print_separator()
    # 3
    print("Exercício 3")
    print("Existem", EC.cardinality(), "pontos na curva")
    print_separator()
    # 4
    print("Exercício 4")
    print("Primeiros 10 pontos na curva: ", first_elements(10))
    print_separator()
    # 5 
    print("Exercício 5")
    print("(175, 80) pertence à curva?", POLY.substitute(x = 175, y = 80, z = 1) == 0)
    R = (175, 80, 1)
    print_separator()
    #  6
    print("Exercício 6")
    print("Soma P + R: ", sum_points_with_EC_rule(P, R))
    print_separator()
    # 7
    print("Exercício 7")
    s = 10723944 % PRIME
    print("s = 10723944 % 263 =", s)
    print_separator()
    # 8
    print("Exercício 8")
    public_key_alice, secret_key_alice = MV_keygen(s, P)
    print("Q = sP =", public_key_alice[0])
    print_separator()
    # 9
    print("Exercício 9")
    Y = MV_encrypt(R, public_key_alice)
    print("Y = (y0, y1, y2) = ", Y)
    print_separator()
    # 10
    print("Exercício 10")
    decipher_Y = MV_decrypt(Y, secret_key_alice)
    print("Decifração de Y:", decipher_Y)
    print_separator()
    # 11
    print("Exercício 11")
    nusp = '10723944'
    n = 100000
    random_bytes = generate_random_bytes(n)
    write_file_with_nusp('documento1', random_bytes, nusp)
    documento1 = read_file('documento1')
    print("Primeiros 100 bytes de documento1: ", documento1[:200])
    print_separator()
    # 12
    print("Exercício 12")
    doc1_bin = correct_size(bin(int(documento1, 16))[2:])
    doc1_cript, points_y0 = CBC_MV_encrypt(doc1_bin, public_key_alice)
    doc1_cript_string = ''
    for i in doc1_cript:
        doc1_cript_string += ''.join(i)
    print("Primeiros 100 bytes de doc1_cript: ", hex(int(doc1_cript_string[:800], 2)))
    print_separator()
    # 13
    print("Exercício 13")
    doc1_cript_inverso = CBC_MV_decrypt(doc1_cript[:800], secret_key_alice, points_y0)
    doc1_cript_inv_string = ''
    for i in doc1_cript_inverso:
        doc1_cript_inv_string += ''.join(i)
    print("Primeiros 100 bytes de doc1_cript_inverso:", hex(int(doc1_cript_inv_string, 2))[:200])
    print_separator()
    # 14
    print("Exercício 14")
    print("Exercício anulado")
    # doc1_cript_inverso = hex(int(doc1_cript_inv_string, 2))
    # doc1_cript = hex(int(doc1_cript_string, 2))
    # print("Distância de Hamming entre doc1_cript_inverso e doc1_cript: ", \
    # hamming_distance_with_hex_strings(doc1_cript, doc1_cript_inverso))
    print_separator()
    # 15
    print("Exercício 15")
    nusp = '20723944'
    write_file_with_nusp('documento2', random_bytes, nusp)
    documento2 = read_file('documento2')
    print("Primeiros 100 bytes de documento2:", documento2[:200])
    print_separator()
    # 16
    print("Exercício 16")
    doc2_bin = correct_size(bin(int(documento2, 16))[2:])
    doc2_cript, points_y0 = CBC_MV_encrypt(doc2_bin, public_key_alice)
    doc2_cript_string = ''
    for i in doc2_cript:
        doc2_cript_string += ''.join(i)
    print("Primeiros 100 bytes de doc2_cript: ", hex(int(doc2_cript_string[:800], 2)))
    print_separator()
    #17
    print("Exercício 17")
    doc2_cript = hex(int(doc2_cript_string, 2))
    print("Distância de Hamming entre doc1_cript e doc2_cript", hamming_distance_with_hex_strings( \
        hex(int(doc2_cript_string,2)), hex(int(doc1_cript_string, 2))))
    print_separator()
    #18
    print("Exercício 18")
    public_key_beto, secret_key_beto = MV_keygen(99999999, P)
    print("Chaves de beto:", secret_key_beto, public_key_beto)
    print_separator()
    #19
    print("Exercício 19")
    doc1_cript_beto, points_y0 = CBC_MV_encrypt(doc1_bin, public_key_beto)
    doc1_cript_beto_string = ''
    for i in doc1_cript_beto:
        doc1_cript_beto_string += ''.join(i)
    print("Primeiros 100 bytes de doc1 criptografado por beto:", hex(int(doc1_cript_beto_string, 2))[:200])
    print_separator()
    # 20
    print("Exercício 20")
    doc1_cript_beto_hex = hex(int(doc1_cript_beto_string, 2))
    print("Distância de Hamming entre doc1-cript e doc1-cript-beto", hamming_distance_with_hex_strings \
        (doc1_cript_beto_hex, hex(int(doc1_cript_string, 2))))
    print_separator()

if __name__ == '__main__':
    main()
