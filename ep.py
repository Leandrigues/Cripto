
from sage.all import *

import sys

# Parâmetro público p: a característica do corpo finito usado para instanciar
# a curva elíptica
EC = EllipticCurve([0, 0, 0, 2, 3])
PRIME = 263
EC = EC.change_ring(GF(PRIME))
POLY = EC.defining_polynomial()

def MV_keygen(s, P):
    secret = s % PRIME
    Q = secret*P
    public_key = (Q, P)
    secret_key = secret

    return public_key, secret_key


# Função de encriptação simples (DE UM BLOCO)
def MV_encrypt(X, public_key):
    k = 0
    y0 = int(k) * public_key[1]
    (c1, c2, z) = int(k) * public_key[0]

    while k == 0 or y0[0] == 0 or y0[1] == 0 or c1 == 0 or c2 == 0:
        k = GF(PRIME).random_element()
        k = int(k) % 256
        y0 = int(k) * public_key[1]
        (c1, c2, z) = int(k) * public_key[0]

    y1 = (c1*X[0]) % PRIME
    y2 = (c2*X[1]) % PRIME

    return (y0, y1, y2)


# Função de encriptação usando modo CBC
# (quebra uma mensagem grande em blocos e encripta sequencialmente sob o regime
# CBC - cipher block chaining)
def correctBlockSize(message, n):
    message_bin = bin(message)[2:]
    size = len(message_bin)
    padding = n - size
    message_bin = '0' * padding + message_bin
    return message_bin

def CBC_MV_encrypt(big_message_bin, public_key):

    length = len(big_message_bin)
    rest = length % 16
    if rest != 0:
        padding = '0'*(16 - rest)
        big_message_bin = big_message_bin + padding 

    blocks = [big_message_bin[i:i+16] for i in range(0, length, 16)]
    last_block = 0
    Y = []
    y0s = []
    
    for block in blocks:
        x = int(block, 2).__xor__(last_block)
        x_with_block_size = correctBlockSize(x, 16)
        x1 = int(x_with_block_size[:8], 2)
        x2 = int(x_with_block_size[8:], 2)
        (y0, y1, y2) = MV_encrypt([x1, x2], public_key)
        y1 = int(y1) % 256
        y2 = int(y2) % 256 
        last_block_x1 = correctBlockSize(y1, 8)
        last_block_x2 = correctBlockSize(y2, 8)
        last_block = int(last_block_x1 + last_block_x2, 2)
        string_block = last_block_x1 + last_block_x2
        Y.append(string_block)
        y0s.append(y0)

    return Y, y0s

def MV_decrypt(Y, secret_key):
    # Calcula o valor de X = (x1, x2) como descrito no enunciado
    (c1, c2, z) = secret_key * Y[0]
    x1 = (Y[1] * inverse_mod(int(c1), PRIME)) % PRIME
    x2 = (Y[2] * inverse_mod(int(c2), PRIME)) % PRIME

    X = (x1, x2)

    return X


# Função de decriptação usando modo CBC
# (quebra uma mensagem grande em blocos e decripta sequencialmente na ordem
# certa sob o regime CBC - cipher block chaining)
def CBC_MV_decrypt(big_ciphertext_bin, secret_key, y0s):
    length = len(big_ciphertext_bin)
    blocks = [big_ciphertext_bin[i:i+16] for i in range(0, length, 16)]
    plain_text = []
    y0s.reverse()
    blocks.reverse()
    blocks.append('0000000000000000')

    for i in range(len(blocks) - 1):
        y0 = y0s[i]
        y1 = int(blocks[i][:8], 2)
        y2 = int(blocks[i][8:], 2)
        X = MV_decrypt([y0, y1, y2], secret_key)

        x1 = correctBlockSize(int(X[0]) % 256, 8)
        x2 = correctBlockSize(int(X[1]) % 256, 8)
        if len(x1) != 8 or len(x2) != 8:
            print("ERRO")
            return
        next_block_y1 = int(blocks[i+1][:8], 2)
        next_block_y2 = int(blocks[i+1][8:], 2)

        x1_int = int(x1, 2)
        x2_int = int(x2, 2)
        xor_x1 = x1_int.__xor__(next_block_y1)
        xor_x2 = x2_int.__xor__(next_block_y2)

        plain_x1 = correctBlockSize(xor_x1, 8)
        plain_x2 = correctBlockSize(xor_x2, 8)
        plain_text.append(plain_x1 + plain_x2)

    plain_text.reverse()

    return plain_text


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

def firstElements(n):
    P = EC.an_element()
    point_list = []

    for i in range(1, n + 1):
        point_list.append(i*P)

    return point_list

def sum_points_with_EC_rule(P, Q):
    t = (Q[1] - P[1]) / (Q[0] - P[0]) 
    xR = t ** 2  - P[0] - Q[0]
    yR = t*(P[0] - xR) - P[1]

    return (xR, yR)

def write_file_with_nusp(name, random_bytes, nUSP):
    # Escreve random_bytes + nUSP em um arquivo
    f = open(name, "w")
    f.write(nUSP + random_bytes)
    first_bytes = nUSP + random_bytes[:92]
    result = nUSP + first_bytes
    f.close()

    return result

def generate_random_bytes(n):
    # Gera 100000 bytes aleatórios e retorna sua representação hexadecimal
    return os.urandom(n).hex()

def read_file(name):
    # Lê e retorna o texto de um arquivo
    f = open(name, "r")
    text = f.read()
    f.close()

    return text

def hex_to_bin(hex_string):
    bin_string = []
    for char in hex_string:
        bin_char = bin(int(char, 16))[2:]
        padding = 8 - len(bin_char)
        bin_char = '0'*padding + bin_char
        bin_string.append(bin_char)
    result = ''.join(bin_string)

    return result

# def bin_to_hex(bin_string):

def main():
    """
    Função principal que ordena as chamadas de funções para realizar o que foi
    pedido no EP.
    """

    # print(MV_keygen())
    P = EC(200, 39)
    # P = (200, 39, 1)
    # R = EC(175, 80)
    R = (175, 80, 1)
    # print("(200, 39) pertence à curva?", POLY.substitute(x = 200, y = 39, z = 1) == 0)
    # print("Quantidas de de pontos em E:", EC.cardinality())
    # print("10 primeiros pontos de E:", firstElements(10))

    # print("(175, 80) pertence à curva?", POLY.substitute(x = 175, y = 80, z = 1) == 0)  

    # print("P + R = ", P + R)
    alice_keys = MV_keygen(10723944, P)
    public_key_alice = alice_keys[0]
    secret_key_alice = alice_keys[1]
    # print("Chave pública de Alice:", public_key_alice)
    # print("Chave secreta de Alice:", secret_key_alice)

    sum_pr_with_EC_rule = sum_points_with_EC_rule(P, R)
    # print("Soma P+R = ", sum_pr_with_EC_rule)

    Y = MV_encrypt(R, public_key_alice)
    # print("Criptografando R, Y =", Y)
    R = MV_decrypt(Y, secret_key_alice)
    # print("Decriptografando Y, R = ", R)

    nusp = '10723944'
    n = 4096
    random_bytes = generate_random_bytes(100)
    write_file_with_nusp('documento1', random_bytes, nusp)

    documento1 = read_file('documento1')
    doc1_bin = get_binary_representation_512_bits_of_hex(documento1[:n])
    cipher_text, points_y0s = CBC_MV_encrypt(doc1_bin[:n], public_key_alice)
    cipher_text = (''.join(cipher_text))
    decipher_text = CBC_MV_decrypt(cipher_text, secret_key_alice, points_y0s)
    decipher_text = ''.join(decipher_text)
    original = hex(int(doc1_bin[:n], 2))
    doc1_cript_inverso = hex(int(decipher_text, 2))
    doc1_cript = hex(int(cipher_text, 2))
    # 13
    # print("Decriptografando doc1-cript: ", doc1_cript_inverso)
    # 14
    # print("Distância de Hamming entre doc1-cript e doc1-cript-inverso:", hamming_distance_with_hex_strings(doc1_cript, doc1_cript_inverso))

    # 15
    nusp = '20723944'
    write_file_with_nusp('documento2', random_bytes, nusp)
    documento2 = read_file('documento2')
    doc2_bin = bin(int(documento2, 16))[2:]
    # 16
    doc2_cript, points_y0s = CBC_MV_encrypt(doc2_bin, public_key_alice)
    doc2_cript = ''.join(doc2_cript)
    print("doc2_cript: ", doc2_cript[:100])

    #17
    doc2_cript = hex(int(doc2_cript, 2))
    print("Distância de Hamming entre doc1_cript e doc2_cript", hamming_distance_with_hex_strings(doc2_cript, doc1_cript))

    #18
    secret_key_beto, public_key_beto = MV_keygen(99999999, P)
    print("Chaves de beto:", secret_key_beto, public_key_beto)

    #19
    # cipher_text, points_y0s = CBC_MV_encrypt(doc1_bin, public_key_beto)
    # print("Texto cifrado por beto:", cipher_text)

if __name__ == '__main__':
    main()
