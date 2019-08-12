#!/usr/bin/env python
# coding=utf-8

# @file oraclepadding.py
# @brief oraclepadding
# @author Anemone95,x565178035@126.com
# @version 1.0
# @date 2019-07-13 20:25
import subprocess
import logging
import copy
import sys
from multiprocessing import Pool
from contextlib import closing

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def get_loop_str(_len: int, alphabet: str) -> str:
    ret = ""
    for i in range(_len):
        ret += alphabet[i % len(alphabet)]
    return ret


def decode(secret: bytearray, iv: bytearray) -> int:
    cmd = "java -jar ./aesdemo/target/aesdemo-1.0-SNAPSHOT.jar decrypt {secret} keykeyke {iv}"\
        .format(secret=secret.hex(), iv=iv.hex())
    process = subprocess.Popen(cmd, shell=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    code = process.returncode  # 返回码
    if code != 0:
        return -1
    else:
        return code


def burp_iv_single_core(
        secret_block: bytearray,
        iv: bytearray,
        pos: int) -> int:
    for iv_byte in range(256):
        iv[pos] = iv_byte
        # 对java的函数的封装，当报错时返回-1。
        ret = DECODE_FUNC(secret_block, iv)
        logging.info("{0}::{1}".format(iv.hex(), ret))
        if ret != -1:
            return iv_byte


def burp_iv_with_iv_byte(args: [bytearray, bytearray, int, int]) -> int:
    secret_block, iv, pos, iv_byte = args
    ivv = copy.copy(iv)
    ivv[pos] = iv_byte
    # 对java的函数的封装，当报错时返回-1。
    ret = DECODE_FUNC(secret_block, ivv)
    logging.info("{0}::{1}".format(ivv.hex(), ret))
    return ret, iv_byte


def burp_iv_mulit_core(
        secret_block: bytearray,
        iv: bytearray,
        pos: int) -> int:
    args = [(secret_block, iv, pos, iv_byte) for iv_byte in range(256)]
    with closing(Pool(processes=10)) as p:
        res = p.map(burp_iv_with_iv_byte, args)
    res = list(filter(lambda e: e[0] != -1, res))
    iv_byte = res[0][1]
    logging.info("Get IV[{0}]: {1}".format(pos, "0x%02x" % iv_byte))
    return iv_byte


def update_iv(intermedi: bytearray, iv: bytearray, padding: int) -> bytearray:
    for i in range(1, padding + 1):
        iv[-i] = padding ^ intermedi[-i]
    return iv


def burp_intermediary(secret_block: bytearray, block_len: int) -> bytearray:
    intermedi = bytearray(block_len)
    fake_legal_iv = bytearray(block_len)
    for i in range(block_len - 1, -1, -1):
        padding = block_len - i
        legal_iv_byte = burp_iv(secret_block, fake_legal_iv, i)
        # 更新intermediary value
        intermedi_byte = padding ^ legal_iv_byte
        intermedi[i] = intermedi_byte
        # 更新iv
        padding += 1
        if padding <= block_len:
            update_iv(intermedi, fake_legal_iv, padding)
    logging.info("Get Intermediary Value: {}".format(intermedi.hex()))
    return intermedi


def decrypt_plain_block(intermedi: bytearray, iv: bytearray) -> bytearray:
    block_len = len(intermedi)
    plain = bytearray(block_len)
    for i in range(block_len):
        plain[i] = intermedi[i] ^ iv[i]
    logging.info("Get Plain Value: {}".format(plain.hex()))
    return plain


def decrypt(secret: bytearray, iv: bytearray) -> bytearray:
    plain = bytearray()
    block_len = len(iv)
    real_iv = iv
    for i in range(0, len(secret), block_len):
        block_secret = secret[i:i + block_len]
        intermedi = burp_intermediary(block_secret, block_len)
        plain += decrypt_plain_block(intermedi, real_iv)
        real_iv = secret[i:i + block_len]
    logging.info("Get Full Plain: {}".format(plain.hex()))
    return plain


def pkcs5(plain: bytearray, block_len: int) -> bytearray:
    padding_val = block_len - len(plain) % block_len
    for i in range(padding_val):
        plain += padding_val.to_bytes(1, 'little')
    return plain


def encrypt_block(secret_block: bytearray,
                  fake_plain: bytearray) -> (bytearray,
                                             bytearray):
    block_len = len(secret_block)
    if len(fake_plain) < block_len:
        fake_plain = pkcs5(fake_plain, block_len)

    intermedi = burp_intermediary(secret_block, block_len)
    iv = bytearray(block_len)
    for i in range(block_len):
        iv[i] = intermedi[i] ^ fake_plain[i]
    logging.info(
        "Fake IV: {0}, Secret: {1}".format(
            iv.hex(),
            secret_block.hex()))
    return iv, secret_block


def encrypt(plain: bytearray, block_len: int) -> (bytearray, bytearray):
    idxs = list(range(0, len(plain), block_len))
    secret = bytearray()
    secret_block = bytearray(block_len)
    for idx in idxs[::-1]:
        iv, secret_block = encrypt_block(secret_block, plain[idx:idx + block_len])
        secret = secret_block + secret
        secret_block = iv

    logging.info("IV: {0}, Secret: {1}".format(iv.hex(), secret.hex()))
    return iv, secret


def padding_oracle() -> bytearray:
    secret = bytearray.fromhex("c8c9c4f092468f9e75b520a3ea1832c0")
    real_iv = bytearray.fromhex("c86518374d219a7e")

    # 解密
    #  intermedi=burp_intermediary(secret, block_len)
    #  decrypt(secret, real_iv)

    # 加密
    fake_plain = bytearray("987654321", "ascii")
    encrypt(fake_plain, len(real_iv))


DECODE_FUNC = decode # Oracle function, -1 means padding exception

burp_iv = burp_iv_single_core

if __name__ == '__main__':
    logging.basicConfig(
        format='%(asctime)s : %(levelname)s : %(filename)s : %(funcName)s : %(message)s',
        level=logging.INFO)
    padding_oracle()
