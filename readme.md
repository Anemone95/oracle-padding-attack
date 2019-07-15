# Usage

首先需要实现decode(secret: bytearray, iv: bytearray)->int方法，返回负值为padding exception。

```python
DECODE_FUNC=decode
```

## 解密

```python
secret=bytearray.fromhex("c8c9c4f092468f9e75b520a3ea1832c0")
real_iv=bytearray.fromhex("c86518374d219a7e")
intermedi=burp_intermediary(secret, block_len)
decrypt(secret, real_iv)
```

## 加密

```python
fake_plain=bytearray("987654321", "ascii")
encrypt(fake_plain, len(real_iv))
```

## 选择单线程

单线程有利于理解算法，但是不实用

```python
burp_iv=burp_iv_single_core
```

