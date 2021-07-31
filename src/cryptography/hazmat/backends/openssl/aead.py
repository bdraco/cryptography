# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


from cryptography.exceptions import InvalidTag


_ENCRYPT = 1
_DECRYPT = 0


def _aead_cipher_name(cipher):
    from cryptography.hazmat.primitives.ciphers.aead import (
        AESCCM,
        AESGCM,
        ChaCha20Poly1305,
    )

    if isinstance(cipher, ChaCha20Poly1305):
        return b"chacha20-poly1305"
    elif isinstance(cipher, AESCCM):
        return "aes-{}-ccm".format(len(cipher._key) * 8).encode("ascii")
    else:
        assert isinstance(cipher, AESGCM)
        return "aes-{}-gcm".format(len(cipher._key) * 8).encode("ascii")


def _create_ctx(backend):
    ctx = backend._lib.EVP_CIPHER_CTX_new()
    ctx = backend._ffi.gc(ctx, backend._lib.EVP_CIPHER_CTX_free)
    return ctx


def _set_cipher(backend, ctx, cipher_name, operation):
    evp_cipher = backend._lib.EVP_get_cipherbyname(cipher_name)
    backend.openssl_assert(evp_cipher != backend._ffi.NULL)
    res = backend._lib.EVP_CipherInit_ex(
        ctx,
        evp_cipher,
        backend._ffi.NULL,
        backend._ffi.NULL,
        backend._ffi.NULL,
        int(operation == _ENCRYPT),
    )
    backend.openssl_assert(res != 0)


def _set_key_and_nonce(backend, ctx, key, nonce, nonce_len, operation):
    res = backend._lib.EVP_CIPHER_CTX_ctrl(
        ctx,
        backend._lib.EVP_CTRL_AEAD_SET_IVLEN,
        nonce_len,
        backend._ffi.NULL,
    )
    backend.openssl_assert(res != 0)
    res = backend._lib.EVP_CIPHER_CTX_set_key_length(ctx, len(key))
    backend.openssl_assert(res != 0)
    key_ptr = backend._ffi.from_buffer(key)
    nonce_ptr = backend._ffi.from_buffer(nonce)
    res = backend._lib.EVP_CipherInit_ex(
        ctx,
        backend._ffi.NULL,
        backend._ffi.NULL,
        key_ptr,
        nonce_ptr,
        int(operation == _ENCRYPT),
    )
    backend.openssl_assert(res != 0)


def _set_key(backend, ctx, key, operation):
    res = backend._lib.EVP_CIPHER_CTX_set_key_length(ctx, len(key))
    backend.openssl_assert(res != 0)
    key_ptr = backend._ffi.from_buffer(key)
    res = backend._lib.EVP_CipherInit_ex(
        ctx,
        backend._ffi.NULL,
        backend._ffi.NULL,
        key_ptr,
        backend._ffi.NULL,
        int(operation == _ENCRYPT),
    )
    backend.openssl_assert(res != 0)


def _set_tag(backend, ctx, cipher_name, tag, tag_len, operation):
    if operation == _DECRYPT:
        res = backend._lib.EVP_CIPHER_CTX_ctrl(
            ctx, backend._lib.EVP_CTRL_AEAD_SET_TAG, len(tag), tag
        )
        backend.openssl_assert(res != 0)
    elif cipher_name.endswith(b"-ccm"):
        res = backend._lib.EVP_CIPHER_CTX_ctrl(
            ctx, backend._lib.EVP_CTRL_AEAD_SET_TAG, tag_len, backend._ffi.NULL
        )
        backend.openssl_assert(res != 0)


def _set_nonce(backend, ctx, nonce, operation):
    nonce_ptr = backend._ffi.from_buffer(nonce)
    res = backend._lib.EVP_CipherInit_ex(
        ctx,
        backend._ffi.NULL,
        backend._ffi.NULL,
        backend._ffi.NULL,
        nonce_ptr,
        int(operation == _ENCRYPT),
    )
    backend.openssl_assert(res != 0)


def _aead_setup_with_nonce(
    backend, cipher_name, key, nonce, tag, tag_len, operation
):
    ctx = _create_ctx(backend)
    _set_cipher(backend, ctx, cipher_name, operation)
    _set_key_and_nonce(backend, ctx, cipher_name, key, nonce, operation)
    _set_tag(backend, ctx, cipher_name, tag, tag_len, operation)
    return ctx


def _aead_setup(backend, cipher_name, key, tag, tag_len, operation):
    ctx = _create_ctx(backend)
    _set_cipher(backend, ctx, cipher_name, operation)
    _set_key(backend, ctx, cipher_name, key, operation)
    _set_tag(backend, ctx, cipher_name, tag, tag_len, operation)
    return ctx


def _set_length(backend, ctx, data_len):
    intptr = backend._ffi.new("int *")
    res = backend._lib.EVP_CipherUpdate(
        ctx, backend._ffi.NULL, intptr, backend._ffi.NULL, data_len
    )
    backend.openssl_assert(res != 0)


def _process_aad(backend, ctx, associated_data):
    outlen = backend._ffi.new("int *")
    res = backend._lib.EVP_CipherUpdate(
        ctx, backend._ffi.NULL, outlen, associated_data, len(associated_data)
    )
    backend.openssl_assert(res != 0)


def _process_data(backend, ctx, data):
    outlen = backend._ffi.new("int *")
    buf = backend._ffi.new("unsigned char[]", len(data))
    res = backend._lib.EVP_CipherUpdate(ctx, buf, outlen, data, len(data))
    backend.openssl_assert(res != 0)
    return backend._ffi.buffer(buf, outlen[0])[:]


def _encrypt(backend, cipher, nonce, data, associated_data, tag_length):
    ctx = _aead_setup_with_nonce(
        backend,
        _aead_cipher_name(cipher),
        cipher._key,
        nonce,
        None,
        tag_length,
        _ENCRYPT,
    )
    return _encrypt_data(
        backend, ctx, cipher, data, associated_data, tag_length
    )


def _encrypt_data(backend, ctx, cipher, data, associated_data, tag_length):
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    # CCM requires us to pass the length of the data before processing anything
    # However calling this with any other AEAD results in an error
    if isinstance(cipher, AESCCM):
        _set_length(backend, ctx, len(data))

    _process_aad(backend, ctx, associated_data)
    processed_data = _process_data(backend, ctx, data)
    outlen = backend._ffi.new("int *")
    res = backend._lib.EVP_CipherFinal_ex(ctx, backend._ffi.NULL, outlen)
    backend.openssl_assert(res != 0)
    backend.openssl_assert(outlen[0] == 0)
    tag_buf = backend._ffi.new("unsigned char[]", tag_length)
    res = backend._lib.EVP_CIPHER_CTX_ctrl(
        ctx, backend._lib.EVP_CTRL_AEAD_GET_TAG, tag_length, tag_buf
    )
    backend.openssl_assert(res != 0)
    tag = backend._ffi.buffer(tag_buf)[:]

    return processed_data + tag


def _tag_from_data(data, tag_length):
    if len(data) < tag_length:
        raise InvalidTag
    return data[-tag_length:]


def _decrypt(backend, cipher, nonce, data, associated_data, tag_length):
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    tag = _tag_from_data(data, tag_length)
    data = data[:-tag_length]

    ctx = _aead_setup_with_nonce(
        backend,
        _aead_cipher_name(cipher),
        cipher._key,
        nonce,
        tag,
        tag_length,
        _DECRYPT,
    )

    if isinstance(cipher, AESCCM):
        return _decrypt_data_aesccm(backend, ctx, data, associated_data)

    return _decrypt_data(backend, ctx, data, associated_data)


def _decrypt_data_aesccm(backend, ctx, data, associated_data):
    # CCM requires us to pass the length of the data before processing anything
    # However calling this with any other AEAD results in an error
    _set_length(backend, ctx, len(data))

    _process_aad(backend, ctx, associated_data)
    # CCM has a different error path if the tag doesn't match. Errors are
    # raised in Update and Final is irrelevant.
    outlen = backend._ffi.new("int *")
    buf = backend._ffi.new("unsigned char[]", len(data))
    res = backend._lib.EVP_CipherUpdate(ctx, buf, outlen, data, len(data))
    if res != 1:
        backend._consume_errors()
        raise InvalidTag
    return backend._ffi.buffer(buf, outlen[0])[:]


def _decrypt_data(backend, ctx, data, associated_data):
    _process_aad(backend, ctx, associated_data)
    processed_data = _process_data(backend, ctx, data)
    outlen = backend._ffi.new("int *")
    res = backend._lib.EVP_CipherFinal_ex(ctx, backend._ffi.NULL, outlen)
    if res == 0:
        backend._consume_errors()
        raise InvalidTag

    return processed_data
