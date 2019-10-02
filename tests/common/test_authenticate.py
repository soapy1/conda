# -*- coding: utf-8 -*-
# Copyright (C) 2019 Anaconda, Inc
# SPDX-License-Identifier: ❓UNDETERMINED
"""
This file tests the authenticate.py module.
"""

# 🔥Python2 Compatibility🔥
from __future__ import absolute_import, division, print_function, unicode_literals

from conda_build.authenticate import *

import pytest

# Some REGRESSION test data.
REG__KEYPAIR_NAME = 'keytest_old'
REG__PRIVATE_BYTES = b'\xc9\xc2\x06\r~\r\x93al&T\x84\x0bI\x83\xd0\x02!\xd8\xb6\xb6\x9c\x85\x01\x07\xdat\xb4!h\xf97'
REG__PUBLIC_BYTES = b"\x01=\xddqIb\x86m\x12\xba[\xae'?\x14\xd4\x8c\x89\xcf\x07s\xde\xe2\xdb\xf6\xd4V\x1eR\x1c\x83\xf7"
# Signature is over b'123456\x067890' using key REG__PRIVATE_BYTES.
REG__SIGNATURE = b'\xb6\xda\x14\xa1\xedU\x9e\xbf\x01\xb3\xa9\x18\xc9\xb8\xbd\xccFM@\x87\x99\xe8\x98\x84C\xe4}9;\xa4\xe5\xfd\xcf\xdaau\x04\xf5\xcc\xc0\xe7O\x0f\xf0F\x91\xd3\xb8"\x7fD\x1dO)*\x1f?\xd7&\xd6\xd3\x1f\r\x0e'
REG__HASHED_VAL = b'string to hash\n'
REG__HASH_HEX = '73aec9a93f4beb41a9bad14b9d1398f60e78ccefd97e4eb7d3cf26ba71dbe0ce'
#REG__HASH_BYTES = b's\xae\xc9\xa9?K\xebA\xa9\xba\xd1K\x9d\x13\x98\xf6\x0ex\xcc\xef\xd9~N\xb7\xd3\xcf&\xbaq\xdb\xe0\xce'
REG__REPODATA_HASHMAP = {
    "noarch/current_repodata.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
    "noarch/repodata.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
    "noarch/repodata_from_packages.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
    "osx-64/current_repodata.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
    "osx-64/repodata.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
    "osx-64/repodata_from_packages.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2"
}
REG__TEST_TIMESTAMP = '2019-10-01T00:00:00Z'
REG__TEST_EXPIRY_DATE = '2025-01-01T10:30:00Z'
REG__EXPECTED_UNSIGNED_REPODATA_VERIFY = {
    'type': 'repodata_verify', 'timestamp': REG__TEST_TIMESTAMP,
    'metadata_spec_version': '0.0.5', 'expiration': REG__TEST_EXPIRY_DATE,
    'secured_files': {
        'noarch/current_repodata.json': '908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe',
        'noarch/repodata.json': '908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe',
        'noarch/repodata_from_packages.json': '908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe',
        'osx-64/current_repodata.json': '8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2',
        'osx-64/repodata.json': '8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2',
        'osx-64/repodata_from_packages.json': '8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2'}
}
REG__EXPECTED_REGSIGNED_REPODATA_VERIFY = {
    # Re-sign this if its data changes: it's signed!
    'type': 'repodata_verify', 'timestamp': '2019-10-01T00:00:00Z',
    'metadata_spec_version': '0.0.5', 'expiration': '2025-01-01T10:30:00Z',
    'secured_files': {
        'noarch/current_repodata.json': '908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe',
        'noarch/repodata.json': '908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe',
        'noarch/repodata_from_packages.json': '908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe',
        'osx-64/current_repodata.json': '8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2',
        'osx-64/repodata.json': '8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2',
        'osx-64/repodata_from_packages.json': '8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2'}
}


# ⚠️ NOTE to dev:
#  test_authenticate is the single suite of integration tests in a single
#  function that I started with and have been pulling code out of to add to the
#  individual unit tests below.  Some I've removed, and some is now redundant.
def test_authenticate():



    # TODO: ✅ Test canonserialize individually.


    # Further test some helper functions.
    assert not is_hex_string_pubkey(loaded_old_public)
    assert not is_hex_string_pubkey(loaded_old_public_bytes)

    # Make a new keypair.  Returns keys and writes keys to disk.
    # Then load it from disk and compare that to the return value.  Exercise
    # some of the functions redundantly.
    generated_private, generated_public = gen_and_write_keys('keytest_new')
    loaded_new_private_bytes, loaded_new_public_bytes = keyfiles_to_bytes(
            'keytest_new')
    loaded_new_private, loaded_new_public = keyfiles_to_keys('keytest_new')
    assert keys_are_equivalent(generated_private, loaded_new_private)
    assert keys_are_equivalent(generated_public, loaded_new_public)
    assert keys_are_equivalent(
            loaded_new_private,
            private_key_from_bytes(loaded_new_private_bytes))
    assert keys_are_equivalent(
            loaded_new_public, public_key_from_bytes(loaded_new_public_bytes))


    # Clean up a bit for the next tests.
    new_private = loaded_new_private
    new_public = loaded_new_public
    old_private = loaded_old_private
    old_public = loaded_old_public
    del (
            loaded_new_public, loaded_new_private,
            loaded_old_private, loaded_old_public,
            generated_private, generated_public,
            loaded_new_private_bytes, loaded_new_public_bytes)







    # Test wrapping, signing signables, and verifying signables.
    d = {'foo': 'bar', '1': 2}
    d_modified = {'foo': 'DOOM', '1': 2}
    signable_d = wrap_as_signable(d)
    assert is_a_signable(signable_d)
    sign_signable(signable_d, old_private)
    assert is_a_signable(signable_d)

    verify_signable(
            signable=signable_d,
            authorized_pub_keys=[binascii.hexlify(key_to_bytes(old_public)).decode('utf-8')],
            threshold=1)

    # Expect failure this time due to bad format.
    try:
        verify_signable(
                signable=signable_d['signed'],
                authorized_pub_keys=[binascii.hexlify(key_to_bytes(old_public)).decode('utf-8')],
                threshold=1)
    except TypeError:
        pass
    else:
        assert False, 'Failed to raise expected exception.'

    # Expect failure this time due to non-matching signature.
    try:
        modified_signable_d = copy.deepcopy(signable_d)
        modified_signable_d['signed'] = d_modified
        verify_signable(
                signable=modified_signable_d,
                authorized_pub_keys=[binascii.hexlify(key_to_bytes(old_public)).decode('utf-8')],
                threshold=1)
    except SignatureError:
        pass
    else:
        assert False, 'Failed to raise expected exception.'

    # TODO: Run tests on the validation examples.


    # Test construction and verification of signed repodata_verify, including
    # wrapping, signing the signable, and verifying the signables with a real
    # example.
    repodata_hashmap = {
            "noarch/current_repodata.json":
            "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
            "noarch/repodata.json":
            "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
            "noarch/repodata_from_packages.json":
            "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
            "osx-64/current_repodata.json":
            "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
            "osx-64/repodata.json":
            "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
            "osx-64/repodata_from_packages.json":
            "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2"}

    rd_v_md = build_repodata_verification_metadata(repodata_hashmap)
    signable_rd_v_md = wrap_as_signable(rd_v_md)
    assert is_a_signable(signable_rd_v_md)
    sign_signable(signable_rd_v_md, old_private)
    assert is_a_signable(signable_rd_v_md)

    verify_signable(
            signable=signable_rd_v_md,
            authorized_pub_keys=[binascii.hexlify(key_to_bytes(old_public)).decode('utf-8')],
            threshold=1)

    # Expect failure this time due to non-matching signature.
    try:
        modified_signable_rd_v_md = copy.deepcopy(signable_rd_v_md)

        modified_signable_rd_v_md[
                'signed']['secured_files']['noarch/current_repodata.json'
                ] = modified_signable_rd_v_md['signed']['secured_files'][
                'noarch/current_repodata.json'][:-1] + 'f' # TODO: Generalize test condition. (Also, un-ugly.)

        verify_signable(
                signable=modified_signable_rd_v_md,
                authorized_pub_keys=[binascii.hexlify(key_to_bytes(old_public)).decode('utf-8')],
                threshold=1)
    except SignatureError:
        pass
    else:
        assert False, 'Failed to raise expected exception.'

    # DEBUG: 💥💥💥💥 Dump the various bits and pieces for debugging.
    #        Remove this.
    with open('/Users/vs/conda-build/conda_build/repodata_hashmap.json', 'wb') as fobj:
        fobj.write(canonserialize(repodata_hashmap))
    with open('/Users/vs/conda-build/conda_build/repodata_verify.json', 'wb') as fobj:
        fobj.write(canonserialize(signable_rd_v_md))


    # Additional regression test for a file produced by the indexer.
    # This should come up as good.
    verify_signable(
        signable={
          "signatures": {
            "013ddd714962866d12ba5bae273f14d48c89cf0773dee2dbf6d4561e521c83f7": "740a426113cb83a62e58eb41fcd0b5f36691b0b18bffbe7eb3da30b5baf83f6c703a0fdb584599702470c74f55572a27cf9de250fc3afb723c43fef4dc778401"
          },
          "signed": {
            "expiration": "2019-10-28T15:36:32Z",
            "metadata_spec_version": "0.0.4",
            "secured_files": {
              "noarch/current_repodata.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
              "noarch/repodata.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
              "noarch/repodata_from_packages.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
              "osx-64/current_repodata.json": "fc9268ea2b4add37e090b7f2b2c88b95c513cab445fb099e8631d8815a384ae4",
              "osx-64/repodata.json": "fc9268ea2b4add37e090b7f2b2c88b95c513cab445fb099e8631d8815a384ae4",
              "osx-64/repodata_from_packages.json": "fc9268ea2b4add37e090b7f2b2c88b95c513cab445fb099e8631d8815a384ae4"
            },
            "timestamp": "2019-09-27T15:36:32Z",
            "type": "repodata_verify"
          }
        },
        authorized_pub_keys=[binascii.hexlify(key_to_bytes(old_public)).decode('utf-8')],
        threshold=1)


    # Clean up a bit.
    for fname in [
            'keytest_new.pub', 'keytest_new.pri',
            'keytest_old.pri', 'keytest_old.pub']:
        if os.path.exists(fname):
            os.remove(fname)




def test_sha512256():
    # Test the SHA-512-truncate-256 hashing function w/ an expected result.
    assert sha512256(REG__HASHED_VAL) == REG__HASH_HEX


    # Test some helper functions.
    assert is_hex_string_pubkey('00' * 32)
    assert not is_hex_string_pubkey('00' * 31)
    assert not is_hex_string_pubkey('00' * 33)
    assert not is_hex_string_pubkey('00' * 64)
    assert not is_hex_string_pubkey('1g' * 32)
    assert not is_hex_string_pubkey(b'1g' * 32)




def test_build_repodata_verification_metadata():
    # Test only construction of (unsigned) repodata_verify.

    # Regression
    rd_v_md = build_repodata_verification_metadata(
            REG__REPODATA_HASHMAP,
            expiry=REG__TEST_EXPIRY_DATE,
            timestamp=REG__TEST_TIMESTAMP)
    assert rd_v_md == REG__EXPECTED_UNSIGNED_REPODATA_VERIFY

    # Bad-argument tests, expecting TypeErrors
    bad_hashmap = copy.deepcopy(REG__REPODATA_HASHMAP)
    bad_hashmap['some_filename'] = 'this is not a hash'

    with pytest.raises(TypeError):
        build_repodata_verification_metadata(bad_hashmap)
    with pytest.raises(TypeError):
        build_repodata_verification_metadata(5) # not a hashmap at all


    signable_rd_v_md = wrap_as_signable(rd_v_md)
    assert is_a_signable(signable_rd_v_md)
    sign_signable(signable_rd_v_md, old_private)
    assert is_a_signable(signable_rd_v_md)


# def test_set_expiry():
#     # Pull from old integration test below.

def test_key_functions():
    """
    Unit tests for functions:
        keyfiles_to_keys
        keyfiles_to_bytes
        key_to_bytes
        public_key_from_bytes
        private_key_from_bytes
        keys_are_equivalent
        gen_and_write_keys
        gen_keys
    """

    # Test keyfiles_to_keys and keyfiles_to_bytes
    # Regression: load old key pair, two ways.
    # First, dump them to temp files (to test keyfiles_to_keys).
    with open('keytest_old.pri', 'wb') as fobj:
        fobj.write(REG__PRIVATE_BYTES)
    with open('keytest_old.pub', 'wb') as fobj:
        fobj.write(REG__PUBLIC_BYTES)
    loaded_old_private_bytes, loaded_old_public_bytes = keyfiles_to_bytes(
            'keytest_old')
    loaded_old_private, loaded_old_public = keyfiles_to_keys('keytest_old')
    assert loaded_old_private_bytes == REG__PRIVATE_BYTES
    assert loaded_old_public_bytes == REG__PUBLIC_BYTES


    # Pull from old integration tests below.
    # Test key_to_bytes
    # Test public_key_from_bytes
    # Test private_key_from_bytes
    # Test keys_are_equivalent
    # Test gen_keys
    # Test gen_and_write_keys




def test_sign_and_verify():
    """
    Tests functions:
        - sign
        - verify_signature
    """

    # Test sign()

    old_private = private_key_from_bytes(REG__PRIVATE_BYTES)
    old_public = public_key_from_bytes(REG__PUBLIC_BYTES)
    new_private, new_public = gen_keys()

    message = b'123456\x067890'
    old_sig = sign(old_private, message)
    new_sig = sign(new_private, message)
    new_sig2 = sign(new_private, message)
    assert new_sig == new_sig2  # deterministic (obv not a thorough test)
    assert old_sig == REG__SIGNATURE # regression

    # Test verify()

    # Good signatures first.
    verify_signature(REG__SIGNATURE, old_public, message)
    verify_signature(old_sig, old_public, message)
    verify_signature(new_sig, new_public, message)

    # Use wrong public key.
    try:
        verify_signature(old_sig, new_public, message)
    except cryptography.exceptions.InvalidSignature:
        pass
    else:
        assert False, 'Did not catch an expected exception.'

    # Modify the data.
    try:
        verify_signature(new_sig, new_public, message + b'a')
    except cryptography.exceptions.InvalidSignature:
        pass
    else:
        assert False, 'Did not catch an expected exception.'
    try:
        verify_signature(new_sig, new_public, message[0:-1])
    except cryptography.exceptions.InvalidSignature:
        pass
    else:
        assert False, 'Did not catch an expected exception.'



# Pull these from old integration test above.
# def test_serialize_and_sign():
# def test_canonserialize():
# def test_wrap_as_signable():
# def test_is_a_signable():
# def test_is_hex_signature():
# def test_is_hex_string_pubkey():
# def test__is_hex_string():
# def test_sign_signable():
# def test_verify_signature():
# def test_verify_signable():
# def test_integration_repodata_verify():






def main():
    test_authenticate()


if __name__ == '__main__':
    main()
