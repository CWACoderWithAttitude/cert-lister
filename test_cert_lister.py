from keyword import issoftkeyword
import pytest
from cert_lister import parse_issuer

# Python3 code to demonstrate working of 
# Flatten Nested Tuples
# Using recursion + isinstance()

# helper function
def flatten(test_tuple):
    
    if isinstance(test_tuple, tuple) and len(test_tuple) == 2 and not isinstance(test_tuple[0], tuple):
        res = [test_tuple]
        return tuple(res)

    res = []
    for sub in test_tuple:
        res += flatten(sub)
    return tuple(res)


def test_parse_issuer_multiple_fields():
    issuer_tuple = (
        (('C', 'US'),),
        (('O', 'Example Org'),),
        (('CN', 'Example CA'),)
    )
    # The parse_issuer function expects each element to be a tuple of two elements, not a tuple containing a tuple.
    # So we need to flatten the structure:
    #flat_issuer_tuple = (('C', 'US'), ('O', 'Example Org'), ('CN', 'Example CA'))
    flat_issuer_tuple = flatten(issuer_tuple)
    assert parse_issuer(flat_issuer_tuple) == "C=US, O=Example Org, CN=Example CA"

def test_parse_issuer_empty():
    issuer_tuple = ()
    assert parse_issuer(issuer_tuple) == ""

def test_parse_issuer_single_field():
    issuer_tuple = (('CN', 'Root CA'),)
    assert parse_issuer(issuer_tuple) == "CN=Root CA"