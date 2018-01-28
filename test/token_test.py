import sys
sys.path.append('..')
from jwtkms import sign, verify
import pytest
from mock import mock
import time
import base64
import json

class MockKMSClient(object):
    def encrypt(*args, **kwargs):
        return {
            "CiphertextBlob": kwargs['Plaintext'][::-1]
        }
    
    def decrypt(*args, **kwargs):
        return {
            "Plaintext": kwargs['CiphertextBlob'][::-1]
        }

@mock.patch('jwtkms.token._kms_client')
def test_sign(mock_kms_client):
    mock_kms_client.return_value = MockKMSClient()
    test_payload = {
        "exp": 1517176973,
        "iat": 1517176973,
        "this_is": "a_test"
    }
    test_kms_key_id = 'a1b2c3-d4e5f6-g7h8i9-j0k1l2'
    response = sign(payload=test_payload, kms_key_id=test_kms_key_id)
    print response
    assert response == 'eyJhbGciOiAiS01TIiwgInR5cCI6ICJKV1QifQ==.eyJpYXQiOiAxNTE3MTc2OTczLCAidGhpc19pcyI6ICJhX3Rlc3QiLCAiZXhwIjogMTUxNzE3Njk3M30=.PT1RUHdNVFR6c21hT05UUjY1RWVWUlZUbjltYUpkSGFZcFZhQk5FVHBGMU1qeG1VemdGYUtOVVMya1VlakJYT3hNR2NvZEVacEYwUU1wM1lVOWtNalJWVHpVRVZPaFhRcDlVYVJoVld3cFVlbDVTUDlFbFpwRlZNV3RrU0Rsa05KTjBZMUlsYkpkMmRwbEVWeEF6VXBGVWFQbDJZSEpHYUtsWFo='

@mock.patch('jwtkms.token._kms_client')
def test_verify(mock_kms_client):
    mock_kms_client.return_value = MockKMSClient()
    test_kms_key_id = 'a1b2c3-d4e5f6-g7h8i9-j0k1l2'

    # Test for error on token from future
    with pytest.raises(ValueError) as e_info:
        tomorrow = int(time.time()) + (60 * 60 * 24)
        test_payload = {
            "this_is": "a_test",
            "iat": tomorrow
        }
        response = sign(payload=test_payload, kms_key_id=test_kms_key_id)
        verify(token=response)
    
    # Test for error on expired token
    with pytest.raises(ValueError) as e_info:
        yesterday = int(time.time()) - (60 * 60 * 24)
        test_payload = {
            "this_is": "a_test",
            "exp": yesterday
        }
        response = sign(payload=test_payload, kms_key_id=test_kms_key_id)
        verify(token=response)

    # Test for error on tampered token
    with pytest.raises(ValueError) as e_info:
        yesterday = int(time.time()) - (60 * 60 * 24)
        test_payload = {
            "this_is": "a_test",
        }
        response = sign(payload=test_payload, kms_key_id=test_kms_key_id)

        changed_payload = json.loads(base64.b64decode(response.split('.')[1]))
        changed_payload['this_is'] = 'an_attack'

        changed_jwt = response.split('.')
        changed_jwt[1] = base64.b64encode(json.dumps(changed_payload))
        changed_jwt = '.'.join(changed_jwt)
        verify(token=changed_jwt)

    # Test sucess case
    test_payload = {
        "this_is": "a_test",
    }
    response = sign(payload=test_payload, kms_key_id=test_kms_key_id)
    verify(token=response)   
    