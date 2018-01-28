import boto3
import base64
import json
import time

def _kms_client():
    return boto3.client('kms')

def sign(kms_key_id, payload=dict()):
    header = {
        "alg": "KMS",
        "typ": "JWT"
    }

    pl = payload
    if not 'exp' in pl.keys():
        exiration = int(time.time()) + 5 * 60
        pl['exp'] = exiration

    if not 'iat' in pl.keys():
        issued_at = int(time.time())
        pl['iat'] = issued_at

    token_components = {
        "header": base64.b64encode(json.dumps(header).encode('ASCII')),
        "payload": base64.b64encode(json.dumps(pl).encode('ASCII'))
    }

    client = _kms_client()

    response = client.encrypt(
        KeyId=kms_key_id,
        Plaintext=base64.b64encode(
            "{}.{}".format(
                token_components["header"],
                token_components["payload"]
            ).encode('ASCII')
        )
    )
    
    token = "{}.{}.{}".format(
        token_components["header"],
        token_components["payload"],
        base64.b64encode(response['CiphertextBlob'])
    )

    return token

def verify(token):
    header = token.split('.')[0]
    payload = token.split('.')[1]
    signature = base64.b64decode(token.split('.')[2])
    client = _kms_client()

    iat = json.loads(base64.b64decode(payload).decode('utf-8'))['iat']
    exp = json.loads(base64.b64decode(payload).decode('utf-8'))['exp']

    if iat > int(time.time()):
        raise ValueError('Token was created before now')

    if exp < int(time.time()):
        raise ValueError('Token is expired')

    response = client.decrypt(
        CiphertextBlob=signature
    )

    if base64.b64decode(response['Plaintext']) == "{}.{}".format(header, payload):
        return "It's Valid"
    else:
        raise ValueError('Malformed Signature.')