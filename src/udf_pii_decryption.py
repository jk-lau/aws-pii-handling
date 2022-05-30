import json
import os
import sys
import subprocess

import boto3
import base64
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# pip install custom package to /tmp/ and add to path
subprocess.call('pip install cryptography -t /tmp/ --no-cache-dir'.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
sys.path.insert(1, '/tmp/')

# import Fernet to implement AES decryption
from cryptography.fernet import Fernet

# Secret Manager ARN stored encrypted data key
dk_sm_arn = ''
# Secret Manager ARN for Master Key KMS ARN
cmk_sm_arn = ''
region_name = 'us-east-1'

# Function to return current datetime string
def current_dt():
    return datetime.now().strftime("%d/%m/%Y %H:%M:%S")

# Function to decrypt the data key
def decrypt_data_key(id, data_key_encrypted):
    """Decrypt an encrypted data key

    :param data_key_encrypted: Encrypted ciphertext data key.
    :return Plaintext base64-encoded binary data key as binary string
    :return None if error
    """

    kms_client = boto3.client('kms')
    try:
        # Decrypt the data key
        response = kms_client.decrypt(KeyId = id, CiphertextBlob = bytes(base64.b64decode(data_key_encrypted)))
    except e:
        raise Exception(e)
        return None

    # Return plaintext base64-encoded binary data key
    return base64.b64encode((response['Plaintext']))

# Function to access Secret Manager retriving necessary KMS arn
def get_secret(secret_arn, region):

    client = boto3.client("secretsmanager")

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId = secret_arn
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret

# Function to convert string to JSON
def jsonify(response):
    if type(response) == str:
        return json.loads(response)
    else:
        return response    
 
# Function to decrypt value
def decrypt_val(cipher_text, MASTER_KEY):
    f = Fernet(MASTER_KEY)
    clear_val=f.decrypt(cipher_text.encode()).decode()
    return clear_val
    
def lambda_handler(event, context):
    logger.info(str(current_dt()) + ' - Function start') 
    ret = dict()
    res = []
    response = jsonify(get_secret(dk_sm_arn, region_name))
    encrypted_dk = response["CiphertextBlob"]

    response = jsonify(get_secret(cmk_sm_arn, region_name))
    cmk_arn = response["ARN"]
    cmk_keyid = response["KeyId"]

    dk = decrypt_data_key(cmk_keyid, encrypted_dk)

    for argument in event['arguments']:
        val = argument[0]

        try:
            de_val = decrypt_val(val, dk)
        except:
            de_val = val
            logger.warning('Decryption for value failed: ' + str(val)) 
        res.append(json.dumps(de_val))
    
    ret['success'] = True
    logger.info(str(current_dt()) + ' - Function end successfully.') 
    ret['results'] = res
           
    return json.dumps(ret)
    