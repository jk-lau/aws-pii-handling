

# Boto3 client for AWS services connecetion and action
import boto3

import json
import base64

# Fernet for symmetric data encryption and decryption
from cryptography.fernet import Fernet

# Pyspark package for UDF manipulation
from pyspark.sql.functions import udf, lit, md5
from pyspark.sql.types import StringType

import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from awsglue import DynamicFrame

# Set of PII Fields which Glue job will look up and perform AES encryption
pii_fields = {"Document_ID__c", "address", "Document_Type__c"}

# Secret Manager ARN stored encrypted data key
dk_sm_arn = ''

# Secret Manager ARN for Master Key KMS ARN
cmk_sm_arn = ''
region_name = 'us-east-1'

def decrypt_data_key(id, data_key_encrypted):
    """Decrypt an encrypted data key

    :param data_key_encrypted: Encrypted ciphertext data key.
    :return Plaintext base64-encoded binary data key as binary string
    :return None if error
    """

    # Decrypt the data key
    kms_client = boto3.client('kms')
    try:
        response = kms_client.decrypt(KeyId = id, CiphertextBlob = bytes(base64.b64decode(data_key_encrypted)))
    except e:
        raise Exception(e)
        return None

    # Return plaintext base64-encoded binary data key
    return base64.b64encode((response['Plaintext']))

def get_secret(secret_arn, region):

    # Create a Secrets Manager client
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

def jsonify(response):
    if type(response) == str:
        return json.loads(response)
    else:
        return response    

def sparkSqlQuery(glueContext, query, mapping, transformation_ctx) -> DynamicFrame:
    for alias, frame in mapping.items():
        frame.toDF().createOrReplaceTempView(alias)
    result = spark.sql(query)
    return DynamicFrame.fromDF(result, glueContext, transformation_ctx)

# Define Encrypt User Defined Function 
def encrypt_val(clear_text, MASTER_KEY):
    f = Fernet(MASTER_KEY)
    clear_text_b=bytes(clear_text, 'utf-8')
    cipher_text = f.encrypt(clear_text_b)
    cipher_text = str(cipher_text.decode('ascii'))
    return cipher_text
 
# Define decrypt user defined function 
def decrypt_val(cipher_text, MASTER_KEY):
    f = Fernet(MASTER_KEY)
    clear_val=f.decrypt(cipher_text.encode()).decode()
    return clear_val

# Register UDF's
encrypt = udf(encrypt_val, StringType())
decrypt = udf(decrypt_val, StringType())

args = getResolvedOptions(sys.argv, ['TempDir','JOB_NAME'])

sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args['JOB_NAME'], args)
needDataKey = False

# Create Spark DF for Source DC / File from parameter
DataSource0 = glueContext.create_dynamic_frame.from_options(
    format_options={},
    connection_type="s3",
    format="parquet",
    connection_options={
        "paths": [
            "s3://xxx"
        ],
        "recurse": True,
    },
    transformation_ctx="DataSource0",
)

plain_df = DataSource0.toDF()
wip_df = plain_df

# Start to lookup matched field names for AES encryption
for field in pii_fields:
    if field.upper() in (name.upper() for name in plain_df.columns):
        if not needDataKey:
            needDataKey = True
            response = jsonify(get_secret(dk_sm_arn, region_name))
            encrypted_dk = response["CiphertextBlob"]

            response = jsonify(get_secret(cmk_sm_arn, region_name))
            cmk_arn = response["ARN"]
            cmk_keyid = response["KeyId"]

            dk = decrypt_data_key(cmk_keyid, encrypted_dk)

        else:
            if len(dk) <= 0 :
                raise Exception ('Data Key is invalid.')

        wip_df = wip_df.withColumn(field, encrypt(field,lit(dk)))

TransformEncrypt0 = DynamicFrame.fromDF(wip_df, glueContext, "TransformEncrypt0")

DataSink0 = glueContext.write_dynamic_frame.from_options(
    frame=TransformEncrypt0,
    connection_type="s3",
    format="glueparquet",
    connection_options={
        "path": "s3://xxx/"
    },
    format_options={"compression": "snappy"},
    transformation_ctx="DataSink0",
)

job.commit()