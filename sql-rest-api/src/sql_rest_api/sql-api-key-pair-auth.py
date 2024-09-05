from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import requests
import time
import hashlib
import jwt
import base64

# Key-pair authentication details
private_key_path = '<path to private key file>'  # Replace with your actual path
private_key_passphrase = '<passphrase>'  # If your private key has a passphrase, provide it here

# Snowflake connection details, provide account-identifier and username in UPPER CASE
connection_params = {
    "account": "<account-identifier>",
    "user": "<username>",
    "warehouse": "<warehouse>",
    "database": "<database>",
    "schema": "<schema>"
}

def execute_snowflake_query(query):
    """Executes a SQL query using the Snowflake SQL API and key-pair authentication."""

    # Load private key
    with open(private_key_path, "rb") as key:
        p_key = serialization.load_pem_private_key(
            key.read(),
            password=private_key_passphrase.encode() if private_key_passphrase else None,
            backend=default_backend()
        )

    # Get the public key fingerprint.
    public_key_raw = p_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    # Get the sha256 hash of the raw bytes.
    sha256hash = hashlib.sha256()
    sha256hash.update(public_key_raw)

    # Base64-encode the value and prepend the prefix 'SHA256:'.
    public_key_fp = 'SHA256:' + base64.b64encode(sha256hash.digest()).decode('utf-8')
    
    # 
    payload = {
        "iss": f"{connection_params['account']}.{connection_params['user']}.{public_key_fp}",  # Issuer
        "sub": f"{connection_params['account']}.{connection_params['user']}",  # Subject
        "iat": int(time.time()),  # Issued at time (current timestamp)
        "exp": int(time.time()) + 3600  # Expiration time (1 hour from now)
    }
    
    # Get the JWT token
    token = jwt.encode(payload, p_key, algorithm='RS256')

    api_url = f"https://{connection_params['account']}.snowflakecomputing.com/api/v2/statements"

    # Prepare the request headers
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT"
    }

    # Prepare the request body
    data = {
        "statement": query,
        "database": connection_params["database"],
        "schema": connection_params["schema"],
        "warehouse": connection_params["warehouse"]
    }

    # Make the POST request
    response = requests.post(api_url, headers=headers, json=data)

    # Handle the response
    if response.status_code == 200:
        # Get the statement handle from the response
        statement_handle = response.json()['statementHandle']

        # Construct the URL to get the query result
        result_url = f"https://{connection_params['account']}.snowflakecomputing.com/api/v2/statements/{statement_handle}"

        # Poll for the query result until it's ready
        while True:
            result_response = requests.get(result_url, headers=headers)
            if result_response.status_code == 200:
                # Extracting column name from json
                col_name_list = result_response.json()['resultSetMetaData']['rowType']
                col_name = []
                for col_dict in col_name_list:
                        col_name.append(col_dict['name'])
                print(col_name)
                # Extracting data from json
                result_data = result_response.json()['data']
                for row in result_data:
                    print(row)
                break
            elif result_response.status_code == 202:
                # Query is still running, wait and retry
                time.sleep(1)
            else:
                # Handle error
                print(f"Error: {result_response.status_code} - {result_response.text}")
                break
    else:
        # Handle error
        print(f"Error: {response.status_code} - {response.text}")


# Example usage
query = "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY order by event_timestamp desc limit 10"
execute_snowflake_query(query)