
import json
import urllib.request
import os

WEBHOOK_URL = os.environ['DISCORD_WEBHOOK_URL']

def lambda_handler(event, context):
    
    user = event['detail']['userIdentity']['arn']
    key_id = event['detail']['responseElements']['accessKey']['accessKeyId']
    
    message = f"""
🚨 AWS Alert: CreateAccessKey Detected

User: {user}
New AccessKeyId: {key_id}

Possible credential misuse detected.
"""

    data = json.dumps({"content": message}).encode("utf-8")
    
    req = urllib.request.Request(
        WEBHOOK_URL,
        data=data,
        headers={'Content-Type': 'application/json'}
    )
    
    urllib.request.urlopen(req)
    
    return {
        'statusCode': 200,
        'body': 'Alert sent'
    }
