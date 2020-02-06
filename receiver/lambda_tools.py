# -*- coding: utf-8 -*-
import json
import boto3
import botocore
import base64
import objectpath
import requests
import re
import os
import hmac
import hashlib
import datetime
import time
import sys

aws_request_id = None
function_name = None


kms = boto3.client(
    'kms',
    region_name=os.environ.get("REGION", "ap-northeast-1")
)
ssm = boto3.client(
    'ssm',
    region_name=os.environ.get("REGION", "ap-northeast-1")
)
lambda_client = boto3.client(
    'lambda',
    region_name=os.environ.get("REGION", "ap-northeast-1")
)


class ParameterException(Exception):
    message = None
    name = None
    reason = None

    def __init__(self, message, name=None, reason=None):
        self.message = message
        self.name = name
        self.reason = reason
        super(ParameterException, self).__init__(message)


def get_lambda_info(context, funcname_default):
    global function_name
    global aws_request_id
    if context is not None:
        aws_request_id = context.aws_request_id
        function_name = context.function_name
    else:
        aws_request_id = "debug"
        function_name = os.environ.get("FUNCTION_NAME", funcname_default)


def check_message(message, events=["FILE.UPLOADED"]):
    body = message.get("body", None)
    if body is None:
        raise ParameterException(
            message="Illegal provisioning format",
            name="body",
            reason="key not found in message"
        )
    try:
        body = json.loads(body)
    except Exception as e:
        raise ParameterException(
            message="Illegal provisioning format",
            name="body",
            reason="not json format"
        )
    for name in ["type", "id", "trigger", "source"]:
        value = body.get(name, None)
        if value is None:
            raise ParameterException(
                message="Illegal provisioning format",
                name=name,
                reason="key not found in body"
            )
    source = body.get("source", {})
    for name in ["id", "type", "name", "path_collection"]:
        value = source.get(name, None)
        if value is None:
            raise ParameterException(
                message="Illegal provisioning format",
                name=name,
                reason="key not found in source"
            )

    if body["type"] != "webhook_event":
        raise ParameterException(
            message="Illegal provisioning message",
            name="type",
            reason="event type is not webhook event",
        )
    trigger = body.get("trigger", None)
    if trigger not in events:
        raise ParameterException(
            message="The event which is not processed",
            name=trigger,
            reason="event type is not supported"
        )
    return body


def print_json(message):
    if isinstance(message, str) or isinstance(message, list):
        message = {
            "level": "info",
            "message": message
        }
    if isinstance(message, dict):
        if "level" not in message:
            message["level"] = "info"

    message["request-id"] = aws_request_id
    if aws_request_id == "debug":
        print(json.dumps(message, ensure_ascii=False, indent=4))
    else:
        if message["level"] == "debug":
            return
        print(json.dumps(message, ensure_ascii=False))


def response_code(body: dict):
    """
    @brief      BoxWebhook用レスポンスの返却
    @params[in] イベントBODY
    """
    if body is None:
        return {
            "statusCode": 500,
            "body": "Internal Server Error"
        }
    webhook_id = body.get("id", None)
    source = body.get("source", "{}")
    source_id = source.get("id", None)
    source_name = source.get("name", None)
    trigger = body.get("trigger")
    bd = 'webhook={}, trigger={}, source=<file id={} name="{}">'.format(
        webhook_id, trigger, source_id, source_name
    )
    print_json({
        "level": "debug",
        "message": "Webhook Response",
        "response": {
           "statusCode": 200,
           "body": bd,
           "isBase64Encoded": True
        }
    })
    return {
       "statusCode": 200,
       "body": bd,
       "isBase64Encoded": True
    }


def code_return(body: str = "", code=200) -> dict:
    return {
        'statusCode': code,
        'headers': {'content-type': 'application/json'},
        'body': body
    }


def get_ssm_path(path_name: str, to_snake: bool = True):
    def key_replace(s):
        tmp = s.replace(path_name, "")
        if to_snake:
            tmp = re.sub("([A-Z])", lambda x: "_" + x.group(1).lower(), tmp)
            return tmp[1:]
        return tmp

    def decrypt(encrypted):
        try:
            blob = base64.b64decode(encrypted)
            decrypted = kms.decrypt(CiphertextBlob=blob)['Plaintext']
            return decrypted.decode('utf-8')
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "InvalidCiphertextException":
                return encrypted
            raise e
        except base64.binascii.Error as e:
            return encrypted
        except ValueError as e:
            return encrypted
        except Exception as e:
            return default

    data = ssm.get_parameters_by_path(Path=path_name)
    ret = dict()
    tree = objectpath.Tree(data)
    query = "$..Parameters.Name"
    keys = list(tree.execute(query))
    keys = list(map(key_replace, keys))

    query = "$..Parameters.Value"
    values = list(tree.execute(query))
    values = list(map(decrypt, values))

    for idx in range(len(keys)):
        key = keys[idx]
        value = values[idx]
        ret[key] = value
    return ret


def kms_decrypted(key, default=None):
    if key not in os.environ:
        return default
    ENCRYPTED = os.environ[key]
    try:
        blob = base64.b64decode(ENCRYPTED)
        DECRYPTED = kms.decrypt(CiphertextBlob=blob)['Plaintext']
        return DECRYPTED.decode('utf-8')
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "InvalidCiphertextException":
            return ENCRYPTED
        raise e
    except base64.binascii.Error as e:
        return ENCRYPTED
    except ValueError as e:
        return ENCRYPTED
    except Exception as e:
        return default


def invoke(payload: dict):
    """
    @brief      Lambdaの再帰処理
    """
    global function_name
    try:
        lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='Event',
            Payload=json.dumps(payload)
        )
    except Exception as e:
        raise e


def slack_post(response_url, text):
    """
    @brief      SlackコマンドへのText返却用関数
    @params[in] response_url    Slackのresponse用URL
    @params[in] text            送信するメッセージ
    """
    if aws_request_id == "debug":
        print_json({
            "request-id": aws_request_id,
            "text": text
        })
    else:
        requests.post(
            response_url,
            json={
                "text": text,
                "response_type": "in_channel"
            }
        )

def verify_slack_signature(event):
    secretkey = kms_decrypted("SLACK_SIGNING_SECRET", None)
    if not secretkey:
        return Exception("Signing Secret not found")
    if "X-Slack-Request-Timestamp" not in event["headers"] \
        or "X-Slack-Signature" not in event["headers"]:
        raise Exception("Header Invalid")


    timestamp = event["headers"]["X-Slack-Request-Timestamp"]
    signature = event["headers"]["X-Slack-Signature"]

    if abs(time.time() - int(timestamp)) > 60 * 5:
        raise Exception("Timestamp Invalid")

    body = event["body"]
    message = "v0:{}:{}".format(timestamp, body)
    message_bytes = bytes(message, 'UTF-8')
    request_hash = 'v0=' + hmac.new(
        str.encode(secretkey),
        message_bytes,
        hashlib.sha256
    ).hexdigest()

    result = False
    if hasattr(hmac, "compare_digest"):
        if (sys.version_info[0] == 2):
            result = hmac.compare_digest(bytes(request_hash), bytes(signature))
        else:
            result = hmac.compare_digest(request_hash, signature)
    else:
        if len(request_hash) != len(signature):
            raise Exception("Signature invalid")
        result = 0
        if isinstance(request_hash, bytes) and isinstance(signature, bytes):
            for x, y in zip(request_hash, signature):
                result |= x ^ y
        else:
            for x, y in zip(request_hash, signature):
                result |= ord(x) ^ ord(y)
        result = result == 0

    if not result:
        raise Exception("Signature invalid")
    return result
