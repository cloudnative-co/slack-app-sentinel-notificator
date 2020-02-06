# -*- coding: utf-8 -*-
# import module snippets
import error
import json
import requests
import Slack
import lambda_tools
import boto3
import datetime
import pytz
import urllib
from lambda_tools import invoke
from lambda_tools import print_json
from lambda_tools import kms_decrypted
from lambda_tools import get_lambda_info


def main_function(event, context):
    name = kms_decrypted("IGNORE_QUEUE")
    region = kms_decrypted("REGION", "ap-northeast-1")
    sqs = boto3.client('sqs', region_name=region)
    url = sqs.get_queue_url(QueueName=name)
    url = url["QueueUrl"]
    print_json({
       "type": "SQS",
       "message": "Search Message",
       "queue": name
    })
    while(True):
        result = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=10,
            VisibilityTimeout=30,
            WaitTimeSeconds=20,
            AttributeNames=["All"],
            MessageAttributeNames=["SystemAlertId"]
        )
        if "Messages" not in result:
            break
        if len(result["Messages"]) == 0:
            break
        print_json({
            "type": "lambda",
            "message": "Lambdaを再帰呼出しします",
            "payload": result
        })
        if lambda_tools.aws_request_id == "debug":
            lambda_handler(result, context)
        else:
            invoke(result)


def set_status(system_alert_id):
    """
    @brief      Logic Appにステータスを送信
    @params[in] system_alert_id     Azure SentinelのSystem Alert Id
    """
    url = kms_decrypted("LOGIC_APP_URL")
    method = "POST"
    headers = {"Content-Type": "application/json"}
    data = json.dumps({
        "SystemAlertId": system_alert_id,
    }).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, method=method, headers=headers
    )
    with urllib.request.urlopen(request) as response:
        result = False
        ret = {
            "type": "Logic App",
            "id": system_alert_id,
        }
        if response.status == 200:
            expires = response.getheader("Expires")
            if expires == "-1":
                ret["message"] = "Send Status(System Alert Id was Expired)"
            else:
                ret["message"] = "Send Status({})".format(response.msg)
                result = True
        else:
            ret["message"] = "Send Status({})".format(response.msg)

        ret["result"] = {
            "status": response.status,
            "reason": response.reason,
            "message": response.msg
        }
    print_json(ret)
    return result


def repost(message):
    body = json.loads(message['Body'])
    slack_api_token = kms_decrypted("SLACK_API_TOKEN")
    slack_bot_token = kms_decrypted("SLACK_BOT_TOKEN")
    channel_id = kms_decrypted("SLACK_CHANNEL_ID")
    slack_chat = Slack.Chat(token=slack_api_token)
    body["MessageId"] = message["MessageId"]
    username = body["Name"].replace('assumed-role/sso/', '')
    blocks = []
    blocks.append({
        "type": "section",
        "block_id": "alert",
        "text": {
            "type": "mrkdwn",
            "text": "@{}\nAzure Sentinel 警告通知".format(username)
        },
        "fields": [
            {"type": "mrkdwn", "text": "*アラート名*"},
            {"type": "mrkdwn", "text": body["AlertName"]},
            {"type": "mrkdwn", "text": "*アラート概要*"},
            {"type": "mrkdwn", "text": body["Description"]},
        ]
    })
    blocks.append({"type": "divider"})
    elements = []
    body["Status"] = True
    elements.append({
        "type": "button", "text": {"type": "plain_text", "text": "意図している"},
        "value": json.dumps(body)
    })
    body["Status"] = False
    elements.append({
        "type": "button",
        "text": {"type": "plain_text", "text": "心当たりがない"},
        "value": json.dumps(body)
    })
    blocks.append({
        "type": "actions",
        "elements": elements
    })
    post_args = {
        "channel": channel_id,
        "text": "Azure Sentinel 警告通知",
        "blocks": blocks,
        "link_names": True,
        "mrkdwn": True
    }
    print_json({
        "type": "Slack",
        "message": "メッセージ再送信",
        "channel-id": channel_id,
        "payload": post_args,
    })
    result = slack_chat.post_message(**post_args)


def check_messages(event):
    ja = pytz.timezone("Asia/Tokyo")
    nt = datetime.datetime.now(ja)
    nt = nt.timestamp() * 1000
    for message in event:
        body = json.loads(message['Body'])
        alert_id = message["MessageAttributes"]["SystemAlertId"]["StringValue"]
        sent_timestamp = int(message["Attributes"]["SentTimestamp"])
        stime = datetime.datetime.fromtimestamp(sent_timestamp / 1000, ja)
        stime = "{0:%Y-%m-%d %H:%M:%S}".format(stime)
        lapsed_time = nt - sent_timestamp
        msg = None

        if lapsed_time < 86400000:
            msg = "24時間未満"
        # 24時間以上48時間以下
        elif lapsed_time < 172800000:
            msg = "24時間経過"
            repost(message)
        # 48時間以上72時間以下
        elif lapsed_time < 259200000:
            msg = "48時間経過"
            repost(message)
        # 72時間以上
        else:
            msg = "72時間経過"
            set_status(alert_id)
        print_json({
            "type": "Lambda",
            "message": msg,
            "send_time": stime,
            "alert": body
        })


def lambda_handler(event, context):
    get_lambda_info(context, "sentinel-alert-crawler")
    print_json({
        "type": "lambda",
        "message": "イベント受信",
        "payload": event,
    })
    response_url = None
    try:
        if 'Messages' in event:
            check_messages(event["Messages"])
        else:
            main_function(event, context)
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {},
            "body": json.dumps({})
        }
    except Exception as e:
        print_json({
            "type": "lambda",
            "level": "error",
            "request-id": lambda_tools.aws_request_id,
            "message": str(e),
            "reason": error.exception_fail(e)
        })
        return {
            "isBase64Encoded": False,
            "statusCode": 502,
            "headers": {},
            "body": json.dumps({
                "text": str(e),
                "response_type": "in_channel"
            })
        }
