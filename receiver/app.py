# -*- coding: utf-8 -*-
# import module snippets
import error
import json
import requests
import Slack
import lambda_tools
import Slack.Util
import boto3
from time import sleep
from urllib.parse import parse_qs
from lambda_tools import invoke
from lambda_tools import print_json
from lambda_tools import kms_decrypted
from lambda_tools import get_lambda_info
from lambda_tools import verify_slack_signature


def set_ignore_queue(message):
    body = json.loads(message)
    name = kms_decrypted("IGNORE_QUEUE")
    system_alert_id = body["SystemAlertId"]
    region = kms_decrypted("REGION", "ap-northeast-1")
    sqs = boto3.resource('sqs', region_name=region)
    try:
        queue = sqs.get_queue_by_name(QueueName=name)
    except Exception as e:
        queue = sqs.create_queue(QueueName=name)
    queue.set_attributes(
        Attributes={
            'ReceiveMessageWaitTimeSeconds': '20',
            'VisibilityTimeout': '30'
        }
    )
    print_json({
        "type": "SQS",
        "message": "Send Message",
        "queue": name,
        "payload": message
    })
    result = queue.send_message(
        MessageBody=message,
        MessageAttributes={
            "SystemAlertId": {
                "StringValue": system_alert_id,
                'DataType': 'String'
            }
        }
    )
    message_id = result["MessageId"]
    return message_id


def main_function(events):
    slack_api_token = kms_decrypted("SLACK_API_TOKEN")
    slack_bot_token = kms_decrypted("SLACK_BOT_TOKEN")
    channel_id = kms_decrypted("SLACK_CHANNEL_ID")
    slack_chat = Slack.Chat(token=slack_api_token)
    for event in events:
        body = event.get("body", None)
        if body is None:
            continue
        id = set_ignore_queue(body)
        body = json.loads(body)
        username = body["Name"].replace('assumed-role/sso/', '')
        body["MessageId"] = id
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
            "action_id": "answer_true",
            "type": "button", "text": {"type": "plain_text", "text": "意図している"},
            "value": json.dumps(body)
        })
        body["Status"] = False
        elements.append({
            "action_id": "answer_false",
            "type": "button",
            "text": {"type": "plain_text", "text": "心当たりがない"},
            "value": json.dumps(body)
        })
        blocks.append({
            "block_id": "answer",
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
            "message": "メッセージ送信",
            "channel-id": channel_id,
            "payload": post_args,
        })
        result = slack_chat.post_message(**post_args)


def lambda_handler(event, context):
    get_lambda_info(context, "sentinel-alert-receiver")
    print_json({
        "type": "lambda",
        "message": "イベント受信",
        "payload": event,
    })
    response_url = None
    try:
        if 'Records' in event:
            params = event['Records']
            print_json({
                "type": "lambda",
                "message": "Lambdaを再帰呼出しします",
                "payload": params,
            })
            if lambda_tools.aws_request_id == "debug":
                return lambda_handler(params, context)
            else:
                invoke(params)
        else:
            main_function(event)
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {},
            "body": json.dumps({
                "response_type": "in_channel"
            })
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
