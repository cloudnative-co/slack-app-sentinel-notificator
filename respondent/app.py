# -*- coding: utf-8 -*-
# import module snippets
import error
import json
import lambda_tools
import boto3
import urllib.request
import Slack
from urllib.parse import parse_qs
from lambda_tools import invoke
from lambda_tools import print_json
from lambda_tools import kms_decrypted
from lambda_tools import get_lambda_info
from lambda_tools import verify_slack_signature


def remove_message(message_id, system_alert_id):
    """
    @brief      指定したMessageIdとSystemAlertIdに合致するSQSメッセージの削除
    @params[in] message_id      SQSのメッセージId
    @params[in] system_alert_id Azure SentinelのアラートID
    """
    name = kms_decrypted("IGNORE_QUEUE")
    region = kms_decrypted("REGION", "ap-northeast-1")
    sqs = boto3.resource('sqs', region_name=region)
    queue = sqs.get_queue_by_name(QueueName=name)
    id = None
    recipt_handle = None
    print_json({
       "type": "SQS",
       "message": "Search Message",
       "queue": name,
       "message_id": message_id,
    })
    while(True):
        result = queue.receive_messages(
            MaxNumberOfMessages=10,
            VisibilityTimeout=3,
            WaitTimeSeconds=20,
            MessageAttributeNames=["SystemAlertId"]
        )
        if len(result) == 0:
            break
        for msg in result:
            if message_id != msg.message_id:
                continue
            said = msg.message_attributes.get("SystemAlertId", None)
            if said is None:
                continue
            if system_alert_id != said["StringValue"]:
                continue

            receipt_handle = msg.receipt_handle
            print_json({
                "type": "SQS",
                "message": "Delete Message",
                'message_id': message_id,
                'receipt_handle': receipt_handle
            })
            response = queue.delete_messages(Entries=[{
                'Id': message_id,
                'ReceiptHandle': receipt_handle
            }])
            return True
    return False


def set_status(system_alert_id, status, message: str = None):
    """
    @brief      Logic Appにステータスを送信
    @params[in] system_alert_id     Azure SentinelのSystem Alert Id
    @params[in] status              ユーザー応答結果
    @n                              True : 意図している
    @n                              False: 覚えがない
    @params[in] message             理由テキスト
    """
    url = kms_decrypted("LOGIC_APP_URL")
    method = "POST"
    headers = {"Content-Type": "application/json"}
    data = {
        "SystemAlertId": system_alert_id,
        "UserResult": 0 if status else 1,
    }
    if message is not None:
        data["UserMessage"] = message
    ret = {
        "type": "Logic App",
        "id": system_alert_id,
        "payload": data,
        "status": status
    }
    data = json.dumps(data).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, method=method, headers=headers
    )
    with urllib.request.urlopen(request) as response:
        result = False
        ret["result"] = {
            "status": response.status,
            "reason": response.reason,
            "message": response.msg
        }
        if response.status == 200:
            result = True
            expires = response.getheader("Expires")
            if expires == "-1":
                ret["message"] = "Send Status(System Alert Id was Expired)"
            else:
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


def call_modal(event):
    """
    @brief      入力用Modal Viewの表示
    @params[in] event       イベントペイロード
    @details    メッセージ上のBlocksに表示されたボタンのaction_idが
    @n          answer_trueである場合に呼び出されます。
    @n          呼出元のBlocksのチャンネル情報とメッセージ情報を
    @n          private_metadataに格納しModal Viewを画面上に表示されます。
    """
    slack_api_token = kms_decrypted("SLACK_API_TOKEN")
    trigger_id = event["trigger_id"]
    action = event["actions"][0]
    action_value = action["value"]
    action_value = json.loads(action_value)
    data = json.dumps({
        "container": event["container"],
        "channel": event["channel"],
        "message": event["message"],
        "user": event["user"],
        "action_value": action_value
    })
    slack_views = Slack.Views(token=slack_api_token)
    view = {
        "type": "modal",
        "private_metadata": data,
        "callback_id": "modal_reason",
        "title": {"type": "plain_text", "text": "Azure Sentinel 通知"},
        "submit": {"type": "plain_text", "text": "Submit"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [{
            "type": "input",
            "block_id": "reason_input",
            "element": {
                "type": "plain_text_input", "multiline": True,
                "action_id": "reason_text"
            },
            "label": {"type": "plain_text", "text": "理由"}
        }]
    }
    slack_views.open(trigger_id, view)


def view_submission(event):
    """
    @brief      入力用Modal ViewからSubmitssion Callbackの受け取り
    @params[in] event       イベントペイロード
    @details    入力値を取得しprivate_metadataから呼出元メッセージを特定し
    @n          chat.update APIにて入力値を呼び出し元に反映します
    """
    view = event["view"]
    private_metadata = json.loads(view["private_metadata"])
    container = private_metadata["container"]
    message = private_metadata["message"]
    channel_id = container["channel_id"]
    blocks = message["blocks"]
    user = private_metadata["user"]
    action_value = private_metadata["action_value"]
    reason = view["state"]["values"]["reason_input"]["reason_text"]["value"]
    status = action_value["Status"]
    alert_id = action_value["SystemAlertId"]
    message_id = action_value["MessageId"]

    blocks[2] = {
        "type": "section",
        "block_id": "reason",
        "fields": [
            {"type": "mrkdwn", "text": "*応答*"},
            {"type": "mrkdwn", "text": "意図している"},
            {"type": "mrkdwn", "text": "*応答ユーザー*"},
            {"type": "mrkdwn", "text": user["username"]},
            {"type": "mrkdwn", "text": "*理由*"},
            {"type": "mrkdwn", "text": reason}
        ]
    }
    reason = "[{}]{}".format(user["username"], reason)
    result = set_status(alert_id, status, reason)
    if result:
        slack_api_token = kms_decrypted("SLACK_API_TOKEN")
        slack_chat = Slack.Chat(token=slack_api_token)
        post_args = {
            "channel": channel_id,
            "text": message["text"],
            "ts": message["ts"],
            "blocks": blocks,
        }
        print_json({
            "type": "Slack",
            "message": "Update Message",
            "metadata": post_args
        })
        slack_chat.update_message(**post_args)
        remove_message(message_id, alert_id)


def answer_false(event, action):
    value = action["value"]
    value = json.loads(value)
    print_json({
        "type": "Slack",
        "message": "Interactive Event Value",
        "value": value,
    })
    message = event["message"]
    alert_id = value["SystemAlertId"]
    user = event["user"],
    channel_id = event["container"]["channel_id"]
    blocks = message["blocks"]
    blocks[2] = {
        "type": "section",
        "block_id": "reason",
        "fields": [
            {"type": "mrkdwn", "text": "*応答*"},
            {"type": "mrkdwn", "text": "心当たりがない"},
            {"type": "mrkdwn", "text": "*応答ユーザー*"},
            {"type": "mrkdwn", "text": user[0]["username"]}
        ]
    }
    set_status(alert_id, False)
    slack_api_token = kms_decrypted("SLACK_API_TOKEN")
    slack_chat = Slack.Chat(token=slack_api_token)
    post_args = {
        "channel": channel_id,
        "text": message["text"],
        "ts": message["ts"],
        "blocks": blocks,
    }
    slack_chat.update_message(**post_args)


def block_actions(event):
    for action in event["actions"]:
        print_json({
            "type": "Slack",
            "message": "Interactive Event",
            "action": action
        })
        action_id = action["action_id"]
        if (action_id == "answer_true"):
            call_modal(event)
        elif (action_id == "answer_false"):
            answer_false(event, action)


def main_function(event):
    print_json({
        "type": "Slack",
        "message": "Interactive Event",
        "payload": event,
    })
    type = event["type"]
    if type == "view_submission":
        view_submission(event)
    elif type == "block_actions":
        block_actions(event)


def lambda_handler(event, context):
    get_lambda_info(context, "sentinel-alert-answer")
    print_json({
        "type": "lambda",
        "message": "イベント受信",
        "payload": event,
    })
    try:
        if 'body' in event:
            if lambda_tools.aws_request_id != "debug":
                verify_slack_signature(event)
            params = parse_qs(event['body'])
            print_json({
                "type": "lambda",
                "message": "Lambdaを再帰呼出しします",
                "payload": params,
            })
            if lambda_tools.aws_request_id == "debug":
                return lambda_handler(params, context)
            else:
                invoke(params)
        elif 'payload' in event:
            payload = event["payload"]
            payload = json.loads(payload[0])
            main_function(payload)
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {
                'content-type': 'application/json'
            },
            "body": ""
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
            "headers": {
                'content-type': 'application/json'
            },
            "body": json.dumps({
                "text": str(e),
                "response_type": "in_channel"
            })
        }
