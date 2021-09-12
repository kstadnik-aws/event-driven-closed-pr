import hashlib
import hmac
import json
import logging
import os
import time
import urllib.parse

import boto3
import requests
from botocore.client import ClientError

secretsmanager = boto3.client(service_name="secretsmanager")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def change_status(commit_sha, git_token, github_repo, state, target_url):
    """
    Change the status of commit

    Args:
        commit_sha ([str]): [sha of the commit involved in Pull Request]
        git_token ([str]): [GitHub personal access token]
        github_repo ([str]): [GitHub repository]
        state ([str]): [state (e.g. error, failure, pending or success) of the commit based on the result of the desired actions]
        target_url ([str]): [full URL to the lambda's current execution log stream]

    Returns:
        [status_code]: [status code of https POST request]
    """
    git_status = requests.post(
        f"https://api.github.com/repos/{github_repo}/statuses/{commit_sha}",
        headers={
            "Authorization": f"token {git_token}",
            "Accept": "application/vnd.github.v3+json",
        },
        data=json.dumps(
            {
                "context": "Github Check",
                "state": f"{state}",
                "target_url": f"{target_url}",
            }
        ),
    )
    return git_status.status_code


def lambda_handler(event, context):
    logger.info(event)
    # get environment variables
    webhook_secret_name = os.environ["webhook_secret_name"]
    github_secret_name = os.environ["github_secret_name"]
    pr_to_branch = os.environ["pr_to_branch"]
    region = os.environ["AWS_REGION"]
    lambda_log_group_name_encoded = urllib.parse.quote_plus(
        os.environ["AWS_LAMBDA_LOG_GROUP_NAME"]
    )
    lambda_stream_name_encoded = urllib.parse.quote_plus(
        os.environ["AWS_LAMBDA_LOG_STREAM_NAME"]
    )
    # security check
    secure = False
    if event["headers"].get("X-Hub-Signature-256", ""):
        try:
            webhook_secret = secretsmanager.get_secret_value(
                SecretId=webhook_secret_name
            )["SecretString"]
        except Exception as ex:
            raise Exception(f"Attempt to retrieve webhook secret failed: {ex}")
        k1 = hmac.new(
            str(webhook_secret).encode("utf-8"),
            str(event["body"]).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        k2 = str(event["headers"]["X-Hub-Signature-256"].replace("sha256=", ""))
        if k1 == k2:
            secure = True
    if secure == True:
        event_body = json.loads(event["body"])
        pull_request_info = event_body.get("pull_request", "")
        pull_request_action = event_body.get("action", "")
        logger.info(f"PR information: {pull_request_info}")
        logger.info(f"PR action: {pull_request_action}")
        if pull_request_info and pull_request_action:
            if (
                pull_request_info["base"]["ref"] == pr_to_branch
                and pull_request_action == "closed"
                and not pull_request_info["merged"]
            ):
                log_url = f"https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#logsV2:log-groups/log-group/{lambda_log_group_name_encoded}/log-events/{lambda_stream_name_encoded}"
                logger.info(f"Stream url: {log_url}")
                commit_sha = pull_request_info["head"]["sha"]
                github_repo = pull_request_info["head"]["repo"]["full_name"]
                github_repo_shortname = github_repo.split("/")[1]
                github_owner = pull_request_info["head"]["repo"]["owner"]["login"]
                pr_branch = (
                    github_repo_shortname + "/" + pull_request_info["head"]["ref"]
                )
                logger.info(f"Commit sha: {commit_sha}")
                logger.info(f"GitHub repository: {github_repo}")
                logger.info(f"GitHub owner: {github_owner}")
                logger.info(f"PR branch: {pr_branch}")
                try:
                    git_token = secretsmanager.get_secret_value(
                        SecretId=github_secret_name
                    )["SecretString"]
                except Exception as ex:
                    raise Exception(f"Attempt to retrieve github secret failed: {ex}")
                git_status = change_status(
                    commit_sha, git_token, github_repo, "pending", log_url
                )
                if git_status != 201:
                    raise Exception(
                        f"GitHub POST response return code is not 201 ({git_status})"
                    )
                # PERFORM YOUR NEEDED ACTIONS HERE
                # IF ACTIONS ARE PERFORMED SUCCESSFULLY -> SEND SUCCESS STATUS BACK TO COMMIT
                # this sleep here is only for testing purposes
                time.sleep(20)
                git_status = change_status(
                    commit_sha, git_token, github_repo, "success", log_url
                )
                if git_status != 201:
                    raise Exception(
                        f"GitHub POST response return code is not 201 ({git_status})"
                    )
                return {
                    "statusCode": 200,
                    "body": json.dumps("Request has been accepted"),
                }
            else:
                return {
                    "statusCode": 200,
                    "body": json.dumps(
                        "Request has been sent but nothing will be done because filter conditions are not met"
                    ),
                }
    else:
        return {"statusCode": 400, "body": json.dumps("Unauthorized request")}
