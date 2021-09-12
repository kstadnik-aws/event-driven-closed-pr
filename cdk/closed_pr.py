#!/usr/bin/env python3

import os

from aws_cdk import aws_apigateway as apigateway
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import core
from aws_cdk.aws_secretsmanager import SecretStringGenerator


class ClosedPREventStack(core.Stack):
    """
    A CDK Stack that creates Lambda function,
    API Gateway and generates a secret that will be used as
    a webhook secret.
    """

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        webhook_secret_name = self.node.try_get_context("pWebhookSecretName")
        github_secret_name = self.node.try_get_context("pGitHubAcessTokenSecretName")
        pr_to_branch = self.node.try_get_context("pPrToBranch")


        # create webhook secret (randomly generated)
        webhook_secret = secretsmanager.Secret(
            scope=self,
            id="WebHookSecret",
            description="Webhook secret that ensures POST requests sent to the payload URL are from GitHub",
            generate_secret_string=SecretStringGenerator(),
            secret_name=webhook_secret_name,
        )

        lambda_webhook_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "lambda")
        )

        lambda_function = aws_lambda.Function(
            scope=self,
            id="LambdaWebhookEvent",
            function_name="webhook-event",
            code=aws_lambda.Code.from_asset(path=lambda_webhook_dir),
            memory_size=1024,
            timeout=core.Duration.seconds(5 * 60),
            environment={
                "pr_to_branch": pr_to_branch,
                "webhook_secret_name": webhook_secret_name,
                "github_secret_name": github_secret_name,
            },
        )
        lambda_function.role.add_to_policy(
            iam.PolicyStatement(
                actions=["secretsmanager:GetSecretValue"],
                effect=iam.Effect.ALLOW,
                resources=[
                    core.Fn.import_value(
                        shared_value_to_import="GitHubAccessTokenSecret"
                    ),
                    webhook_secret.secret_arn,
                ],
            )
        )

        # create an API
        api_gateway = apigateway.RestApi(
            self,
            id="ApiGateway",
            rest_api_name="close-pr-webhook-event",
            endpoint_types=[apigateway.EndpointType.REGIONAL],
            deploy_options={"stage_name": "prod"},
            endpoint_export_name="webhook-event-apigateway-endpoint",
            policy=iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=["execute-api:Invoke"],
                    resources=["execute-api:/prod/POST/"],
                    effect=iam.Effect.ALLOW,
                    principals=[iam.AnyPrincipal()],
                )
            ]
        ),
        )
        api_lambda_integration = apigateway.LambdaIntegration(
            lambda_function, proxy=True
        )
        api_gateway.root.add_method("POST", api_lambda_integration)

app = core.App()


ClosedPREventStack(
    scope=app, id=f"closed-pr-event-stack"
)

app.synth()
