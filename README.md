# Description
AWS CodeBuild does not natively support webhook triggers on GitHub PULL_REQUEST_CLOSED events. Currently, webhook filter groups can be used to specify which GitHub webhook events trigger a build. These events include PUSH, PULL_REQUEST_CREATED, PULL_REQUEST_UPDATED, PULL_REQUEST_REOPENED, and PULL_REQUEST_MERGED. A common use-case for intercepting closed pull request events is to perform cleanup actions in a CI/CD driven workflow.

The focus of this document is the design and implementation of a custom architecture to support intercepting GitHub PULL_REQUEST_CLOSED events to perform complex actions using AWS services based on this event.

