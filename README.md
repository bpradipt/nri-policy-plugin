# NRI OPA Policy Plugin

This plugin adds [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) policy support to NRI. It evaluates incoming container creation requests against a user-supplied Rego policy, allowing or denying container creation based on the policy decision.

## Features

- Evaluates OPA policies on container creation events
- Passes container command line arguments, environment, and image as input to the policy
- Denies container creation if the policy returns `allow = false`

## Configuration

- `policyFile`: Path to the Rego policy file to load (required)
- `logFile`: Path to a log file (optional)
- `events`: List of NRI events to subscribe to (default: CreateContainer)

## Example Policy (policy.rego)

```rego
package nri

default allow = false

allow {
  not input.args[_] == "forbidden-arg"
}
```

## Usage

```sh
nri-opa-policy -policy-file /path/to/policy.rego -log-file /tmp/nri-opa.log
```

If the policy denies the container (returns `allow = false`), the container creation will be blocked. 