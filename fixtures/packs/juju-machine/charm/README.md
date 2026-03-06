# Greentic Operator Machine Charm

## Deploy

`juju deploy ./charm greentic-operator`

## Integrate

- `juju integrate greentic-operator redis`
- `juju integrate greentic-operator ingress`
- `juju integrate greentic-operator observability`

## Upgrade

`juju refresh greentic-operator --path ./charm`

## Rollback guidance

Update charm config back to a prior bundle digest and re-run `juju config` or refresh to an earlier charm revision.

