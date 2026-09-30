# Nodes-ops release (canonical)

**Production path: systemd + `/opt/nodes/current` only.**

Do not point `WorkingDirectory` at a dated release directory. Always:

1. Copy files into `/opt/nodes/releases/<stamp>/`
2. `ln -sfn /opt/nodes/releases/<stamp> /opt/nodes/current`
3. Ensure unit has `WorkingDirectory=/opt/nodes/current`
4. `systemctl daemon-reload && systemctl restart nodes-web`

Use `deploy/deploy_release.py` from a machine that can SSH to the host.

## compose.yml

`compose.yml` is for **local / lab** builds only. Production dashboard on
`YOUR_DOMAIN.example` / `YOUR_SERVER_IP` runs under systemd (`nodes-web`), not compose.
