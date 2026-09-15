#!/usr/bin/env python3
"""Optional daily GitHub rule refresh, independent of the proxy service."""
import json
from pathlib import Path
import sys

from chain import ConfigError
from runtime import Runtime, atomic_write

SERVICE = 'sing-box-addon-rules.service'
TIMER = 'sing-box-addon-rules.timer'
SETTINGS = Path('/etc/sing-box-addon/rules-update.json')


class Scheduler:
    def __init__(self, runtime=None):
        self.runtime = runtime or Runtime()
        self.settings = self.runtime.path(SETTINGS)
        self.service = self.runtime.path('/etc/systemd/system/' + SERVICE)
        self.timer = self.runtime.path('/etc/systemd/system/' + TIMER)

    def enable(self, state_dir):
        manager = self.runtime
        state_dir = Path(state_dir).absolute()
        if state_dir.is_symlink() or not (state_dir / 'state.json').is_file():
            raise ConfigError('请先初始化附件，再启用规则自动更新')
        if not manager.path('/opt/sing-box-addon/tool/scheduler.py').is_file():
            raise ConfigError('请先安装附件运行环境，再启用规则自动更新')
        manager.preflight()
        with manager.transaction(service=TIMER, files=[self.settings, self.service, self.timer], reload=True):
            atomic_write(self.settings, json.dumps({'version': 1, 'state': str(state_dir)}) + '\n')
            atomic_write(self.service, '''[Unit]
Description=Refresh independent sing-box addon client rules
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/sing-box-addon/tool/scheduler.py run
TimeoutStartSec=10min
NoNewPrivileges=yes
PrivateTmp=yes
UMask=0077
''', 0o644)
            atomic_write(self.timer, '''[Unit]
Description=Daily GeoIP and GeoSite update for sing-box addon

[Timer]
OnCalendar=daily
RandomizedDelaySec=30min
Persistent=true
Unit=sing-box-addon-rules.service

[Install]
WantedBy=timers.target
''', 0o644)
            manager._daemon_reload()
            manager._require('enable', service=TIMER)
            manager._require('start', service=TIMER)
        return self.status()

    def disable(self):
        manager = self.runtime
        with manager._lock():
            if self.timer.is_file():
                manager._require('stop', service=TIMER)
                manager._require('disable', service=TIMER)
            # Let an in-progress update finish its metadata/publication
            # transaction; stopping its process could interrupt that commit.
        return self.status()

    def status(self):
        return {**self.runtime.service_state(TIMER, strict=False), 'installed': self.timer.is_file()}


def run(settings_path=SETTINGS):
    from addon import Store
    from updates import update_rules
    path = Path(settings_path)
    if path.is_symlink():
        raise ConfigError('规则更新设置不能为符号链接')
    settings = json.loads(path.read_text())
    if settings.get('version') != 1 or not isinstance(settings.get('state'), str) or not Path(settings['state']).is_absolute():
        raise ConfigError('规则更新设置无效')
    store = Store(settings['state'])
    with store.locked():
        update_rules(store, scheduled=True)


if __name__ == '__main__':
    try:
        if sys.argv[1:] != ['run']:
            raise ConfigError('请通过 sb-chain rules-auto 管理规则定时更新')
        run()
    except (ConfigError, RuntimeError, OSError, ValueError):
        print('规则自动更新失败；保留上一份有效规则与订阅。可运行 sb-chain geodata 重试。', file=sys.stderr)
        sys.exit(1)
