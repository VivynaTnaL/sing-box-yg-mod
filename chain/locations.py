"""Select the manager state directory independently of the proxy runtime."""
from pathlib import Path

from chain import ConfigError, read_json


DEFAULT_STATE = Path('/etc/sing-box-addon')
MANAGER_SETTINGS = DEFAULT_STATE / 'manager.json'


def state_directory(value=None, settings_path=None):
    """Explicit CLI path wins; otherwise use the last installed directory."""
    if value is not None:
        return Path(value).expanduser().absolute()
    settings = Path(settings_path) if settings_path is not None else MANAGER_SETTINGS
    if settings.is_symlink():
        raise ConfigError('管理目录设置不能为符号链接：' + str(settings) +
                          '；请检查该路径，可用显式 --state 继续管理原部署')
    if not settings.exists():
        return DEFAULT_STATE
    if not settings.is_file():
        raise ConfigError('管理目录设置必须是普通文件：' + str(settings) +
                          '；请检查该路径，可用显式 --state 继续管理原部署')
    try:
        saved = read_json(settings)
        if not isinstance(saved, dict) or type(saved.get('schema_version')) is not int or saved['schema_version'] != 1:
            raise ValueError()
        directory = saved.get('state_dir')
        if not isinstance(directory, str) or not directory or '\0' in directory:
            raise ValueError()
        selected = Path(directory)
        if not selected.is_absolute():
            raise ValueError()
    except (OSError, ValueError, TypeError):
        raise ConfigError('管理目录设置无法读取或格式无效；可用 --state 指定原目录后重新 install') from None
    if selected.is_symlink() or not selected.is_dir():
        raise ConfigError('已保存的管理状态目录不存在或不可用：' + str(selected) +
                          '；请用 --state 指定原目录后重新 install')
    return selected
