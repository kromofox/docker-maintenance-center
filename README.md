# docker-maintenance-center

通过中文 WebUI 和 Telegram 管理已有 Docker Compose 项目的更新。单管理员、单实例、SQLite 状态；应用容器不挂载 Docker Socket。真实维护通过 SSH 固定命令和受限 sudo 宿主网关执行。

## 支持范围与风险

- Linux 宿主，系统 `/usr/bin/python3` 为 3.12 或更新版本，系统 PyYAML（如 Ubuntu 的 python3-yaml 包），Docker Engine 与 Compose **v2**，OpenSSH server、sudo、visudo。
- 发现已经运行的 Compose 服务，预检后接管；支持自动、人工批准、仅通知策略。解除接管不停止容器、不删除业务数据。
- 计划短时有效、一次消费；更新前核对 Compose、运行状态和镜像身份。失败或结果未知会停写，不自动重放。
- **通用适配器不做数据备份、自动回滚或数据库恢复。** 接管必须明确确认备份豁免风险；请自行维护经过恢复演练的业务备份。保留旧镜像不等于可安全降级数据库。
- 更新可能中断服务。Web 可在确认接管前选择 manual/notify；Telegram 添加采用明确确认后的 auto 策略，首次检查可能立即更新，即使周期调度暂停。
- 默认只读 shadow 模式；主动修改为 active 后才开放维护。默认不接管任何真实项目。
- 仅用于受信任局域网，HTTP 不提供传输加密，禁止公网暴露。当前不支持 HTTPS 反向代理模式，不信任转发头。远程使用可信 VPN。
- 仅管理已经由管理员信任的 Compose 配置。目录与配置必须 root 所有，父路径不能是符号链接或允许其他用户写入。不是多租户容器隔离工具。
- 不支持 Swarm/Kubernetes、构建型 image、Compose hooks、多副本服务及无法绑定的外部配置输入；预检拒绝时不要绕过检查。没有任意 Shell、Compose 编辑或独立重启入口。

## 安装

以下操作由 Linux 宿主管理员执行。应用目录必须放在允许发现的业务目录之外。示例 `/srv/compose` 仅用于已有业务 Compose，不要放入维护中心自身配置、凭据和状态。

### 1. 准备专用 SSH 账户与宿主网关

创建一个可用公钥登录、没有其他用途的账户（示例名 maintenance）。不加入 docker/sudo/wheel/admin 组，不授予通用 sudo。关闭该账户密码登录，删除其他登录密钥。账户需要可执行 forced-command 的 shell；不要设置为 nologin。

安装系统依赖后，在本仓库根目录运行预检，然后安装：

```sh
sudo /usr/bin/python3 host/install.py check \
  --gateway-user maintenance --docker-path /usr/bin/docker --allowed-root /srv/compose
sudo /usr/bin/python3 host/install.py install \
  --gateway-user maintenance --docker-path /usr/bin/docker --allowed-root /srv/compose
```

`--docker-path` 必须是 root 所有的真实可执行文件路径，不能是符号链接。允许多个 `--allowed-root`。安装器不会安装系统包、接管项目或触发更新。它创建 root-only 空注册表、宿主状态目录和只允许无参数网关命令的 sudoers，并在生效前通过 visudo 校验。

安装位置：`/usr/local/libexec/docker-maintenance-center`；非敏感宿主策略：`/etc/docker-maintenance-center/host.json`；注册表：同目录 `registry.json`；默认宿主状态：`/var/lib/docker-maintenance-center/host`。

安装器只支持首次安装。失败时不要覆盖已有注册表/状态；先检查部分落盘和 sudoers，人工修复后重试。应用和宿主升级应停调度、等待操作结束、备份状态并审查变更，不允许重跑首次安装覆盖现场。

### 2. 构建应用与准备本地文件

```sh
docker build -t docker-maintenance-center:0.1.0 .
mkdir -p state config secrets
cp examples/runtime.json config/runtime.json
ssh-keygen -t ed25519 -N '' -f secrets/gateway_ed25519
```

修改 `config/runtime.json`：两处示例 IP 改为真实私网 IPv4；设置 SSH 用户/端口；保持 `mode=shadow`。端口 `8767` 是示例 Compose 映射端口，若修改，必须同时修改 runtime、Compose 和浏览器地址。

将 `secrets/gateway_ed25519.pub` 公钥加入专用宿主账户的 `authorized_keys`，前缀必须完整保留：

```text
restrict,command="/usr/local/libexec/docker-maintenance-center/active_dispatch.py" ssh-ed25519 YOUR_ACTUAL_PUBLIC_KEY
```

该行的实际 key 来自本机生成的 `.pub` 文件，不能复制示例占位文本。没有专用公钥和 forced-command 限制不得启用应用。不要把私钥提交到 Git。

从宿主控制台核对 SSH host key 指纹；经可信渠道取得公钥后写入 `secrets/known_hosts`，左侧必须使用配置中的别名，例如：

```text
docker-maintenance-center ssh-ed25519 VERIFIED_HOST_PUBLIC_KEY
```

`ssh-keyscan` 只能采集候选公钥，不提供真实性保证。不要关闭 StrictHostKeyChecking。

生成 Telegram 加密密钥并设置文件权限（密钥不输出到终端）：

```sh
docker run --rm --user 0:0 --entrypoint python \
  -v "$PWD/secrets:/keys" docker-maintenance-center:0.1.0 \
  -c 'import os; from cryptography.fernet import Fernet; fd=os.open("/keys/telegram.key",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(fd,Fernet.generate_key()); os.close(fd)'
sudo chown -R 10001:10001 state secrets
sudo chmod 700 state secrets
sudo chmod 600 secrets/gateway_ed25519 secrets/telegram.key
sudo chmod 644 secrets/known_hosts config/runtime.json
```

不要更改或丢失已投入使用的 Telegram 加密密钥；密钥丢失需要重新配置 Token，旧备份不可解密。应用 UID/GID 为 10001，与宿主 gateway 账户 UID 无需相同。

### 3. 初始化和只读启动

设置绑定地址，必须与 runtime 中的 address 一致：

```sh
export DMC_BIND_ADDRESS=192.168.50.10
# 服务停止时执行；短时初始化码只显示在自己的终端，不粘贴到工单。
docker compose run --rm --no-deps maintenance --state-dir /state --issue-code initialize
docker compose up -d
```

在 `http://你的私网IP:8767/initialize` 输入初始化码，设置管理员账户。无默认密码。忘记密码：先停止服务，再将上述 initialize 换成 recover；恢复会撤销旧会话。

确认只读连接、宿主账号与信任边界后，停止应用，将 runtime 的 mode 改为 active，再启动。Web「项目管理」发现业务、只读预检、选择策略和健康检查、确认风险后接管。

Telegram：在 Web 设置页输入 Bot Token，验证成功后生成绑定码，在 Bot 私聊绑定。仅绑定的数字用户/私聊有权限；支持 `/status`、`/projects`、`/set`、`/check`、`/resume`、`/help`。不承诺恰好一次消息送达；回复超时可能产生重复文字，但不会重跑已执行业务。

## 故障和恢复

维护中心重启后会对账，不复活旧批准。unknown 不是成功，也不是可以安全重试。先暂停计划并由宿主管理员调查业务容器、数据与镜像；必要时在带外恢复业务。

对 generic unknown 操作，root 管理员可以生成只读审查摘要：

```sh
sudo /usr/local/libexec/docker-maintenance-center/recover.py review \
  --project PROJECT_ID --operation-ref OPERATION_REF
```

仅在现场修复/调查完成且健康检查通过后，使用该次返回的 `review_digest`：

```sh
sudo /usr/local/libexec/docker-maintenance-center/recover.py resolve \
  --project PROJECT_ID --operation-ref OPERATION_REF \
  --expected-review REVIEW_DIGEST \
  --evidence 'Describe actual investigation and verified recovery evidence; do not include credentials.' \
  --acknowledge-no-data-recovery
```

它保留未知证据，将操作结为 **failed/manually_reviewed**，不改写为成功、不执行更新、不恢复数据。回到 Web 对账，然后显式恢复该项目自动维护。现场变化会使摘要失效，需要重新审查。

应用 state 与 secrets、宿主 registry 与 host-state 都是私密恢复材料，应在无运行/未知操作时停止应用和宿主入口后做一致性备份。不要复制运行中的 SQLite 文件冒充一致性备份；不要只恢复一个数据库或覆盖历史回执。恢复后先 shadow 对账，未确认前不要启用调度。

## 开发与演示

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --only-binary=:all: --require-hashes -r requirements.lock
python -m unittest discover -s tests -v
python -m maintenance_center.web --state-dir /tmp/dmc-demo --issue-code initialize
python -m maintenance_center.web --state-dir /tmp/dmc-demo
```

不指定 runtime-config 时只使用演示网关，地址 `http://127.0.0.1:8767`。演示页面不是宿主接入验收。不要给演示环境配置真实 Token。

## 许可证

项目自有代码采用 [MIT](LICENSE)。依赖不因本项目 MIT 而变更许可，见 [第三方声明](THIRD_PARTY.md) 与 `third_party/licenses/`。`sbom.cdx.json` 是 Python 依赖清单，不包含完整操作系统镜像包清单。协议名 `project007-v2` 是源项目继承的接口标识，不依赖私有项目目录或生产系统。
