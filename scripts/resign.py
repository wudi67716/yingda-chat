
import base64, datetime, glob, html, os, plistlib, re, shutil, subprocess, tempfile, time, zipfile
import jwt, requests
from cryptography.hazmat.primitives.serialization import pkcs12

APP_KEY = os.environ.get("APP_KEY", "app_hga").strip() or "app_hga"
if not re.fullmatch(r"[A-Za-z0-9._-]+", APP_KEY):
    raise ValueError(f"APP_KEY 只允许字母、数字和 . _ -，当前值: {APP_KEY!r}")
UDID = os.environ.get("TARGET_UDID", "").strip()
STRIP_EXT = os.environ.get("STRIP_EXTENSIONS", "false").lower() == "true"
# Worker 访问地址（可选，如 https://xxx.workers.dev）。配置后安装页轮询重签进度；未配置退回固定倒计时
ENROLL_BASE = os.environ.get("ENROLL_BASE", "").strip().rstrip("/")

ISSUER_ID = os.environ["ASC_ISSUER_ID"]
KEY_ID = os.environ["ASC_KEY_ID"]
P12_PWD = os.environ["P12_PASSWORD"]
REPO = os.environ["GITHUB_REPOSITORY"]
OWNER, REPO_NAME = REPO.split("/")

PAGES_BASE = f"https://{OWNER}.github.io/{REPO_NAME}"
RELEASE_BASE = f"https://github.com/{REPO}/releases/download/signed"

P8_PATH = "/tmp/AuthKey.p8"
P12_PATH = "/tmp/dist.p12"
BASE_IPA = f"/tmp/{APP_KEY}.ipa"
SIGNED_IPA = f"/tmp/{APP_KEY}_signed.ipa"
ASC_API = "https://api.appstoreconnect.apple.com/v1"


# Safari 校验：itms-services 安装只在 iOS 自带 Safari 有效，微信/QQ 等内置浏览器点了没反应
SAFARI_JS = """
var ua = navigator.userAgent;
var isIOS = /iPhone|iPad|iPod/i.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
var NOT_SAFARI = !(isIOS && /Safari/i.test(ua) && !/CriOS|FxiOS|EdgiOS|MicroMessenger|MQQBrowser|WeChat|WeiBo|BytedanceWebview|Instagram|TikTok/i.test(ua));
var installBtn = document.getElementById('install-btn');
if (NOT_SAFARI) {
    if (installBtn) {
        installBtn.style.opacity = '0.35';
        installBtn.style.pointerEvents = 'none';
        var tip = document.createElement('p');
        tip.style.cssText = 'margin-top:18px;color:#d4380d;font-size:14px';
        tip.textContent = isIOS
            ? '当前不是 Safari 打开，点安装不会生效：请点击右上角选择“在浏览器/Safari 中打开”，或在 iPhone 自带 Safari 中重新访问本页。'
            : '需要用 iPhone/iPad 自带的 Safari 浏览器打开本页才能安装。';
        installBtn.parentNode.insertBefore(tip, installBtn.nextSibling);
    }
} else if (installBtn) {
    var goBox = document.getElementById('go-box');
    installBtn.addEventListener('click', function () {
        installBtn.textContent = '已开始安装（无反应可再点一次）';
        if (goBox) {
            goBox.style.display = 'block';
            goBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    });
}
"""

# 安装页等待脚本：轮询 Worker status 接口（20 秒后首次，每 30 秒一次，页面隐藏时暂停）
WAIT_JS = """
const params = new URLSearchParams(window.location.search);
if (params.get('enrolled') === '1') {
    var box = document.getElementById('wait-box'),
        btn = document.getElementById('install-btn'),
        msg = document.getElementById('wait-msg'),
        sec = document.getElementById('sec');
    box.style.display = 'block';
    btn.style.opacity = '0.4';
    btn.style.pointerEvents = 'none';
    var since = parseInt(params.get('t') || '0', 10) || Math.floor(Date.now() / 1000) - 60;
    var waited = 0, done = false;
    var clock = setInterval(function () { waited += 1; sec.textContent = String(waited); }, 1000);
    function finish(text, unlock) {
        done = true;
        clearInterval(clock); clearInterval(poll);
        msg.textContent = text;
        if (unlock && !NOT_SAFARI) { btn.style.opacity = '1'; btn.style.pointerEvents = 'auto'; }
    }
    function check() {
        if (done) return;
        if (waited > 1200) { finish('排队比预期长，可以先关掉本页面，几分钟后重新打开再试。', true); return; }
        fetch('__STATUS_URL__?since=' + since, { cache: 'no-store' })
            .then(function (r) { return r.json(); })
            .then(function (d) {
                if (done) return;
                if (d.state === 'success') {
                    finish('重签完成，你的设备已入列！页面即将刷新，点安装即可拿到含你设备的包：）', false);
                    setTimeout(function () { window.location.href = window.location.pathname; }, 1500);
                } else if (d.state === 'failed') {
                    finish('本次重签未成功，请稍等几分钟后重试；仍不行请联系管理员查看 Actions 运行日志。', true);
                } else if (d.state === 'running') {
                    msg.textContent = '服务器正在签名，会把你的设备写进新描述文件，请稍候...';
                } else if (d.state === 'queued') {
                    msg.textContent = '你已进入重签队列，正在等待前面的任务完成...';
                } else {
                    msg.textContent = '正在与服务器同步设备信息，请稍候...';
                }
            })
            .catch(function () { /* 网络抖动忽略，下一轮自动重试 */ });
    }
    var poll = setInterval(function () { if (!document.hidden) check(); }, 30000);
    setTimeout(check, 20000);
    document.addEventListener('visibilitychange', function () { if (!document.hidden) check(); });
}
"""

# 未配置 ENROLL_BASE 时的退回脚本：约 75 秒后自动刷新一次
WAIT_JS_LEGACY = """
const params = new URLSearchParams(window.location.search);
if (params.get('enrolled') === '1') {
    var box = document.getElementById('wait-box'),
        btn = document.getElementById('install-btn'),
        msg = document.getElementById('wait-msg'),
        sec = document.getElementById('sec');
    box.style.display = 'block';
    btn.style.opacity = '0.4';
    btn.style.pointerEvents = 'none';
    msg.textContent = '新设备 UDID 已提交，服务器正在重签（约 1-2 分钟），完成后页面自动刷新';
    var waited = 0;
    var timer = setInterval(function () {
        waited += 1;
        sec.textContent = String(waited);
        if (waited >= 75) { clearInterval(timer); window.location.href = window.location.pathname; }
    }, 1000);
}
"""


def asc_headers() -> dict:
    with open(P8_PATH, "rb") as f:
        key = f.read()
    now = int(time.time())
    token = jwt.encode(
        {"iss": ISSUER_ID, "iat": now, "exp": now + 600, "aud": "appstoreconnect-v1"},
        key, algorithm="ES256", headers={"kid": KEY_ID},
    )
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def check_resp(resp: requests.Response, what: str) -> requests.Response:
    if resp.status_code >= 400:
        print(f"[ASC] {what} 失败: HTTP {resp.status_code}\n响应: {resp.text}")
        resp.raise_for_status()
    return resp


def asc_call(what: str, method: str, url: str, headers: dict, retries: int = 3, **kwargs) -> requests.Response:
    # 苹果 ASC 偶发 500/429（服务端抖动），退避重试；最终仍失败由 check_resp 打印错误体并抛出
    for attempt in range(1, retries + 1):
        resp = requests.request(method, url, headers=headers, timeout=20, **kwargs)
        if resp.status_code in (429, 500, 502, 503) and attempt < retries:
            wait = 15 * attempt
            print(f"[ASC] {what} 返回 HTTP {resp.status_code}，{wait} 秒后重试（{attempt}/{retries - 1}）")
            time.sleep(wait)
            continue
        return check_resp(resp, what)


def build_profile(headers: dict, bundle_id: str, cert_res: str, prof_type: str, dev_rels: list, save_path: str):
    r_bid = asc_call(f"查询 Bundle ID {bundle_id}", "GET", f"{ASC_API}/bundleIds", headers, params={"filter[identifier]": bundle_id})
    exact = [b for b in r_bid.json().get("data", []) if b["attributes"]["identifier"] == bundle_id]
    if not exact:
        raise RuntimeError(f"苹果后台未找到精确匹配的 Bundle ID: {bundle_id}")
    bid_res = exact[0]["id"]

    prof_name = f"GH_Auto_{bundle_id}"
    # filter[name] 为模糊匹配，下面在客户端按名称精确比对后删除
    r_old = asc_call(f"查询描述文件 {prof_name}", "GET", f"{ASC_API}/profiles", headers, params={"filter[name]": prof_name})
    for old in r_old.json().get("data", []):
        if old["attributes"]["name"] == prof_name:
            asc_call(f"删除旧描述文件 {prof_name}", "DELETE", f"{ASC_API}/profiles/{old['id']}", headers)

    resp = asc_call(f"创建描述文件 {prof_name}", "POST", f"{ASC_API}/profiles", headers,
        json={
            "data": {
                "type": "profiles",
                "attributes": {"name": prof_name, "profileType": prof_type},
                "relationships": {
                    "bundleId": {"data": {"type": "bundleIds", "id": bid_res}},
                    "certificates": {"data": [{"type": "certificates", "id": cert_res}]},
                    "devices": {"data": dev_rels},
                },
            }
        },
    )
    with open(save_path, "wb") as f:
        f.write(base64.b64decode(resp.json()["data"]["attributes"]["profileContent"]))


def main():
    if not os.path.exists(BASE_IPA):
        raise FileNotFoundError(f"未在 base Release 中找到底包: {APP_KEY}.ipa")

    # 1. 提取原包 Bundle ID 与版本信息（保持原样，确保原有 APNs 推送证书继续有效）
    with zipfile.ZipFile(BASE_IPA, "r") as zf:
        plist_path = next((n for n in zf.namelist() if re.match(r"^Payload/[^/]+\.app/Info\.plist$", n)), None)
        if plist_path is None:
            raise RuntimeError(f"底包 {APP_KEY}.ipa 内未找到 Payload/*.app/Info.plist，请确认底包结构")
        info = plistlib.loads(zf.read(plist_path))
    bundle_id = info.get("CFBundleIdentifier")
    if not bundle_id:
        raise RuntimeError(f"底包 {APP_KEY}.ipa 的 Info.plist 缺少 CFBundleIdentifier")
    version = info.get("CFBundleShortVersionString", "1.0.0")
    app_name = info.get("CFBundleDisplayName") or info.get("CFBundleName", APP_KEY)

    with open(P12_PATH, "rb") as f:
        _, cert, _ = pkcs12.load_key_and_certificates(f.read(), P12_PWD.encode())
    local_serial = format(cert.serial_number, "X").lstrip("0")

    headers = asc_headers()

    # 2. 注册或重新启用传入的测试机 UDID
    if UDID:
        r = asc_call(f"查询设备 {UDID}", "GET", f"{ASC_API}/devices", headers, params={"filter[udid]": UDID})
        existing = r.json().get("data", [])
        if existing:
            if existing[0]["attributes"]["status"] != "ENABLED":
                asc_call(f"启用设备 {UDID}", "PATCH", f"{ASC_API}/devices/{existing[0]['id']}", headers,
                    json={"data": {"type": "devices", "id": existing[0]["id"], "attributes": {"status": "ENABLED"}}})
        else:
            asc_call(f"注册设备 {UDID}", "POST", f"{ASC_API}/devices", headers,
                json={"data": {"type": "devices", "attributes": {"name": f"Tester_{UDID[:8]}", "udid": UDID, "platform": "IOS"}}})
        print(f"已同步测试设备 UDID: {UDID}")

    # 3. 匹配同账号证书与全量已启用设备
    r_certs = asc_call("查询证书列表", "GET", f"{ASC_API}/certificates", headers,
        params={"filter[certificateType]": "IOS_DISTRIBUTION,DISTRIBUTION,IOS_DEVELOPMENT,DEVELOPMENT"})
    certs = r_certs.json()["data"]
    matched_cert = next(
        (c for c in certs
         if c["attributes"]["serialNumber"].upper().lstrip("0") == local_serial),
        None,
    )
    if matched_cert is None:
        remote = ", ".join(c["attributes"]["serialNumber"] for c in certs) or "(空列表)"
        raise RuntimeError(f"ASC 证书里找不到本地 p12 对应的证书: 本地序列号 {local_serial}，远端序列号 [{remote}]（请确认 P12 属于当前 ASC 账号/Team）")
    cert_res = matched_cert["id"]
    prof_type = "IOS_APP_DEVELOPMENT" if "DEVELOPMENT" in matched_cert["attributes"]["certificateType"] else "IOS_APP_ADHOC"

    devs = []
    url = f"{ASC_API}/devices"
    params = {"filter[platform]": "IOS", "filter[status]": "ENABLED", "limit": 200}
    while url:
        page = asc_call("分页查询已启用设备", "GET", url, headers, params=params).json()
        devs.extend(page.get("data", []))
        url = page.get("links", {}).get("next")
        params = None  # next 链接已带全部查询参数
    dev_rels = [{"type": "devices", "id": d["id"]} for d in devs]
    print(f"当前账号已启用设备总数: {len(devs)}")

    # 4. 签发主包与扩展描述文件并调用 zsign 重签
    work_dir = tempfile.mkdtemp(prefix="gh_zsign_")
    try:
        main_prov = os.path.join(work_dir, "main.mobileprovision")
        build_profile(headers, bundle_id, cert_res, prof_type, dev_rels, main_prov)

        ext_profiles = {}
        if not STRIP_EXT:
            with zipfile.ZipFile(BASE_IPA, "r") as zf:
                for name in zf.namelist():
                    if re.match(r"^Payload/[^/]+\.app/PlugIns/[^/]+\.appex/Info\.plist$", name):
                        ext_bid = plistlib.loads(zf.read(name)).get("CFBundleIdentifier")
                        if not ext_bid:
                            raise RuntimeError(f"扩展 {name} 缺少 CFBundleIdentifier")
                        ext_dir = name.split("/")[-2]
                        ext_prov = os.path.join(work_dir, f"{ext_dir}.mobileprovision")
                        build_profile(headers, ext_bid, cert_res, prof_type, dev_rels, ext_prov)
                        ext_profiles[ext_dir] = ext_prov

        if ext_profiles:
            unpack_dir = os.path.join(work_dir, "unpacked")
            with zipfile.ZipFile(BASE_IPA, "r") as zf:
                zf.extractall(unpack_dir)
            apps = glob.glob(os.path.join(unpack_dir, "Payload", "*.app"))
            if not apps:
                raise RuntimeError("解压底包后未找到 Payload/*.app")
            app_folder = apps[0]
            for ext_dir, ext_prov in ext_profiles.items():
                subprocess.run(["zsign", "-k", P12_PATH, "-p", P12_PWD, "-m", ext_prov, os.path.join(app_folder, "PlugIns", ext_dir)], check=True)
            subprocess.run(["zsign", "-k", P12_PATH, "-p", P12_PWD, "-m", main_prov, "-z", "1", "-o", SIGNED_IPA, app_folder], check=True)
        else:
            cmd = ["zsign", "-k", P12_PATH, "-p", P12_PWD, "-m", main_prov, "-z", "1", "-o", SIGNED_IPA]
            if STRIP_EXT:
                cmd.append("-E")
            cmd.append(BASE_IPA)
            subprocess.run(cmd, check=True)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    # 5. 生成 GitHub Pages 托管的 manifest.plist 与防索引安装页
    out_dir = os.path.join("docs", APP_KEY)
    os.makedirs(out_dir, exist_ok=True)
    ts = int(time.time())
    build_time = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
    ipa_url = f"{RELEASE_BASE}/{APP_KEY}_signed.ipa?t={ts}"
    manifest_url = f"{PAGES_BASE}/{APP_KEY}/manifest.plist"

    manifest = {
        "items": [{
            "assets": [{"kind": "software-package", "url": ipa_url}],
            "metadata": {
                "bundle-identifier": bundle_id,
                "bundle-version": version,
                "kind": "software",
                "title": app_name,
            },
        }]
    }
    with open(os.path.join(out_dir, "manifest.plist"), "wb") as f:
        plistlib.dump(manifest, f)

    wait_js = (WAIT_JS if ENROLL_BASE else WAIT_JS_LEGACY).replace("__STATUS_URL__", f"{ENROLL_BASE}/enroll/{APP_KEY}/status")
    app_name_h = html.escape(str(app_name))
    version_h = html.escape(str(version))
    page_html = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title>{app_name_h} - 测试版安装</title></head><body style="font-family:-apple-system,sans-serif;text-align:center;padding:48px 20px">
    <h2>{app_name_h}</h2>
    <p style="color:#666;font-size:14px">版本: {version_h} | 授权设备: {len(devs)} 台<br>最后更新时间: {build_time} (CST)</p>
    <div id="wait-box" style="display:none;margin:24px auto;padding:16px;max-width:340px;background:#fff8e6;border:1px solid #ffd591;border-radius:10px;color:#d46b08;font-size:14px">
      <p id="wait-msg" style="margin:0 0 6px">新设备 UDID 已提交云端重签队列...</p>
      <p style="margin:0">已等待 <b id="sec">0</b> 秒</p>
    </div>
    <a id="install-btn" href="itms-services://?action=download-manifest&url={manifest_url}"
       style="display:inline-block;margin-top:20px;padding:15px 32px;background:#34c759;color:#fff;border-radius:10px;text-decoration:none;font-size:17px;font-weight:600">
       点击直接安装到 iPhone</a>
    <div id="go-box" style="display:none;margin-top:16px;padding:16px;max-width:340px;background:#f0f9eb;border:1px solid #b7eb8f;border-radius:10px;color:#389e0d;font-size:14px;text-align:left;line-height:1.9">
      ✅ 已唤起安装：请回到 iPhone 桌面，「{app_name_h}」图标会自动开始下载（保持网络连接）。<br>
      若 10 秒后桌面没有动静：确认是在 iPhone 自带 <b>Safari</b> 里点的（微信/QQ 内无效），再点一次按钮即可。
    </div>
    <p style="margin-top:20px;font-size:13px;color:#888">请使用 Safari 浏览器打开，点击安装后返回桌面查看进度</p>
    <script>
    {SAFARI_JS}
    {wait_js}
    </script></body></html>"""
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(page_html)


if __name__ == "__main__":
    main()
