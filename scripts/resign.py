
import base64, datetime, glob, os, plistlib, re, shutil, subprocess, tempfile, time, zipfile
import jwt, requests
from cryptography.hazmat.primitives.serialization import pkcs12

APP_KEY = os.environ.get("APP_KEY", "app_a").strip() or "app_a"
UDID = os.environ.get("TARGET_UDID", "").strip()
STRIP_EXT = os.environ.get("STRIP_EXTENSIONS", "false").lower() == "true"

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


def asc_headers() -> dict:
    with open(P8_PATH, "rb") as f:
        key = f.read()
    now = int(time.time())
    token = jwt.encode(
        {"iss": ISSUER_ID, "iat": now, "exp": now + 600, "aud": "appstoreconnect-v1"},
        key, algorithm="ES256", headers={"kid": KEY_ID},
    )
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def build_profile(headers: dict, bundle_id: str, cert_res: str, prof_type: str, dev_rels: list, save_path: str):
    r_bid = requests.get(f"{ASC_API}/bundleIds", headers=headers, params={"filter[identifier]": bundle_id}, timeout=15)
    r_bid.raise_for_status()
    exact = [b for b in r_bid.json().get("data", []) if b["attributes"]["identifier"] == bundle_id]
    if not exact:
        raise RuntimeError(f"苹果后台未找到精确匹配的 Bundle ID: {bundle_id}")
    bid_res = exact[0]["id"]

    prof_name = f"GH_Auto_{bundle_id}"
    r_old = requests.get(f"{ASC_API}/profiles", headers=headers, params={"filter[name]": profile_name_clean(prof_name)}, timeout=15)
    for old in r_old.json().get("data", []):
        if old["attributes"]["name"] == prof_name:
            requests.delete(f"{ASC_API}/profiles/{old['id']}", headers=headers, timeout=15)

    resp = requests.post(
        f"{ASC_API}/profiles", headers=headers,
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
        timeout=20,
    )
    resp.raise_for_status()
    with open(save_path, "wb") as f:
        f.write(base64.b64decode(resp.json()["data"]["attributes"]["profileContent"]))


def profile_name_clean(name: str) -> str:
    return name


def main():
    if not os.path.exists(BASE_IPA):
        raise FileNotFoundError(f"未在 base Release 中找到底包: {APP_KEY}.ipa")

    # 1. 提取原包 Bundle ID 与版本信息（保持原样，确保原有 APNs 推送证书继续有效）
    with zipfile.ZipFile(BASE_IPA, "r") as zf:
        plist_path = [n for n in zf.namelist() if re.match(r"^Payload/[^/]+\.app/Info\.plist$", n)][0]
        info = plistlib.loads(zf.read(plist_path))
    bundle_id = info["CFBundleIdentifier"]
    version = info.get("CFBundleShortVersionString", "1.0.0")
    app_name = info.get("CFBundleDisplayName") or info.get("CFBundleName", APP_KEY)

    with open(P12_PATH, "rb") as f:
        _, cert, _ = pkcs12.load_key_and_certificates(f.read(), P12_PWD.encode())
    local_serial = format(cert.serial_number, "X").lstrip("0")

    headers = asc_headers()

    # 2. 注册或重新启用传入的测试机 UDID
    if UDID:
        r = requests.get(f"{ASC_API}/devices", headers=headers, params={"filter[udid]": UDID}, timeout=15)
        r.raise_for_status()
        existing = r.json().get("data", [])
        if existing:
            if existing[0]["attributes"]["status"] != "ENABLED":
                requests.patch(
                    f"{ASC_API}/devices/{existing[0]['id']}", headers=headers,
                    json={"data": {"type": "devices", "id": existing[0]["id"], "attributes": {"status": "ENABLED"}}},
                    timeout=15,
                ).raise_for_status()
        else:
            requests.post(
                f"{ASC_API}/devices", headers=headers,
                json={"data": {"type": "devices", "attributes": {"name": f"Tester_{UDID[:8]}", "udid": UDID, "platform": "IOS"}}},
                timeout=15,
            ).raise_for_status()
        print(f"已同步测试设备 UDID: {UDID}")

    # 3. 匹配同账号证书与全量已启用设备
    r_certs = requests.get(
        f"{ASC_API}/certificates", headers=headers,
        params={"filter[certificateType]": "IOS_DISTRIBUTION,DISTRIBUTION,IOS_DEVELOPMENT,DEVELOPMENT"},
        timeout=15,
    )
    r_certs.raise_for_status()
    matched_cert = next(
        c for c in r_certs.json()["data"]
        if c["attributes"]["serialNumber"].upper().lstrip("0") == local_serial
    )
    cert_res = matched_cert["id"]
    prof_type = "IOS_APP_DEVELOPMENT" if "DEVELOPMENT" in matched_cert["attributes"]["certificateType"] else "IOS_APP_ADHOC"

    r_devs = requests.get(
        f"{ASC_API}/devices", headers=headers,
        params={"filter[platform]": "IOS", "filter[status]": "ENABLED", "limit": 200},
        timeout=15,
    )
    r_devs.raise_for_status()
    devs = r_devs.json()["data"]
    dev_rels = [{"type": "devices", "id": d["id"]} for d in devs]
    print(f"当前账号已启用设备总数: {len(devs)} / 100")

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
                        ext_bid = plistlib.loads(zf.read(name))["CFBundleIdentifier"]
                        ext_dir = name.split("/")[-2]
                        ext_prov = os.path.join(work_dir, f"{ext_dir}.mobileprovision")
                        build_profile(headers, ext_bid, cert_res, prof_type, dev_rels, ext_prov)
                        ext_profiles[ext_dir] = ext_prov

        if ext_profiles:
            unpack_dir = os.path.join(work_dir, "unpacked")
            with zipfile.ZipFile(BASE_IPA, "r") as zf:
                zf.extractall(unpack_dir)
            app_folder = glob.glob(os.path.join(unpack_dir, "Payload", "*.app"))[0]
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
    build_time = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
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

    html = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title>{app_name} - 测试版安装</title></head><body style="font-family:-apple-system,sans-serif;text-align:center;padding:48px 20px">
    <h2>{app_name}</h2>
    <p style="color:#666;font-size:14px">版本: {version} | 授权设备: {len(devs)} 台<br>最后更新时间: {build_time} (CST)</p>
    <div id="wait-box" style="display:none;margin:24px auto;padding:16px;max-width:340px;background:#fff8e6;border:1px solid #ffd591;border-radius:10px;color:#d46b08;font-size:14px">
      新设备 UDID 已提交云端重签队列，请等待 <b id="sec">75</b> 秒后页面自动刷新再点击安装...
    </div>
    <a id="install-btn" href="itms-services://?action=download-manifest&url={manifest_url}"
       style="display:inline-block;margin-top:20px;padding:15px 32px;background:#34c759;color:#fff;border-radius:10px;text-decoration:none;font-size:17px;font-weight:600">
       点击直接安装到 iPhone</a>
    <p style="margin-top:20px;font-size:13px;color:#888">请使用 Safari 浏览器打开，点击安装后返回桌面查看进度</p>
    <script>
    const params = new URLSearchParams(window.location.search);
    if (params.get('enrolled') === '1') {{
        const box = document.getElementById('wait-box');
        const btn = document.getElementById('install-btn');
        box.style.display = 'block';
        btn.style.opacity = '0.4';
        btn.style.pointerEvents = 'none';
        let left = 75;
        const timer = setInterval(() => {{
            left--;
            document.getElementById('sec').innerText = left;
            if (left <= 0) {{
                clearInterval(timer);
                window.location.href = window.location.pathname;
            }}
        }}, 1000);
    }}
    </script></body></html>"""
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)


if __name__ == "__main__":
    main()
