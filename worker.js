/**
 * Cloudflare Worker：iOS 测试分发设备绑定入口
 *
 * 路由：
 *   GET  /enroll/{appKey}                    引导页（Safari 打开）
 *   GET  /enroll/{appKey}/udid.mobileconfig  Profile Service 描述文件
 *   POST /enroll/{appKey}/callback           苹果回调：提取 UDID -> repository_dispatch 触发重签 -> 303 跳安装页
 *   GET  /enroll/{appKey}/status?since=ts    重签进度轮询（安装页调用，10 秒共享缓存，开放 CORS）
 *   其余路径                                  302 回默认 app 引导页
 *
 * 环境变量：
 *   GH_REPO         owner/repo
 *   GH_TOKEN        触发 Actions 的 classic PAT（需 repo 权限；fine-grained PAT 不支持 dispatches API）
 *   DEFAULT_APP_KEY 缺省 appKey，默认 app_hga
 */

const APP_KEY_RE = /^[A-Za-z0-9._-]{1,64}$/;
// 兼容老设备（40 位 hex）与新设备（0xxxxxxxx-xxxxxxxxxxxxxxxx）两种 UDID 格式
const UDID_RE = /^(?:[0-9a-fA-F]{40}|0[0-9a-fA-F]{8}-[0-9a-fA-F]{16})$/;
const DEDUP_TTL = 600; // 同一 UDID 触发后的去重窗口（秒），防手抖/脚本刷重签队列

// 由 appKey 派生稳定的 UUID，多 app 共存于一台设备时描述文件不会互相覆盖
function uuidForApp(appKey) {
  let h = 0x9e3779b9;
  for (const ch of appKey) {
    h ^= ch.codePointAt(0);
    h = Math.imul(h, 0x85ebca6b) >>> 0;
  }
  const hex = Array.from({ length: 4 }, () => {
    h ^= h << 13; h >>>= 0;
    h ^= h >>> 17;
    h ^= h << 5;  h >>>= 0;
    return h.toString(16).padStart(8, "0");
  }).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

function errorHtml(message, appKey, status) {
  const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>测试设备绑定</title></head><body style="font-family:-apple-system,sans-serif;text-align:center;padding:48px 20px">
  <h2>⚠️ 绑定未完成</h2><p style="color:#555">${message}</p>
  <a href="/enroll/${appKey}" style="display:inline-block;margin-top:20px;padding:14px 28px;background:#007aff;color:#fff;border-radius:10px;text-decoration:none;font-size:16px;font-weight:600">
  返回重试</a></body></html>`;
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean); // ["enroll", "app_hga", "action"]
    const defaultApp = env.DEFAULT_APP_KEY || "app_hga";
    const appKey = parts[1] || defaultApp;

    // appKey 白名单：挡住引导页反射 XSS、mobileconfig XML 注入和垃圾 dispatch；
    // 未知路由或非法 appKey 一律回默认引导页
    if (parts[0] !== "enroll" || !APP_KEY_RE.test(appKey)) {
      return Response.redirect(`${url.origin}/enroll/${defaultApp}`, 302);
    }
    const action = parts[2] || "";

    // 1. 落地引导页
    if (!action) {
      const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
      <title>测试设备绑定</title></head><body style="font-family:-apple-system,sans-serif;text-align:center;padding:48px 20px">
      <h2>iOS 测试版设备授权</h2><p style="color:#555">请使用 iPhone 自带 <b>Safari</b> 浏览器打开</p>
      <a href="/enroll/${appKey}/udid.mobileconfig" style="display:inline-block;margin-top:20px;padding:14px 28px;background:#007aff;color:#fff;border-radius:10px;text-decoration:none;font-size:16px;font-weight:600">
      一键获取 UDID 并重签</a></body></html>`;
      return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    // 2. 下发描述文件
    if (action === "udid.mobileconfig") {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadContent</key><dict>
    <key>URL</key><string>${url.origin}/enroll/${appKey}/callback</string>
    <key>DeviceAttributes</key><array><string>UDID</string></array>
  </dict>
  <key>PayloadOrganization</key><string>Internal Test</string>
  <key>PayloadDisplayName</key><string>获取测试设备 UDID</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadUUID</key><string>${uuidForApp(appKey)}</string>
  <key>PayloadIdentifier</key><string>com.internal.udid.${appKey}</string>
  <key>PayloadType</key><string>Profile Service</string>
</dict></plist>`;
      return new Response(xml, {
        headers: {
          "Content-Type": "application/x-apple-aspen-config",
          "Content-Disposition": "attachment; filename=udid.mobileconfig",
          "Cache-Control": "no-store",
        },
      });
    }

    // 3. 接收苹果回调：提取 UDID -> 触发 GitHub Actions -> 303 跳 Pages 安装页倒计时
    if (action === "callback" && request.method === "POST") {
      if (!env.GH_REPO || !env.GH_TOKEN) {
        console.error("[enroll] 缺少 GH_REPO/GH_TOKEN 环境变量");
        return errorHtml("服务未正确配置（缺少 GH_REPO / GH_TOKEN），请联系管理员", appKey, 500);
      }
      const body = await request.text();
      const match = body.match(/<key>UDID<\/key>\s*<string>([^<]+)<\/string>/);
      const udid = match ? match[1].trim() : "";
      if (!UDID_RE.test(udid)) {
        // 非设备回调（探测/垃圾 POST）不发 dispatch，避免空转重签
        console.warn(`[enroll:${appKey}] 回调未带回合法 UDID，UA=${request.headers.get("User-Agent") || "?"}`);
        return errorHtml("没有从设备读取到有效 UDID，请在 Safari 中重新点击绑定按钮", appKey, 400);
      }

      const [owner, repo] = env.GH_REPO.split("/");
      const installUrl = `https://${owner}.github.io/${repo}/${appKey}/`;

      // 同一 UDID 在去重窗口内只触发一次重签；窗口内重复回调仍正常跳安装页
      const cache = caches.default;
      const dedupKey = new Request(`https://udid-dedup.invalid/${appKey}/${udid}`);
      if (await cache.match(dedupKey)) {
        return Response.redirect(`${installUrl}?enrolled=1&t=${Math.floor(Date.now() / 1000)}`, 303);
      }

      let ghStatus = 0;
      let ghDetail = "";
      try {
        const ghResp = await fetch(`https://api.github.com/repos/${env.GH_REPO}/dispatches`, {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.GH_TOKEN}`,
            "Accept": "application/vnd.github+json",
            "User-Agent": "CF-Worker-OTA",
          },
          body: JSON.stringify({
            event_type: "resign",
            client_payload: { app_key: appKey, udid },
          }),
        });
        ghStatus = ghResp.status;
        if (ghStatus >= 400) ghDetail = (await ghResp.text()).slice(0, 300);
      } catch (e) {
        ghDetail = `请求 GitHub 异常: ${e.message}`;
      }

      if (ghStatus >= 200 && ghStatus < 300) {
        ctx.waitUntil(cache.put(dedupKey, new Response(null, {
          headers: { "Cache-Control": `public, max-age=${DEDUP_TTL}` },
        })));
        return Response.redirect(`${installUrl}?enrolled=1&t=${Math.floor(Date.now() / 1000)}`, 303);
      }
      console.error(`[enroll:${appKey}] dispatch 失败: HTTP ${ghStatus} ${ghDetail}`);
      return errorHtml(`已读取设备 ${udid}，但触发重签失败（HTTP ${ghStatus}），请稍后返回重试`, appKey, 502);
    }

    // 4. 重签进度查询：安装页轮询调用（20 秒后每 30 秒一次）。
    //    GH 查询按 app 做 10 秒共享缓存，多人同扫每 10 秒也只回源一次
    if (action === "status" && (request.method === "GET" || request.method === "HEAD")) {
      let runs = [];
      if (env.GH_REPO && env.GH_TOKEN) {
        const statusCache = caches.default;
        const statusKey = new Request(`https://resign-status.invalid/${appKey}`);
        const cached = await statusCache.match(statusKey);
        if (!cached) {
          try {
            const gh = await fetch(`https://api.github.com/repos/${env.GH_REPO}/actions/workflows/resign.yml/runs?per_page=5`, {
              headers: {
                "Authorization": `Bearer ${env.GH_TOKEN}`,
                "Accept": "application/vnd.github+json",
                "User-Agent": "CF-Worker-OTA",
              },
            });
            if (gh.ok) {
              runs = (await gh.json()).workflow_runs.map((r) => ({
                t: Math.floor(Date.parse(r.created_at) / 1000),
                s: r.status,
                c: r.conclusion,
              }));
            }
          } catch (e) {
            console.warn(`[status:${appKey}] 查询 GitHub runs 失败: ${e.message}`);
          }
          ctx.waitUntil(statusCache.put(statusKey, new Response(JSON.stringify({ runs }), {
            headers: { "Cache-Control": "public, max-age=10" },
          })));
        } else {
          try {
            runs = (await cached.json()).runs || [];
          } catch (e) { runs = []; }
        }
      }
      const since = Number(new URL(request.url).searchParams.get("since")) || 0;
      // 优先找本次回调之后触发的 run；找不到就用最近一次（去重命中场景下通常就是那次）
      const mine = runs.find((r) => r.t >= since) || runs[0];
      let state = "starting";
      if (mine) {
        state = mine.s === "completed"
          ? (mine.c === "success" ? "success" : "failed")
          : (mine.s === "in_progress" ? "running" : "queued");
      }
      return new Response(JSON.stringify({ state, queue: runs.length }), {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    return Response.redirect(`${url.origin}/enroll/${defaultApp}`, 302);
  },
};
