// Cloudflare Pages Functions 中间件：全站 HTTP Basic Auth，仅放行站内代理接口。
// 注意：浏览器只在导航和图片/子资源请求上复用 Basic 认证缓存，fetch 请求不会携带凭据，
// 因此对 /api/proxy 做鉴权会让前端调用恒定 401 并反复弹出密码框，这里必须放行。
export async function onRequest(context) {
  const { request, next, env } = context;

  const url = new URL(request.url);
  if (url.pathname === '/api/proxy') {
    return next();
  }

  const user = env.BASIC_USER;
  const pass = env.BASIC_PASS;
  if (!user || !pass) {
    return new Response("Access control is not configured.", { status: 500 });
  }
  const header = request.headers.get("Authorization") || "";
  const prefix = "Basic ";
  if (!header.startsWith(prefix)) return unauthorized();
  const decoded = atob(header.slice(prefix.length));
  const sep = decoded.indexOf(":");
  const u = decoded.slice(0, sep);
  const p = decoded.slice(sep + 1);
  if (u === user && p === pass) return next();
  return unauthorized();
}

function unauthorized() {
  return new Response("需要密码访问", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="POSE Atlas", charset="UTF-8"' },
  });
}
