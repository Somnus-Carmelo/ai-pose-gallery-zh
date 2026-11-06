export async function onRequest(context) {
  const { request, next, env } = context;
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
