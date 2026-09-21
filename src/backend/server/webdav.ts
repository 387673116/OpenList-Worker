import { Hono } from "hono"
import { authUserFromReq, getOrInitUsers, verifyUserPassword } from "./auth"
import { can, PermissionBit } from "../pkg/permission"
import {
  listItems,
  getItem,
  putItem,
  makeDirectory,
  removeItems,
  moveItems,
  copyItems,
} from "../internal/op/storage"
import { buildWebDavPropfindResponse } from "../internal/webdav/webdav"
import { safeErrorMessage } from "../pkg/errs"
import { getSettings, resolvePath } from "../internal/model/db"
import { canUseProxyEndpoint, normalizeExtList } from "../internal/driver/proxy"

/**
 * WebDAV åè®®æå¡ï¼æè½½äº /dav/*ï¼ã
 *
 * è®¤è¯ï¼Basic Authï¼ç¨æ·å/å¯ç ï¼æ Bearer tokenï¼å¨å± tokenï¼ã
 * æéï¼WEBDAV_READï¼è¯»/åç®å½ï¼ä¸ WEBDAV_MANAGEï¼å/å /ç§»å¨/å¤å¶ï¼æä½æ ¡éªã
 * æ¯ææ¹æ³ï¼OPTIONS / PROPFIND / GET / HEAD / PUT / MKCOL / DELETE / MOVE / COPYã
 */

export const webdavRouter = new Hono()

const getStorageRequestContext = (c: any) => {
  try {
    const executionCtx = c.executionCtx
    if (!executionCtx || typeof executionCtx.waitUntil !== "function") {
      return undefined
    }
    return {
      waitUntil: (p: Promise<unknown>) => executionCtx.waitUntil(p),
      env: c.env, // ä¼ é env ç¨äºè¯·æ±çº§ KV ç¼å­å¤ç¨
    }
  } catch {
    return undefined
  }
}

/** Basic Auth æ Bearer token è®¤è¯ï¼è¿åç¨æ·å¯¹è±¡ï¼æªè®¤è¯è¿å nullï¼ */
async function webdavAuth(c: any): Promise<any> {
  const authHeader = c.req.header("Authorization") || ""
  if (authHeader.startsWith("Basic ")) {
    try {
      const decoded = atob(authHeader.substring(6).trim())
      const idx = decoded.indexOf(":")
      if (idx < 0) return null
      const username = decoded.substring(0, idx)
      const password = decoded.substring(idx + 1)
      const { users } = await getOrInitUsers(c.env)
      const user = users.find(
        (u: any) => u.username === username && !u.disabled,
      )
      if (!user) return null
      // ç©ºå¯ç ç¨æ·ï¼guestï¼ï¼Basic Auth ä¸è¥æªæä¾å¯ç ååè®¸ï¼ä¸ AList ä¸è´ï¼
      if (!user.password) {
        return password === "" ? user : null
      }
      if (await verifyUserPassword(user, password)) return user
      return null
    } catch {
      return null
    }
  }
  if (authHeader.startsWith("Bearer ")) {
    const auth = await authUserFromReq(c)
    return auth ? auth.user : null
  }
  return null
}

/** ä» URL pathname ä¸­å¥ç¦» /dav åç¼ï¼å¾å°èææä»¶è·¯å¾ */
function davPathOf(c: any): string {
  const pathname = new URL(c.req.url).pathname
  let p = pathname.replace(/^\/dav/, "")
  if (!p) p = "/"
  try {
    return decodeDavPathSegment(p)
  } catch {
    return p
  }
}

/** æåèæè·¯å¾ä¸º { dir, name } */
function splitPath(p: string): { dir: string; name: string } {
  const clean = p.startsWith("/") ? p : "/" + p
  const parts = clean.split("/").filter(Boolean)
  const name = parts.pop() || ""
  const dir = "/" + parts.join("/")
  return { dir, name }
}

webdavRouter.all("/*", async (c) => {
  const user = await webdavAuth(c)
  if (!user) {
    return c.text("Unauthorized", 401, {
      "WWW-Authenticate": 'Basic realm="OpenList"',
    })
  }
  const canRead = can(user, PermissionBit.WEBDAV_READ)
  const canManage = can(user, PermissionBit.WEBDAV_MANAGE)
  if (!canRead && !canManage) {
    return c.text("Forbidden", 403)
  }

  const method = c.req.method.toUpperCase()
  const davPath = davPathOf(c)
  const ctx = getStorageRequestContext(c)

  try {
    switch (method) {
      case "OPTIONS": {
        c.header("DAV", "1, 2")
        c.header(
          "Allow",
          "OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, DELETE, MOVE, COPY",
        )
        c.header("MS-Author-Via", "DAV")
        return c.body(null, 200)
      }

      case "PROPFIND": {
        if (!canRead) return c.text("Forbidden", 403)
        const depth = c.req.header("Depth") || "1"
        const res = await listItems(davPath, ctx)
        const items = (res.content || []).map((it: any) => ({
          name: it.name,
          size: it.size || 0,
          isFolder: !!it.is_dir,
          modified: it.modified || new Date().toISOString(),
        }))
        const href =
          davPath === "/"
            ? "/"
            : encodeURI(davPath.endsWith("/") ? davPath : davPath + "/")
        const xml = buildWebDavPropfindResponse(href, items)
        return c.body(xml, depth === "0" ? 207 : 207, {
          "Content-Type": "application/xml; charset=utf-8",
        })
      }

      case "GET":
      case "HEAD": {
        if (!canRead) return c.text("Forbidden", 403)
        const { item, rawUrl } = await getItem(davPath, ctx)
        if (!item) return c.text("Not found", 404)
        if (item.is_dir) return c.text("Is a directory", 400)
        // éå®åå° rawRouter å®éä¸è½½ï¼rawRouter å·²å¤çææé©±å¨çä¸è½½åè®®
        // ï¼proxy/redirect/stream + Range + SSRF é²æ¤ï¼ã
        //
        // èµ° /p è¿æ¯ /d åå³äºå­å¨çä»£çç­ç¥ï¼/p æ¯åéçå¬å¼ä»£çç«¯ç¹
        // ï¼å¯¹é½ Go handles.canProxy()ï¼æªå¼å¯ä»£ççå­å¨ä¼ 403ï¼ï¼è WebDAV åè®®
        // ææµå¿é¡»è½æ¿å°å­èââä¸è½æ¿ç´é¾çå­å¨ï¼å¦ WebDav èªèº«ï¼æéè¦ /pã
        // å æ­¤è¿éæåä¸ä¸ªå¤æ®éæ©ç«¯ç¹ï¼é¿å WebDAV å®¢æ·ç«¯è¯»å° 403ã
        let prefix = "/api/p"
        try {
          const resolved: any = await resolvePath(davPath)
          const storage = resolved?.storage
          if (storage) {
            const settings: Record<string, any> = await getSettings().catch(
              () => ({}) as Record<string, any>,
            )
            const allowProxy = canUseProxyEndpoint({
              storage,
              driver: storage.driver,
              filename: davPath,
              proxyTypes: normalizeExtList(settings.proxy_types),
              textTypes: normalizeExtList(settings.text_types),
            })
            if (!allowProxy) prefix = "/api/d"
          }
        } catch {
          // è§£æå¤±è´¥æ¶ä¿æé»è®¤ /pï¼äº¤ç± rawRouter ç»åºæç»ç»è®º
        }
        return c.redirect(
          rawUrl || `${prefix}${davPath.startsWith("/") ? "" : "/"}${davPath}`,
          302,
        )
      }

      case "PUT": {
        if (!canManage) return c.text("Forbidden", 403)
        const buffer = Buffer.from(await c.req.arrayBuffer())
        await putItem(davPath, buffer, ctx)
        return c.body(null, 201)
      }

      case "MKCOL": {
        if (!canManage) return c.text("Forbidden", 403)
        await makeDirectory(davPath, ctx)
        return c.body(null, 201)
      }

      case "DELETE": {
        if (!canManage) return c.text("Forbidden", 403)
        const { dir, name } = splitPath(davPath)
        await removeItems(dir, [name], ctx)
        return c.body(null, 204)
      }

      case "MOVE": {
        if (!canManage) return c.text("Forbidden", 403)
        const destRaw = c.req.header("Destination") || ""
        let dest = destRaw
        try {
          dest = decodeURIComponent(
            new URL(destRaw, c.req.url).pathname,
          ).replace(/^\/dav/, "")
        } catch {}
        const src = splitPath(davPath)
        const dst = splitPath(dest)
        await moveItems(src.dir, dst.dir, [src.name], ctx)
        return c.body(null, 201)
      }

      case "COPY": {
        if (!canManage) return c.text("Forbidden", 403)
        const destRaw = c.req.header("Destination") || ""
        let dest = destRaw
        try {
          dest = decodeURIComponent(
            new URL(destRaw, c.req.url).pathname,
          ).replace(/^\/dav/, "")
        } catch {}
        const src = splitPath(davPath)
        const dst = splitPath(dest)
        await copyItems(src.dir, dst.dir, [src.name], ctx)
        return c.body(null, 201)
      }

      case "LOCK":
      case "UNLOCK":
        // ç®åå®ç°ï¼å£°æä¸æ¯æéï¼å®¢æ·ç«¯éå¸¸å¯ç»§ç»­æ éæä½
        return c.text("Locking not supported", 405)

      default:
        return c.text("Method Not Allowed", 405)
    }
  } catch (e: any) {
    const msg = safeErrorMessage(e)
    if (msg.includes("not found") || msg.includes("storage not found")) {
      return c.text("Not Found", 404)
    }
    return c.text(msg, 500)
  }
})/**
 * GBK fallback decode: fix silent fallback when non-UTF-8 clients
 * (some iOS/Windows apps) send GBK percent-encoded Chinese paths.
 *
 * decodeURIComponent throws URIError on non-UTF-8 sequences (e.g. %d1%a7).
 * The old implementation returned the raw percent string, path resolution
 * then fell back to the mount root, which clients see as
 * "failed to load second-level directories". This fix rebuilds the byte
 * sequence and decodes it as GBK; it only activates when UTF-8 decoding
 * fails, so well-formed UTF-8 paths are unaffected.
 */
function decodeDavPathSegment(p: string): string {
  try {
    return decodeURIComponent(p)
  } catch {
    try {
      const bytes: number[] = []
      let i = 0
      while (i < p.length) {
        if (p[i] === "%" && i + 3 <= p.length) {
          const hex = p.slice(i + 1, i + 3)
          if (/^[0-9a-fA-F]{2}$/.test(hex)) {
            bytes.push(parseInt(hex, 16))
            i += 3
            continue
          }
        }
        const code = p.charCodeAt(i)
        if (code < 128) bytes.push(code)
        else {
          const enc = encodeURIComponent(p[i])
          bytes.push(parseInt(enc.slice(1, 3), 16))
        }
        i += 1
      }
      return new TextDecoder("gbk").decode(new Uint8Array(bytes))
    } catch {
      return p
    }
  }
}


