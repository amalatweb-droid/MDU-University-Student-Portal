/* Local exam-demo server. No external packages required. */
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const SESSION_MS = 15 * 60 * 1000;
const USERS_FILE = path.join(__dirname, "users-db.json");
function passwordHash(password) {
  return crypto.scryptSync(password, "mdu-demo-salt", 32).toString("hex");
}
const ACCOUNTS = {
  "student@mdu.edu": {
    name: "Alex Smith",
    role: "student",
    department: "Computer Science · Year 3",
    secret: "JBSWY3DPEHPK3PXP",
    password: "Password123!",
  },
  "lecturer@mdu.edu": {
    name: "Dr. Maya Chen",
    role: "lecturer",
    department: "School of Computing",
    secret: "KRSXG5DSNFXGOIDB",
    password: "Password123!",
  },
  "admin@mdu.edu": {
    name: "Jordan Bennett",
    role: "admin",
    department: "MDU IT Services",
    secret: "MFRGGZDFMZTWQ2LK",
    password: "Password123!",
  },
};
Object.entries(ACCOUNTS).forEach(([email, account]) => {
  account.email = email;
  account.passwordHash = passwordHash(account.password);
  delete account.password;
  account.active = true;
});
try {
  Object.assign(ACCOUNTS, JSON.parse(fs.readFileSync(USERS_FILE, "utf8")));
} catch {}
const sessions = new Map();
const auditFile = path.join(ROOT, "audit-log.json");

function json(res, status, body, origin) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...(origin
      ? {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Credentials": "true",
          Vary: "Origin",
        }
      : {}),
  });
  res.end(JSON.stringify(body));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let b = "";
    req.on("data", (c) => {
      b += c;
      if (b.length > 1e6) req.destroy();
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(b || "{}"));
      } catch {
        reject(new Error("Invalid request"));
      }
    });
  });
}
function cookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || "")
      .split(";")
      .map((x) => x.trim().split("=").map(decodeURIComponent))
      .filter((x) => x[0]),
  );
}
function cookie(res, name, value, maxAge = SESSION_MS / 1000) {
  res.setHeader(
    "Set-Cookie",
    `${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`,
  );
}
function token(n = 32) {
  return crypto.randomBytes(n).toString("base64url");
}
function audit(type, email, detail = "") {
  const row = { at: new Date().toISOString(), type, email, detail };
  let old = [];
  try {
    old = JSON.parse(fs.readFileSync(auditFile, "utf8"));
  } catch {}
  old.unshift(row);
  fs.writeFileSync(auditFile, JSON.stringify(old.slice(0, 100), null, 2));
  return row;
}
function saveUsers() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(ACCOUNTS, null, 2));
}
function base32Secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  return Array.from(crypto.randomBytes(20), (b) => alphabet[b & 31]).join("");
}
function base32Decode(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "",
    out = [];
  for (const c of str.replace(/[=\s-]/g, "").toUpperCase()) {
    const i = alphabet.indexOf(c);
    if (i < 0) throw Error("Invalid key");
    bits += i.toString(2).padStart(5, "0");
  }
  for (let i = 0; i + 8 <= bits.length; i += 8)
    out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function totp(secret, time = Math.floor(Date.now() / 1000)) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(time / 30)));
  const digest = crypto
    .createHmac("sha1", base32Decode(secret))
    .update(counter)
    .digest();
  const off = digest[digest.length - 1] & 15;
  const code = (digest.readUInt32BE(off) & 0x7fffffff) % 1000000;
  return String(code).padStart(6, "0");
}
function validTotp(secret, code) {
  return (
    /^\d{6}$/.test(code || "") &&
    [-30, 0, 30].some((offset) =>
      crypto.timingSafeEqual(
        Buffer.from(totp(secret, Math.floor(Date.now() / 1000) + offset)),
        Buffer.from(code),
      ),
    )
  );
}
function getSession(req, res, authenticated = true) {
  const id = cookies(req).mdu_session;
  const s = sessions.get(id);
  if (!s || s.expires < Date.now() || (authenticated && !s.verified)) {
    if (id) sessions.delete(id);
    json(res, 401, {
      error: "Your secure session has expired. Please sign in again.",
    });
    return null;
  }
  s.expires = Date.now() + SESSION_MS;
  return s;
}
function csrf(req, s) {
  return (
    req.headers["x-csrf-token"] &&
    crypto.timingSafeEqual(
      Buffer.from(req.headers["x-csrf-token"]),
      Buffer.from(s.csrf),
    )
  );
}
function adminSession(req, res) {
  const s = getSession(req, res);
  if (!s) return null;
  if (ACCOUNTS[s.email].role !== "admin") {
    json(res, 403, { error: "Administrator access required." });
    return null;
  }
  return s;
}
function sendFile(res, file, type = "text/html; charset=utf-8") {
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end("Not found");
      return;
    }
    res.writeHead(200, { "Content-Type": type, "Cache-Control": "no-store" });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const method = req.method;
    const origin = req.headers.origin;
    if (url.pathname.startsWith("/api/") && origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.setHeader("Vary", "Origin");
    }
    if (method === "OPTIONS" && url.pathname.startsWith("/api/")) {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": origin || "http://localhost:3000",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
        Vary: "Origin",
      });
      return res.end();
    }
    if (method === "GET" && url.pathname === "/")
      return sendFile(res, path.join(ROOT, "index.html"));
    if (method === "GET" && url.pathname === "/api/health")
      return json(
        res,
        200,
        { ok: true, httpsReady: true, sessionTimeoutMinutes: 15 },
        origin,
      );
    if (method === "POST" && url.pathname === "/api/login") {
      const { email, password } = await readBody(req);
      const a = ACCOUNTS[String(email || "").toLowerCase()];
      if (
        !a ||
        !a.active ||
        !crypto.timingSafeEqual(
          Buffer.from(passwordHash(String(password || "")), "hex"),
          Buffer.from(a.passwordHash, "hex"),
        )
      ) {
        audit("FAILED_LOGIN", email, "Invalid credentials or disabled account");
        return json(res, 401, { error: "Invalid email or password." });
      }
      const id = token(),
        csrfToken = token(24);
      sessions.set(id, {
        email: String(email).toLowerCase(),
        verified: false,
        expires: Date.now() + SESSION_MS,
        csrf: csrfToken,
      });
      cookie(res, "mdu_session", id);
      audit("LOGIN_PASSWORD_VERIFIED", a.email, "Awaiting TOTP");
      return json(res, 200, {
        requiresMfa: true,
        profile: { email: a.email, name: a.name, role: a.role },
        setup: {
          issuer: "Metropolitan Digital University",
          account: a.email,
          secret: a.secret,
          otpauth: `otpauth://totp/MDU%20Portal:${encodeURIComponent(a.email)}?secret=${a.secret}&issuer=Metropolitan%20Digital%20University&algorithm=SHA1&digits=6&period=30`,
        },
      });
    }
    if (method === "POST" && url.pathname === "/api/verify-totp") {
      const s = getSession(req, res, false);
      if (!s) return;
      const { code } = await readBody(req),
        a = ACCOUNTS[s.email];
      if (!validTotp(a.secret, String(code || ""))) {
        audit("FAILED_MFA", a.email, "Invalid TOTP");
        return json(res, 401, {
          error:
            "Incorrect authentication code. Try the current code in your app.",
        });
      }
      s.verified = true;
      s.csrf = token(24);
      audit("MFA_VERIFIED", a.email, "Google Authenticator TOTP verified");
      return json(res, 200, {
        profile: {
          email: s.email,
          name: a.name,
          role: a.role,
          department: a.department,
        },
        csrf: s.csrf,
        expiresIn: SESSION_MS,
      });
    }
    if (method === "GET" && url.pathname === "/api/me") {
      const s = getSession(req, res);
      if (!s) return;
      const a = ACCOUNTS[s.email];
      return json(res, 200, {
        profile: {
          email: s.email,
          name: a.name,
          role: a.role,
          department: a.department,
        },
        csrf: s.csrf,
        expiresIn: s.expires - Date.now(),
      });
    }
    if (method === "GET" && url.pathname === "/api/audit") {
      const s = getSession(req, res);
      if (!s) return;
      if (ACCOUNTS[s.email].role !== "admin")
        return json(res, 403, { error: "Administrator access required." });
      let rows = [];
      try {
        rows = JSON.parse(fs.readFileSync(auditFile, "utf8"));
      } catch {}
      return json(res, 200, { rows });
    }
    if (method === "GET" && url.pathname === "/api/users") {
      const s = adminSession(req, res);
      if (!s) return;
      return json(res, 200, {
        users: Object.values(ACCOUNTS)
          .map(({ passwordHash, secret, ...u }) => u)
          .sort(
            (a, b) =>
              a.role.localeCompare(b.role) || a.name.localeCompare(b.name),
          ),
      });
    }
    if (method === "POST" && url.pathname === "/api/users") {
      const s = adminSession(req, res);
      if (!s) return;
      if (!csrf(req, s))
        return json(res, 403, { error: "CSRF validation failed." });
      const { name, email, role, department, password } = await readBody(req);
      const key = String(email || "")
        .trim()
        .toLowerCase();
      if (
        !name ||
        !/^[^\s@]+@mdu\.edu$/i.test(key) ||
        !["student", "lecturer", "admin"].includes(role) ||
        String(password || "").length < 10
      )
        return json(res, 400, {
          error:
            "Enter a name, an @mdu.edu email, a valid role, and a password with at least 10 characters.",
        });
      if (ACCOUNTS[key])
        return json(res, 409, {
          error: "An account with this email already exists.",
        });
      ACCOUNTS[key] = {
        email: key,
        name: String(name).trim(),
        role,
        department: String(department || "MDU Community").trim(),
        active: true,
        secret: base32Secret(),
        passwordHash: passwordHash(String(password)),
      };
      saveUsers();
      audit("USER_CREATED", s.email, `${role} account created: ${key}`);
      return json(res, 201, {
        user: {
          email: key,
          name: ACCOUNTS[key].name,
          role,
          department: ACCOUNTS[key].department,
          active: true,
        },
      });
    }
    if (method === "POST" && url.pathname === "/api/users/action") {
      const s = adminSession(req, res);
      if (!s) return;
      if (!csrf(req, s))
        return json(res, 403, { error: "CSRF validation failed." });
      const { email, action, name, department, role } = await readBody(req);
      const key = String(email || "").toLowerCase(),
        target = ACCOUNTS[key];
      if (!target) return json(res, 404, { error: "User not found." });
      if (key === s.email && ["toggle", "delete"].includes(action))
        return json(res, 400, {
          error: "You cannot disable or delete your own account.",
        });
      if (action === "toggle") {
        target.active = !target.active;
        audit(
          target.active ? "ACCOUNT_ENABLED" : "ACCOUNT_DISABLED",
          s.email,
          key,
        );
      } else if (action === "reset") {
        target.passwordHash = passwordHash("Password123!");
        target.secret = base32Secret();
        audit("PASSWORD_RESET", s.email, `${key}; MFA secret rotated`);
      } else if (action === "update") {
        if (
          !String(name || "").trim() ||
          !String(department || "").trim() ||
          !["student", "lecturer", "admin"].includes(role)
        )
          return json(res, 400, {
            error: "Enter a valid name, department, and role.",
          });
        if (key === s.email && role !== "admin")
          return json(res, 400, {
            error: "You cannot remove your own administrator role.",
          });
        target.name = String(name).trim();
        target.department = String(department).trim();
        target.role = role;
        audit("USER_UPDATED", s.email, `${key}; role set to ${role}`);
      } else if (action === "delete") {
        delete ACCOUNTS[key];
        for (const [id, session] of sessions)
          if (session.email === key) sessions.delete(id);
        audit("USER_DELETED", s.email, key);
        saveUsers();
        return json(res, 200, {
          message: "User account deleted and active sessions revoked.",
        });
      } else return json(res, 400, { error: "Unsupported user action." });
      saveUsers();
      return json(res, 200, {
        user: {
          email: key,
          name: target.name,
          role: target.role,
          department: target.department,
          active: target.active,
        },
        message:
          action === "reset"
            ? "Password reset to Password123! and MFA enrollment reset."
            : action === "update"
              ? "User profile updated."
              : `Account ${target.active ? "enabled" : "disabled"}.`,
      });
    }
    if (method === "POST" && url.pathname === "/api/logout") {
      const s = getSession(req, res);
      if (!s) return;
      if (!csrf(req, s))
        return json(res, 403, { error: "CSRF validation failed." });
      audit("LOGOUT", s.email, "User logout");
      sessions.delete(cookies(req).mdu_session);
      cookie(res, "mdu_session", "", 0);
      return json(res, 200, { ok: true });
    }
    json(res, 404, { error: "Not found" }, origin);
  } catch (e) {
    json(
      res,
      400,
      { error: e.message || "Unable to process request" },
      req.headers.origin,
    );
  }
});
// Vercel may detect a root server.js before the /api folder.  Delegate to the
// Supabase-backed serverless handler there, rather than starting the local-only
// file-based demo server in its read-only runtime.
if (process.env.VERCEL) {
  const cloudApi = require("./api/index.js");
  module.exports = (req, res) => {
    if (req.url.startsWith("/api/")) return cloudApi(req, res);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(fs.readFileSync(path.join(ROOT, "index.html")));
  };
} else {
  server.listen(PORT, () =>
    console.log(`MDU Portal ready at http://localhost:${PORT}`),
  );
}
