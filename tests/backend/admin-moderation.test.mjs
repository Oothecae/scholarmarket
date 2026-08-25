import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { isAdmin, getAdminUserFromRequest, verifyAdminAuth } from "../../src/lib/auth/adminAuth.js";

const JWT_SECRET = "secret-for-testing-purposes-32chars!";
process.env.JWT_SECRET = JWT_SECRET;

function base64UrlEncode(value) {
  return Buffer.from(value).toString("base64url");
}

function signJwt(payload, signingSecret = JWT_SECRET, { exp } = {}) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload };

  if (typeof exp === "number") {
    body.exp = exp;
  } else if (exp !== null) {
    body.exp = now + 3600;
  }

  const headerPart = base64UrlEncode(JSON.stringify(header));
  const payloadPart = base64UrlEncode(JSON.stringify(body));
  const signature = createHmac("sha256", signingSecret)
    .update(`${headerPart}.${payloadPart}`)
    .digest("base64url");

  return `${headerPart}.${payloadPart}.${signature}`;
}

function createMockRequest({ cookieToken = null, bearerToken = null } = {}) {
  const headers = new Map();
  if (cookieToken) {
    headers.set("cookie", `auth_token=${encodeURIComponent(cookieToken)}`);
  }
  if (bearerToken) {
    headers.set("authorization", `Bearer ${bearerToken}`);
  }
  return {
    headers: {
      get: (name) => headers.get(name.toLowerCase()) || null,
    },
  };
}

test("Admin Auth — isAdmin utility", () => {
  assert.equal(isAdmin(null), false);
  assert.equal(isAdmin({ role: "user" }), false);
  assert.equal(isAdmin({ role: "creator" }), false);
  assert.equal(isAdmin({ role: "admin" }), true);
  assert.equal(isAdmin({ isAdmin: true }), true);
});

test("Admin Auth — Request verification with JWT", async (t) => {
  await t.test("accepts admin with valid cookie token", async () => {
    const token = signJwt({ sub: "admin-1", role: "admin", walletAddress: "GBADMIN123" });
    const req = createMockRequest({ cookieToken: token });

    const user = await getAdminUserFromRequest(req);
    assert.ok(user);
    assert.equal(user.sub, "admin-1");
    assert.equal(user.role, "admin");

    const auth = await verifyAdminAuth(req);
    assert.equal(auth.authorized, true);
    assert.equal(auth.user.sub, "admin-1");
  });

  await t.test("accepts admin with Bearer token in Authorization header", async () => {
    const token = signJwt({ sub: "admin-2", role: "admin" });
    const req = createMockRequest({ bearerToken: token });

    const auth = await verifyAdminAuth(req);
    assert.equal(auth.authorized, true);
    assert.equal(auth.user.sub, "admin-2");
  });

  await t.test("rejects regular non-admin user", async () => {
    const token = signJwt({ sub: "user-1", role: "learner" });
    const req = createMockRequest({ cookieToken: token });

    const auth = await verifyAdminAuth(req);
    assert.equal(auth.authorized, false);
    assert.equal(auth.status, 403);
    assert.match(auth.error, /Forbidden/i);
  });

  await t.test("rejects unauthenticated request without token", async () => {
    const req = createMockRequest();
    const auth = await verifyAdminAuth(req);
    assert.equal(auth.authorized, false);
    assert.equal(auth.status, 403);
  });

  await t.test("rejects invalid signature token", async () => {
    const token = signJwt({ sub: "admin-fake", role: "admin" }, "wrong-secret-key-that-does-not-match");
    const req = createMockRequest({ cookieToken: token });
    const auth = await verifyAdminAuth(req);
    assert.equal(auth.authorized, false);
  });
});
