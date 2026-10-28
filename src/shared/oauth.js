/**
 * OAuth + session auth handlers — Google / GitHub / GitLab + /api/auth/me|logout
 */
import { json, bad } from "./http.js";
import {
  parseCookies,
  sessionCookie,
  clearSessionCookie,
  randomId,
  COOKIE_NAME,
} from "./utils.js";
import { getSessionUser, rejectIfAlreadySignedIn } from "./auth.js";
import { DASHBOARD_URL, SESSION_DAYS } from "./constants.js";

/* ─── Google OAuth ─── */

export function handleAuthGoogleStart(request, env, url) {
  const clientId = env.GOOGLE_CLIENT_ID;
  if (!clientId) return bad(request, "GOOGLE_CLIENT_ID not configured on Worker", 500);

  const redirectUri = `${url.origin}/api/auth/google/callback`;
  const state = randomId(16);
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid email profile",
    access_type: "online",
    include_granted_scopes: "true",
    state,
    prompt: "select_account",
  });

  const headers = new Headers({
    Location: `https://accounts.google.com/o/oauth2/v2/auth?${params}`,
    "Set-Cookie": `a2a_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
  });
  return new Response(null, { status: 302, headers });
}

export async function handleAuthGoogleCallback(request, env, url) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const err = url.searchParams.get("error");

  if (err) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=${encodeURIComponent(err)}`, 302);
  }
  if (!code || !state) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=missing_code`, 302);
  }

  // Must log out before switching provider / re-auth while session active
  const blocked = await rejectIfAlreadySignedIn(request, env);
  if (blocked) return blocked;

  const cookies = parseCookies(request.headers.get("Cookie"));
  if (!cookies.a2a_oauth_state || cookies.a2a_oauth_state !== state) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=bad_state`, 302);
  }

  const clientId = env.GOOGLE_CLIENT_ID;
  const clientSecret = env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=server_config`, 302);
  }

  const redirectUri = `${url.origin}/api/auth/google/callback`;
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    }),
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=token_exchange`, 302);
  }

  const userRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
  });
  const profile = await userRes.json();
  if (!userRes.ok || !profile.sub || !profile.email) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=userinfo`, 302);
  }

  const googleUserId = "google:" + profile.sub;
  const email = String(profile.email);
  const name = String(profile.name || email.split("@")[0]);
  const picture = profile.picture ? String(profile.picture) : null;

  // Same email may already exist from GitHub — link session to that row
  let sessionUserId = googleUserId;
  const byGoogle = await env.DB.prepare(`SELECT id FROM users WHERE id = ?1`)
    .bind(googleUserId)
    .first();

  if (byGoogle) {
    await env.DB.prepare(
      `UPDATE users
       SET email = ?1, name = ?2, picture = ?3, provider = 'google', updated_at = datetime('now')
       WHERE id = ?4`
    )
      .bind(email, name, picture, googleUserId)
      .run();
    sessionUserId = googleUserId;
  } else {
    const byEmail = await env.DB.prepare(`SELECT id FROM users WHERE email = ?1`)
      .bind(email)
      .first();
    if (byEmail) {
      await env.DB.prepare(
        `UPDATE users
         SET name = COALESCE(NULLIF(?1, ''), name),
             picture = COALESCE(?2, picture),
             updated_at = datetime('now')
         WHERE id = ?3`
      )
        .bind(name, picture, byEmail.id)
        .run();
      sessionUserId = byEmail.id;
    } else {
      await env.DB.prepare(
        `INSERT INTO users (id, email, name, picture, provider, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'google', datetime('now'))`
      )
        .bind(googleUserId, email, name, picture)
        .run();
      sessionUserId = googleUserId;
    }
  }

  const sessionId = randomId(24);
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 864e5).toISOString();
  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, expires_at) VALUES (?1, ?2, ?3)`
  )
    .bind(sessionId, sessionUserId, expiresAt)
    .run();

  const maxAge = SESSION_DAYS * 86400;
  const headers = new Headers({ Location: DASHBOARD_URL });
  headers.append("Set-Cookie", sessionCookie(sessionId, maxAge));
  headers.append(
    "Set-Cookie",
    "a2a_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  );
  return new Response(null, { status: 302, headers });
}

/* ─── GitHub OAuth ─── */

export function handleAuthGithubStart(request, env, url) {
  const clientId = env.GITHUB_CLIENT_ID;
  if (!clientId) return bad(request, "GITHUB_CLIENT_ID not configured on Worker", 500);

  const redirectUri = `${url.origin}/api/auth/github/callback`;
  const state = randomId(16);
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: "read:user user:email",
    state,
    allow_signup: "true",
  });
  const headers = new Headers({
    Location: `https://github.com/login/oauth/authorize?${params}`,
    "Set-Cookie": `a2a_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
  });
  return new Response(null, { status: 302, headers });
}

export async function handleAuthGithubCallback(request, env, url) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const err = url.searchParams.get("error");
  if (err) {
    return Response.redirect(
      `${DASHBOARD_URL}?auth_error=${encodeURIComponent(err)}`,
      302
    );
  }
  if (!code || !state) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=missing_code`, 302);
  }

  // Must log out before switching provider / re-auth while session active
  const blocked = await rejectIfAlreadySignedIn(request, env);
  if (blocked) return blocked;

  const cookies = parseCookies(request.headers.get("Cookie"));
  if (!cookies.a2a_oauth_state || cookies.a2a_oauth_state !== state) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=bad_state`, 302);
  }

  const clientId = env.GITHUB_CLIENT_ID;
  const clientSecret = env.GITHUB_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=server_config`, 302);
  }

  const redirectUri = `${url.origin}/api/auth/github/callback`;
  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
    }),
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=token_exchange`, 302);
  }

  const accessToken = tokenData.access_token;
  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "AgentPay-Worker",
    },
  });
  const profile = await userRes.json();
  if (!userRes.ok || !profile.id) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=userinfo`, 302);
  }

  let email = profile.email ? String(profile.email) : null;
  if (!email) {
    try {
      const emailRes = await fetch("https://api.github.com/user/emails", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "AgentPay-Worker",
        },
      });
      if (emailRes.ok) {
        const emails = await emailRes.json();
        const primary =
          (Array.isArray(emails) && emails.find((e) => e.primary && e.verified)) ||
          (Array.isArray(emails) && emails.find((e) => e.verified)) ||
          (Array.isArray(emails) && emails[0]);
        if (primary && primary.email) email = String(primary.email);
      }
    } catch (_) {
      /* optional */
    }
  }
  if (!email) {
    email = `${profile.login}@users.noreply.github.com`;
  }

  const githubUserId = "github:" + profile.id;
  const name = String(profile.name || profile.login || email.split("@")[0]);
  const picture = profile.avatar_url ? String(profile.avatar_url) : null;

  // Resolve account:
  // 1) existing github:id
  // 2) same email already used (e.g. Google) → link session to that user
  // 3) else create new github user
  let sessionUserId = githubUserId;
  const byGithub = await env.DB.prepare(`SELECT id FROM users WHERE id = ?1`)
    .bind(githubUserId)
    .first();

  const ghLogin = profile.login ? String(profile.login) : null;

  if (byGithub) {
    await env.DB.prepare(
      `UPDATE users
       SET email = ?1, name = ?2, picture = ?3, provider = 'github',
           github_access_token = ?4, github_login = ?5, updated_at = datetime('now')
       WHERE id = ?6`
    )
      .bind(email, name, picture, accessToken, ghLogin, githubUserId)
      .run();
    sessionUserId = githubUserId;
  } else {
    const byEmail = await env.DB.prepare(`SELECT id FROM users WHERE email = ?1`)
      .bind(email)
      .first();
    if (byEmail) {
      // Same person logged in via Google before — reuse that row (email UNIQUE)
      await env.DB.prepare(
        `UPDATE users
         SET name = COALESCE(NULLIF(?1, ''), name),
             picture = COALESCE(?2, picture),
             github_access_token = ?3,
             github_login = ?4,
             updated_at = datetime('now')
         WHERE id = ?5`
      )
        .bind(name, picture, accessToken, ghLogin, byEmail.id)
        .run();
      sessionUserId = byEmail.id;
    } else {
      await env.DB.prepare(
        `INSERT INTO users (id, email, name, picture, provider, github_access_token, github_login, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'github', ?5, ?6, datetime('now'))`
      )
        .bind(githubUserId, email, name, picture, accessToken, ghLogin)
        .run();
      sessionUserId = githubUserId;
    }
  }

  const sessionId = randomId(24);
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 864e5).toISOString();
  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, expires_at) VALUES (?1, ?2, ?3)`
  )
    .bind(sessionId, sessionUserId, expiresAt)
    .run();

  const maxAge = SESSION_DAYS * 86400;
  const headers = new Headers({ Location: DASHBOARD_URL });
  headers.append("Set-Cookie", sessionCookie(sessionId, maxAge));
  headers.append(
    "Set-Cookie",
    "a2a_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  );
  return new Response(null, { status: 302, headers });
}


/* ─── GitLab OAuth ─── */

export function handleAuthGitlabStart(request, env, url) {
  const clientId = env.GITLAB_CLIENT_ID;
  if (!clientId) return bad(request, "GITLAB_CLIENT_ID not configured on Worker", 500);

  const redirectUri = `${url.origin}/api/auth/gitlab/callback`;
  const state = randomId(16);
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "read_user read_api",
    state,
  });
  const headers = new Headers({
    Location: `https://gitlab.com/oauth/authorize?${params}`,
    "Set-Cookie": `a2a_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
  });
  return new Response(null, { status: 302, headers });
}

export async function handleAuthGitlabCallback(request, env, url) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const err = url.searchParams.get("error");
  if (err) {
    return Response.redirect(
      `${DASHBOARD_URL}?auth_error=${encodeURIComponent(err)}`,
      302
    );
  }
  if (!code || !state) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=missing_code`, 302);
  }

  const blocked = await rejectIfAlreadySignedIn(request, env);
  if (blocked) return blocked;

  const cookies = parseCookies(request.headers.get("Cookie"));
  if (!cookies.a2a_oauth_state || cookies.a2a_oauth_state !== state) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=bad_state`, 302);
  }

  const clientId = env.GITLAB_CLIENT_ID;
  const clientSecret = env.GITLAB_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=server_config`, 302);
  }

  const redirectUri = `${url.origin}/api/auth/gitlab/callback`;
  const tokenRes = await fetch("https://gitlab.com/oauth/token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
    }),
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=token_exchange`, 302);
  }

  const accessToken = tokenData.access_token;
  const userRes = await fetch("https://gitlab.com/api/v4/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
      "User-Agent": "AgentPay-Worker",
    },
  });
  const profile = await userRes.json();
  if (!userRes.ok || !profile.id) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=userinfo`, 302);
  }

  let email = profile.email ? String(profile.email) : null;
  if (!email && profile.public_email) email = String(profile.public_email);
  if (!email) {
    // Fallback: GitLab may hide email — use noreply style
    email = `${profile.username || profile.id}@users.noreply.gitlab.com`;
  }

  const gitlabUserId = "gitlab:" + profile.id;
  const name = String(profile.name || profile.username || email.split("@")[0]);
  const picture = profile.avatar_url ? String(profile.avatar_url) : null;
  const glUsername = profile.username ? String(profile.username) : null;

  let sessionUserId = gitlabUserId;
  const byGitlab = await env.DB.prepare(`SELECT id FROM users WHERE id = ?1`)
    .bind(gitlabUserId)
    .first();

  if (byGitlab) {
    try {
      await env.DB.prepare(
        `UPDATE users
         SET email = ?1, name = ?2, picture = ?3, provider = 'gitlab',
             gitlab_access_token = ?4, gitlab_username = ?5, updated_at = datetime('now')
         WHERE id = ?6`
      )
        .bind(email, name, picture, accessToken, glUsername, gitlabUserId)
        .run();
    } catch (_) {
      // columns optional until ALTER
      await env.DB.prepare(
        `UPDATE users
         SET email = ?1, name = ?2, picture = ?3, provider = 'gitlab', updated_at = datetime('now')
         WHERE id = ?4`
      )
        .bind(email, name, picture, gitlabUserId)
        .run();
    }
    sessionUserId = gitlabUserId;
  } else {
    const byEmail = await env.DB.prepare(`SELECT id FROM users WHERE email = ?1`)
      .bind(email)
      .first();
    if (byEmail) {
      try {
        await env.DB.prepare(
          `UPDATE users
           SET name = COALESCE(NULLIF(?1, ''), name),
               picture = COALESCE(?2, picture),
               gitlab_access_token = ?3,
               gitlab_username = ?4,
               updated_at = datetime('now')
           WHERE id = ?5`
        )
          .bind(name, picture, accessToken, glUsername, byEmail.id)
          .run();
      } catch (_) {
        await env.DB.prepare(
          `UPDATE users
           SET name = COALESCE(NULLIF(?1, ''), name),
               picture = COALESCE(?2, picture),
               updated_at = datetime('now')
           WHERE id = ?3`
        )
          .bind(name, picture, byEmail.id)
          .run();
      }
      sessionUserId = byEmail.id;
    } else {
      try {
        await env.DB.prepare(
          `INSERT INTO users (id, email, name, picture, provider, gitlab_access_token, gitlab_username, updated_at)
           VALUES (?1, ?2, ?3, ?4, 'gitlab', ?5, ?6, datetime('now'))`
        )
          .bind(gitlabUserId, email, name, picture, accessToken, glUsername)
          .run();
      } catch (_) {
        await env.DB.prepare(
          `INSERT INTO users (id, email, name, picture, provider, updated_at)
           VALUES (?1, ?2, ?3, ?4, 'gitlab', datetime('now'))`
        )
          .bind(gitlabUserId, email, name, picture)
          .run();
      }
      sessionUserId = gitlabUserId;
    }
  }

  const sessionId = randomId(24);
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 864e5).toISOString();
  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, expires_at) VALUES (?1, ?2, ?3)`
  )
    .bind(sessionId, sessionUserId, expiresAt)
    .run();

  const maxAge = SESSION_DAYS * 86400;
  const headers = new Headers({ Location: DASHBOARD_URL });
  headers.append("Set-Cookie", sessionCookie(sessionId, maxAge));
  headers.append(
    "Set-Cookie",
    "a2a_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  );
  return new Response(null, { status: 302, headers });
}

export async function handleAuthMe(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) {
    return json(request, { ok: false, authenticated: false }, 200, {
      "Set-Cookie": clearSessionCookie(),
    });
  }
  let hasGithub = false;
  let githubLogin = null;
  try {
    const g = await env.DB.prepare(
      `SELECT github_access_token, github_login FROM users WHERE id = ?1`
    )
      .bind(user.id)
      .first();
    hasGithub = !!(g && g.github_access_token);
    githubLogin = g?.github_login || null;
  } catch (_) {
    /* columns may be missing until ALTER */
  }
  return json(request, {
    ok: true,
    authenticated: true,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      picture: user.picture,
      provider: user.provider,
      default_repo: user.default_repo || null,
      has_github: hasGithub,
      github_login: githubLogin,
    },
  });
}

export async function handleAuthLogout(request, env) {
  const cookies = parseCookies(request.headers.get("Cookie"));
  const sid = cookies[COOKIE_NAME];
  let githubCleared = false;
  if (sid) {
    // Clear GitHub token before dropping session (security: no lingering token after logout)
    try {
      const sess = await env.DB.prepare(
        `SELECT user_id FROM sessions WHERE id = ?1`
      )
        .bind(sid)
        .first();
      if (sess && sess.user_id) {
        await env.DB.prepare(
          `UPDATE users
           SET github_access_token = NULL,
               github_login = NULL,
               updated_at = datetime('now')
           WHERE id = ?1`
        )
          .bind(sess.user_id)
          .run();
        githubCleared = true;
      }
    } catch (_) {
      /* columns optional */
    }
    await env.DB.prepare(`DELETE FROM sessions WHERE id = ?`).bind(sid).run();
  }
  return json(
    request,
    { ok: true, logged_out: true, github_token_cleared: githubCleared },
    200,
    { "Set-Cookie": clearSessionCookie() }
  );
}
