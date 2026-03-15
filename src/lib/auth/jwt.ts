import { SignJWT, jwtVerify, type JWTPayload } from 'jose'

const secret = new TextEncoder().encode(
  process.env.JWT_SECRET ?? 'hemisx_dev_fallback_secret_change_in_production'
)

const ACCESS_EXPIRES  = process.env.JWT_ACCESS_EXPIRES_IN  ?? '15m'
const REFRESH_EXPIRES = process.env.JWT_REFRESH_EXPIRES_IN ?? '7d'

export interface AccessTokenPayload extends JWTPayload {
  userId: string
  orgId:  string
  role:   string
  email:  string
  name:   string
}

export interface RefreshTokenPayload extends JWTPayload {
  userId:  string
  tokenId: string
}

// ─── Sign ──────────────────────────────────────────────────────────────────

export async function signAccessToken(payload: Omit<AccessTokenPayload, keyof JWTPayload>) {
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(ACCESS_EXPIRES)
    .setIssuer('hemisx')
    .setAudience('hemisx-console')
    .sign(secret)
}

export async function signRefreshToken(
  payload: Omit<RefreshTokenPayload, keyof JWTPayload>
) {
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(REFRESH_EXPIRES)
    .setIssuer('hemisx')
    .setAudience('hemisx-refresh')
    .sign(secret)
}

// ─── Verify ────────────────────────────────────────────────────────────────

export async function verifyAccessToken(token: string): Promise<AccessTokenPayload | null> {
  try {
    const { payload } = await jwtVerify(token, secret, {
      issuer:   'hemisx',
      audience: 'hemisx-console',
    })
    return payload as AccessTokenPayload
  } catch {
    return null
  }
}

export async function verifyRefreshToken(token: string): Promise<RefreshTokenPayload | null> {
  try {
    const { payload } = await jwtVerify(token, secret, {
      issuer:   'hemisx',
      audience: 'hemisx-refresh',
    })
    return payload as RefreshTokenPayload
  } catch {
    return null
  }
}

// ─── Cookie config ─────────────────────────────────────────────────────────

export const ACCESS_COOKIE  = 'hemisx_access'
export const REFRESH_COOKIE = 'hemisx_refresh'

export function cookieOptions(maxAge: number) {
  return {
    httpOnly:  true,
    secure:    process.env.NODE_ENV === 'production',
    sameSite:  'lax' as const,
    path:      '/',
    maxAge,
  }
}
