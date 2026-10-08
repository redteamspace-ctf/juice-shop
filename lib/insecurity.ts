/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import expressJwt from 'express-jwt'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */

// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

const jwtStateDirectory = path.resolve(process.env.JWT_SESSION_DIR ?? 'data/.jwt-auth')
const revokedTokenDirectory = path.join(jwtStateDirectory, 'revoked')

function ensurePrivateDirectory (directory: string) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 })
  if (process.platform !== 'win32' && (fs.statSync(directory).mode & 0o077) !== 0) {
    throw new Error(`JWT state directory must be private: ${directory}`)
  }
}

ensurePrivateDirectory(jwtStateDirectory)
ensurePrivateDirectory(revokedTokenDirectory)

function writePrivateFileOnce (file: string, contents: string) {
  const temporaryFile = `${file}.${process.pid}.${crypto.randomUUID()}.tmp`
  try {
    fs.writeFileSync(temporaryFile, contents, { mode: 0o600, flag: 'wx' })
    try {
      fs.linkSync(temporaryFile, file)
      return true
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') return false
      throw error
    }
  } finally {
    fs.rmSync(temporaryFile, { force: true })
  }
}

function loadPrivateKey () {
  const configuredKey = process.env.JWT_PRIVATE_KEY
  if (configuredKey !== undefined) return configuredKey.replace(/\\n/g, '\n')

  const keyFile = path.join(jwtStateDirectory, 'private.pem')
  if (!fs.existsSync(keyFile)) {
    const generatedKey = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
    }).privateKey
    writePrivateFileOnce(keyFile, generatedKey)
  }

  if (process.platform !== 'win32' && (fs.statSync(keyFile).mode & 0o077) !== 0) {
    throw new Error(`JWT private key must be owner-readable only: ${keyFile}`)
  }
  return fs.readFileSync(keyFile, 'utf8')
}

const privateKey = loadPrivateKey()
const publicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString()
export { publicKey }

function revocationFile (token: string) {
  return path.join(revokedTokenDirectory, crypto.createHash('sha256').update(token).digest('hex'))
}

function isRevoked (token: string) {
  try {
    fs.statSync(revocationFile(token))
    return true
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
    throw error
  }
}

for (const entry of fs.readdirSync(revokedTokenDirectory)) {
  if (!/^[a-f0-9]{64}$/.test(entry)) continue
  const file = path.join(revokedTokenDirectory, entry)
  const contents = fs.readFileSync(file, 'utf8')
  const expiry = Number(contents)
  if (/^\d+$/.test(contents) && Number.isSafeInteger(expiry) && expiry <= Math.floor(Date.now() / 1000)) fs.rmSync(file)
}

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

export const isAuthorized = () => {
  const authorizeRequest = expressJwt(({ secret: publicKey }) as any)
  return (req: Request, res: Response, next: NextFunction) => {
    const token = utils.jwtFrom(req)
    if (!verify(token) || !authenticatedUsers.get(token)) {
      res.status(401).send()
      return
    }
    authorizeRequest(req, res, next)
  }
}
export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)
export const authorize = (user: any = {}) => {
  const data = user?.data
  const payload = data?.id
    ? {
        status: user.status,
        data: {
          id: data.id,
          username: data.username,
          email: data.email,
          role: data.role,
          lastLoginIp: data.lastLoginIp,
          profileImage: data.profileImage
        }
      }
    : user
  const issuedAt = Math.floor(Date.now() / 1000)
  const header = Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'RS256' })).toString('base64url')
  const claims = Buffer.from(JSON.stringify({ ...payload, iat: issuedAt, exp: issuedAt + 6 * 60 * 60 })).toString('base64url')
  const signedData = `${header}.${claims}`
  const signature = crypto.sign('RSA-SHA256', Buffer.from(signedData), privateKey).toString('base64url')
  return `${signedData}.${signature}`
}
export const verify = (token?: string) => decode(token) !== undefined
export const decode = (token?: string): any => {
  if (!token) return undefined
  try {
    const unquotedToken = utils.unquote(token)
    const parts = unquotedToken.split('.')
    if (parts.length !== 3 || parts.some(part => !/^[\w-]+$/.test(part))) return undefined
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'))
    if (header?.alg !== 'RS256' || header?.typ !== 'JWT') return undefined
    const signedData = Buffer.from(`${parts[0]}.${parts[1]}`)
    const signature = Buffer.from(parts[2], 'base64url')
    if (!crypto.verify('RSA-SHA256', signedData, publicKey, signature)) return undefined
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
    const now = Math.floor(Date.now() / 1000)
    if (!payload || typeof payload !== 'object' || typeof payload.exp !== 'number' || payload.exp <= now) return undefined
    if (typeof payload.nbf === 'number' && payload.nbf > now) return undefined
    if (isRevoked(unquotedToken)) return undefined
    return payload
  } catch {
    return undefined
  }
}

export const revokeToken = (token: string) => {
  const unquotedToken = utils.unquote(token)
  const claims = decode(unquotedToken)
  if (!claims?.data?.id) return false

  const file = revocationFile(unquotedToken)
  if (!writePrivateFileOnce(file, String(claims.exp))) return false
  const user = authenticatedUsers.tokenMap[unquotedToken]
  delete authenticatedUsers.tokenMap[unquotedToken]
  if (user && authenticatedUsers.idMap[user.data.id] === unquotedToken) {
    delete authenticatedUsers.idMap[user.data.id]
  }

  const expiresInMs = typeof claims.exp === 'number'
    ? Math.max(0, claims.exp * 1000 - Date.now())
    : 6 * 60 * 60 * 1000
  setTimeout(() => {
    try { fs.rmSync(file, { force: true }) } catch { /* Retain an expired revocation until the next startup. */ }
  }, expiresInMs).unref()
  return true
}

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    if (!token) return undefined
    const unquotedToken = utils.unquote(token)
    return unquotedToken.includes('.') && !verify(unquotedToken) ? undefined : this.tokenMap[unquotedToken]
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const rehydrateAuthenticatedUsers = () => async (req: Request, _res: Response, next: NextFunction) => {
  try {
    const tokens = new Set([utils.jwtFrom(req), req.cookies?.token])
    for (const token of tokens) {
      if (typeof token !== 'string' || authenticatedUsers.get(token)) continue
      const claims = decode(token)
      if (claims?.status !== 'success' || !Number.isSafeInteger(claims.data?.id) || claims.data.id <= 0 || typeof claims.data.email !== 'string') continue

      const { UserModel } = await import('../models/user')
      const user = await UserModel.findByPk(claims.data.id)
      if (user && user.email === claims.data.email) {
        authenticatedUsers.put(token, { status: 'success', data: user, iat: claims.iat, exp: claims.exp })
      }
    }
    next()
  } catch (error) {
    next(error)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  const decoded = z85.decode(coupon)
  if (decoded && (hasValidFormat(decoded.toString()) != null)) {
    const parts = decoded.toString().split('-')
    const validity = parts[0]
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parts[1]
      return parseInt(discount)
    }
  }
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl) // vuln-code-snippet vuln-line redirectChallenge
  }
  return allowed
}
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', privateKey)
  return hmac.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (authenticatedUsers.from(req)?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const user = authenticatedUsers.from(req)?.data
  return user?.role === roles.deluxe && user.deluxeToken === deluxeToken(user.email)
}

export const isCustomer = (req: Request) => {
  return authenticatedUsers.from(req)?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = authenticatedUsers.from(req)
      if (!user?.data?.id) throw new Error('Invalid session')
      req.body = req.body ?? {}
      req.body.UserId = user.data.id
      next()
    } catch (error: unknown) {
      res.status(401).json({ status: 'error', message: utils.getErrorMessage(error) })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies?.token || utils.jwtFrom(req)
  if (token && !authenticatedUsers.get(token)) {
    res.clearCookie('token')
  }
  next()
}
