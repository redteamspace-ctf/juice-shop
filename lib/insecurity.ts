/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */

// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

const signingKeys = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
})
export const publicKey = signingKeys.publicKey
const privateKey = signingKeys.privateKey

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
  revokeUserSessions: (userId: number) => void
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

export const isAuthorized = () => (req: Request, res: Response, next: NextFunction) => {
  const token = utils.jwtFrom(req)
  const payload = token && verify(token) && decode(token)
  if (!payload?.data?.id) {
    res.status(401).json({ error: 'Authentication required' })
    return
  }
  req.user = payload
  next()
}
export const denyAll = () => (_req: Request, res: Response) => res.status(403).json({ error: 'Access denied' })
export const authorize = (user: Record<string, any> = {}) => {
  const payload = { ...user }
  if (payload.data) {
    const userData = payload.data as {
      get?: (options: { plain: boolean }) => unknown
      toJSON?: () => unknown
    }
    const serializedData = typeof userData.get === 'function'
      ? userData.get({ plain: true })
      : typeof userData.toJSON === 'function'
        ? userData.toJSON()
        : payload.data
    payload.data = serializedData !== null && typeof serializedData === 'object' && !Array.isArray(serializedData)
      ? { ...serializedData }
      : {}
    delete payload.data.password
    delete payload.data.totpSecret
  }
  return jwt.sign(payload, privateKey, { expiresInMinutes: 360, algorithm: 'RS256' } as any)
}

const revokedTokens = new Map<string, number>()
let verificationCount = 0

function purgeExpiredRevocations () {
  const now = Date.now()
  for (const [token, expiresAt] of revokedTokens) {
    if (expiresAt <= now) revokedTokens.delete(token)
  }
}

function tokenExpiration (token: string) {
  try {
    const payloadPart = token.split('.')[1]
    const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString())
    return typeof payload.exp === 'number' && Number.isFinite(payload.exp)
      ? payload.exp * 1000
      : Date.now() + 360 * 60 * 1000
  } catch {
    return Date.now() + 360 * 60 * 1000
  }
}

export const verify = (token: string) => {
  try {
    if (++verificationCount % 256 === 0) {
      purgeExpiredRevocations()
    }
    if (typeof token !== 'string' || token.length > 16384) return false
    const revokedUntil = revokedTokens.get(token)
    if (revokedUntil !== undefined) {
      if (revokedUntil > Date.now()) return false
      revokedTokens.delete(token)
    }
    const parts = token.split('.')
    if (parts.length !== 3) return false
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString())
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
    return header.alg === 'RS256' && typeof payload.exp === 'number' && payload.exp > Date.now() / 1000 &&
      crypto.verify('RSA-SHA256', Buffer.from(parts[0] + '.' + parts[1]), publicKey, Buffer.from(parts[2], 'base64url'))
  } catch {
    return false
  }
}
export const decode = (token: string) => { return verify(token) ? jws.decode(token)?.payload : undefined }

export const isAdmin = () => (req: Request, res: Response, next: NextFunction) => {
  const token = utils.jwtFrom(req)
  if (token && decode(token)?.data?.role === roles.admin) {
    next()
  } else {
    res.status(403).json({ error: 'Administrator access required' })
  }
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
    if (revokedTokens.has(token)) return
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    return token && verify(utils.unquote(token)) ? this.tokenMap[utils.unquote(token)] : undefined
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
  },
  revokeUserSessions: function (userId: number) {
    for (const [token, user] of Object.entries(this.tokenMap)) {
      if (user.data.id !== userId) continue
      const expiresAt = tokenExpiration(token)
      if (expiresAt > Date.now()) revokedTokens.set(token, expiresAt)
      delete this.tokenMap[token]
      if (this.idMap[userId] === token) delete this.idMap[userId]
    }
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
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  if (typeof url !== 'string') return false
  try {
    const target = new URL(url)
    if (target.username !== '' || target.password !== '') return false
    return [...redirectAllowlist].some(allowedUrl => target.href === new URL(allowedUrl).href)
  } catch {
    return false
  }
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
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error: unknown) {
      res.status(401).json({ status: 'error', message: utils.getErrorMessage(error) })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token && verify(token)) {
    const payload = decode(token)
    if (payload?.data?.id && authenticatedUsers.get(token) === undefined) {
      authenticatedUsers.put(token, payload)
      res.cookie('token', token, { sameSite: 'lax' })
    }
  }
  next()
}
