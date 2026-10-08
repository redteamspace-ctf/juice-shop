/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// SSRF guard: a "set my profile image from a URL" feature that fetches
// whatever host the client names is a textbook request forgery vector —
// it can reach internal services, cloud metadata endpoints, or the app's
// own internal/admin routes, none of which the client could reach
// directly. Resolve the hostname and refuse anything that isn't a public
// address, before ever issuing the fetch.
function isPrivateOrReservedIp (ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number)
    return (
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a === 0
    )
  }
  const lower = ip.toLowerCase()
  return lower === '::1' || lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')
}

async function isSafeImageUrl (url: string): Promise<boolean> {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return false
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false
  }
  if (net.isIP(parsed.hostname) && isPrivateOrReservedIp(parsed.hostname)) {
    return false
  }
  try {
    const records = await dns.lookup(parsed.hostname, { all: true })
    return records.every(({ address }) => !isPrivateOrReservedIp(address))
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        // Reject an unsafe target outright — it must never reach the
        // catch-all fallback below, which (for ordinary fetch failures)
        // falls back to storing the raw URL as the profile image. That
        // fallback existing at all is fine for a genuinely external image
        // host that just can't be proxied; it must not become a backdoor
        // around the SSRF check for a URL we already know points
        // somewhere it shouldn't.
        if (!(await isSafeImageUrl(url))) {
          next(new Error('Invalid image URL'))
          return
        }
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
