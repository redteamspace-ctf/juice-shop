/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { isIP } from 'node:net'
import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

function isPublicImageHost (hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase()
  if (host === 'localhost' || /\.(localhost|local|internal)$/.test(host) || !host.includes('.')) {
    if (!host.includes(':')) return false
  }
  if (isIP(host) === 4) {
    const [a, b, c] = host.split('.').map(Number)
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113))
  }
  if (isIP(host) === 6) return /^[23][0-9a-f]{3}:/.test(host) && !host.startsWith('2001:db8:')
  return host.includes('.')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      res.status(401).json({ error: 'Authentication required' })
      return
    }
    if (req.body.imageUrl !== undefined) {
      let imageUrl: URL
      try {
        if (typeof req.body.imageUrl !== 'string' || req.body.imageUrl.length > 2048) throw new Error('Invalid image URL')
        imageUrl = new URL(req.body.imageUrl)
        if (!['https:', 'http:'].includes(imageUrl.protocol) || imageUrl.username || imageUrl.password || !isPublicImageHost(imageUrl.hostname)) throw new Error('Invalid image URL')
      } catch {
        res.status(400).json({ error: 'Invalid image URL' })
        return
      }
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        if (!user) {
          res.status(404).json({ error: 'User not found' })
          return
        }
        await user.update({ profileImage: imageUrl.href })
      } catch (error) {
        next(error)
        return
      }
    }
    res.redirect((process.env.BASE_PATH ?? '') + '/profile')
  }
}
