/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { isIP } from 'node:net'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

function isAllowedImageUrl (value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 2048) return false
  try {
    const parsed = new URL(value)
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '')
    return (parsed.protocol === 'https:' || parsed.protocol === 'http:') &&
      !parsed.username && !parsed.password &&
      hostname.includes('.') &&
      hostname !== 'localhost' && !hostname.endsWith('.localhost') &&
      !hostname.endsWith('.local') && !hostname.endsWith('.internal') &&
      isIP(hostname) === 0
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (!isAllowedImageUrl(url)) {
        res.status(400).send('Invalid profile image URL')
        return
      }
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: url })
        } catch (error) {
          next(error)
          return
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
