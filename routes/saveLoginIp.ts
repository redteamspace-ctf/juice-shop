/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import net from 'node:net'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

export function saveLoginIp () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (loggedInUser !== undefined) {
      let lastLoginIp: string | undefined = Array.isArray(req.headers['true-client-ip']) ? req.headers['true-client-ip'][0] : req.headers['true-client-ip']
      // The header is attacker-controlled: only accept a syntactically valid IP address,
      // never arbitrary (HTML) content that would later be rendered to the user.
      if (typeof lastLoginIp !== 'string' || net.isIP(lastLoginIp.trim()) === 0) {
        lastLoginIp = utils.toSimpleIpAddress(req.socket.remoteAddress ?? '')
      } else {
        lastLoginIp = lastLoginIp.trim()
      }
      lastLoginIp = security.sanitizeSecure(lastLoginIp)
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        const updatedUser = await user?.update({ lastLoginIp: lastLoginIp?.toString() })
        // never echo credential material (password hash, TOTP secret) back to the client
        const safeUser: Record<string, unknown> | undefined = updatedUser ? { ...updatedUser.get({ plain: true }) } : undefined
        if (safeUser) {
          delete safeUser.password
          delete safeUser.totpSecret
        }
        res.json(safeUser)
      } catch (error) {
        next(error)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
