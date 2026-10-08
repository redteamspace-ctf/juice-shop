/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import { isIP } from 'node:net'

export function saveLoginIp () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (loggedInUser !== undefined) {
      const clientIp = utils.toSimpleIpAddress(req.ip ?? req.socket.remoteAddress ?? '')
      const lastLoginIp = isIP(clientIp) ? clientIp : '0.0.0.0'
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        const updatedUser = await user?.update({ lastLoginIp: lastLoginIp?.toString() })
        res.json({ lastLoginIp: updatedUser?.lastLoginIp })
      } catch (error) {
        next(error)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
