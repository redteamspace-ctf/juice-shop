/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function logout () {
  return (req: Request, res: Response) => {
    const token = utils.jwtFrom(req) || req.cookies?.token
    if (typeof token !== 'string' || !security.revokeToken(token)) {
      res.sendStatus(401)
      return
    }

    res.clearCookie('token')
    res.sendStatus(204)
  }
}
