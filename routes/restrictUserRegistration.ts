/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

export function restrictUserRegistration () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body === null || typeof req.body !== 'object' || Array.isArray(req.body)) {
      res.status(400).send(res.__('Invalid registration data.'))
      return
    }

    const { username, email, password, passwordRepeat } = req.body
    req.body = { username, email, password, passwordRepeat }
    next()
  }
}
