/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

export function changePassword () {
  return async ({ query, headers, connection }: Request, res: Response, next: NextFunction) => {
    const currentPassword = query.current
    const newPassword = query.new
    const repeatPassword = query.repeat

    if (typeof newPassword !== 'string' || !newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'))
      return
    } else if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
      return
    }

    const token = headers.authorization ? headers.authorization.substr('Bearer='.length) : null
    if (token === null) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }

    const loggedInUser = security.authenticatedUsers.get(token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }

    if (typeof currentPassword !== 'string' || !currentPassword) {
      res.status(401).send(res.__('Current password is not correct.'))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        res.status(404).send(res.__('User not found.'))
        return
      }

      if (security.hash(currentPassword) !== user.password) {
        res.status(401).send(res.__('Current password is not correct.'))
        return
      }

      await user.update({ password: newPassword })
      security.authenticatedUsers.put(token, { ...loggedInUser, data: user })
      challengeUtils.solveIf(
        challenges.changePasswordBenderChallenge,
        () => user.id === 3 && !currentPassword && user.password === security.hash('slurmCl4ssic')
      )
      res.json({ user: { id: user.id, email: user.email } })
    } catch (error) {
      next(error)
    }
  }
}
