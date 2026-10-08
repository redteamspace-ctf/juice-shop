/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

// Only non-sensitive user attributes may be requested via ?fields=
// (never password hashes, TOTP secrets or deluxe tokens)
const PUBLIC_USER_FIELDS = new Set(['id', 'email', 'username', 'role', 'lastLoginIp', 'profileImage', 'isActive', 'createdAt', 'updatedAt'])

export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let user
    let response: any
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    try {
      if (security.verify(req.cookies.token)) {
        user = security.authenticatedUsers.get(req.cookies.token)

        // Parse the fields parameter into an array, splitting by comma.
        // If not provided, both these variables will be undefined.
        const fieldsParam = req.query?.fields as string | undefined
        const requestedFields = typeof fieldsParam === 'string' ? fieldsParam.split(',').map(f => f.trim()).filter(f => PUBLIC_USER_FIELDS.has(f)) : []

        let baseUser: any = {}

        if (typeof fieldsParam === 'string' && fieldsParam.length > 0) {
          // When fields are specified, return only those fields
          for (const field of requestedFields) {
            if (user?.data[field as keyof typeof user.data] !== undefined) {
              baseUser[field] = user?.data[field as keyof typeof user.data]
            }
          }
        } else {
          // If no fields parameter, return standard fields (not password field)
          baseUser = {
            id: user?.data?.id,
            email: user?.data?.email,
            lastLoginIp: user?.data?.lastLoginIp,
            profileImage: user?.data?.profileImage
          }
        }

        response = { user: baseUser }
      } else {
        response = { user: emptyUser }
      }
    } catch (err) {
      response = { user: emptyUser }
    }
    // Solve passwordHashLeakChallenge when password field is included in response
    challengeUtils.solveIf(challenges.passwordHashLeakChallenge, () => response?.user?.password)

    if (req.query.callback === undefined) {
      res.json(response)
    } else {
      challengeUtils.solveIf(challenges.emailLeakChallenge, () => { return true })
      res.jsonp(response)
    }
  }
}
