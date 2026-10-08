/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import { reviewsCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function createProductReviews () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    if (user?.data?.email === undefined) {
      return res.status(401).json({ error: 'Authentication required' })
    }
    if (typeof req.body.message !== 'string' || !/^\d+$/.test(req.params.id)) {
      return res.status(400).json({ error: 'Invalid review' })
    }

    try {
      await reviewsCollection.insert({
        product: Number(req.params.id),
        message: security.sanitizeHtml(req.body.message),
        author: user.data.email,
        likesCount: 0,
        likedBy: []
      })
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json(utils.getErrorMessage(err))
    }
  }
}
