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
    if (!user?.data?.email) {
      return res.status(401).json({ status: 'error', message: 'You need to be logged in to write a review.' })
    }
    const productId = Number(req.params.id)
    if (!Number.isInteger(productId) || typeof req.body.message !== 'string') {
      return res.status(400).json({ status: 'error', message: 'Invalid review.' })
    }

    try {
      await reviewsCollection.insert({
        product: productId,
        message: req.body.message,
        // the author is always the authenticated user, never a client-supplied value
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
