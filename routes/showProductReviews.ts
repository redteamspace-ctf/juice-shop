/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { type Review } from 'data/types'
import * as db from '../data/mongodb'
import * as utils from '../lib/utils'

export function showProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    // Product ids are integers - anything else is rejected instead of being
    // concatenated into a server-side JavaScript ($where) predicate (NoSQL injection / DoS)
    const id = Number(req.params.id)
    if (!Number.isInteger(id)) {
      res.status(400).json({ error: 'Wrong Params' })
      return
    }

    // structured equality query (reviews may store the product id as number or string)
    db.reviewsCollection.find({ product: { $in: [id, String(id)] } }).then((reviews: Review[]) => {
      const user = security.authenticatedUsers.from(req)
      for (let i = 0; i < reviews.length; i++) {
        if (user === undefined || reviews[i].likedBy.includes(user.data.email)) {
          reviews[i].liked = true
        }
      }
      res.json(utils.queryResultToJson(reviews))
    }, () => {
      res.status(400).json({ error: 'Wrong Params' })
    })
  }
}
