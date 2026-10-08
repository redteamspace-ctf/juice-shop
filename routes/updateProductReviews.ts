/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)

    // NoSQL injection guard: req.body.id must be a plain string, never an
    // object (e.g. { $gt: '' }) that MongoDB would interpret as a query
    // operator and match far more documents than intended.
    if (typeof req.body.id !== 'string') {
      res.status(400).send()
      return
    }

    db.reviewsCollection.update(
      // Ownership check: a review can only ever be edited by the user who
      // authored it — otherwise anyone could forge edits to someone else's
      // review.
      { _id: req.body.id, author: user?.data?.email },
      { $set: { message: req.body.message } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
