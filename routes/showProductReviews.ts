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
    const id = Number(req.params.id)

    // A $where clause built from a concatenated/templated string gets
    // eval'd as arbitrary JavaScript against every document — that's a
    // NoSQL injection (up to RCE/DoS, e.g. calling a blocking sleep()).
    // Passing an actual function instead means `id` is only ever used as
    // plain data in a fixed comparison, never as code to execute; `==`
    // (not `===`) is kept deliberately since seed/legacy review documents
    // store `product` as a mix of number and string.
    db.reviewsCollection.find({ $where: function (this: { product: number | string }) { return this.product == id } }).then((reviews: Review[]) => { // eslint-disable-line eqeqeq
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
