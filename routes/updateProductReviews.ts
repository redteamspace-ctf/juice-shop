/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
export function updateProductReviews () {
  return (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req) // vuln-code-snippet vuln-line forgedReviewChallenge
    if (typeof user?.data?.email !== 'string') {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    if (req.body == null || typeof req.body !== 'object' || typeof req.body.id !== 'string' || typeof req.body.message !== 'string') {
      res.status(400).json({ error: 'Invalid review' })
      return
    }
    db.reviewsCollection.update( // vuln-code-snippet neutral-line forgedReviewChallenge
      { _id: req.body.id, author: user.data.email }, // vuln-code-snippet vuln-line noSqlReviewsChallenge forgedReviewChallenge
      { $set: { message: req.body.message } },
      { multi: false } // vuln-code-snippet vuln-line noSqlReviewsChallenge
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 }) // vuln-code-snippet hide-line
        challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 }) // vuln-code-snippet hide-line
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
