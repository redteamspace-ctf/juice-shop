/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from '../data/types'
import * as db from '../data/mongodb'

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    try {
      const review = await db.reviewsCollection.findOne({ _id: id })
      if (!review) {
        return res.status(404).json({ error: 'Not found' })
      }

      const likedBy = review.likedBy
      if (likedBy.includes(user.data.email)) {
        return res.status(403).json({ error: 'Not allowed' })
      }

      // Check and write in ONE update: the old read, check, wait, write sequence let parallel requests all pass
      // the "not liked yet" check (race condition). $addToSet additionally guarantees one entry per user.
      const result = await db.reviewsCollection.update(
        { _id: id, likedBy: { $ne: user.data.email } },
        { $inc: { likesCount: 1 }, $addToSet: { likedBy: user.data.email } }
      )
      if (!result?.modified) {
        return res.status(403).json({ error: 'Not allowed' })
      }
      try {
        const updatedReview: Review = await db.reviewsCollection.findOne({ _id: id })
        const count = updatedReview.likedBy.filter(email => email === user.data.email).length
        challengeUtils.solveIf(challenges.timingAttackChallenge, () => count > 2)
        res.json(result)
      } catch (err) {
        res.status(500).json(err)
      }
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
