/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'

export function trackOrder () {
  return (req: Request, res: Response) => {
    // Order ids only consist of word characters and dashes. Stripping everything else
    // prevents reflecting HTML/JavaScript back to the client (reflected XSS).
    const id = utils.trunc(String(req.params.id).replace(/[^\w-]+/g, ''), 60)

    // Structured equality query instead of a server-side JavaScript $where predicate,
    // so the id can never be interpreted as code (NoSQL injection).
    db.ordersCollection.find({ orderId: id }).then((order: any) => {
      const result = utils.queryResultToJson(order)
      if (result.data[0] === undefined) {
        result.data[0] = { orderId: id }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
