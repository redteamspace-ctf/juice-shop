/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'

export function trackOrder () {
  return (req: Request, res: Response) => {
    // Always strip anything that isn't a word character or hyphen — this
    // value gets echoed back verbatim when no order matches, so it must
    // never carry HTML/script content (reflected XSS). Truncate too, as a
    // belt-and-suspenders bound on size.
    const id = utils.trunc(String(req.params.id).replace(/[^\w-]+/g, ''), 60)

    // A $where built from a template string gets eval'd as arbitrary
    // JavaScript (NoSQL injection) — pass an actual function instead so id
    // is only ever compared as data, never executed as code.
    db.ordersCollection.find({ $where: function (this: { orderId: string }) { return this.orderId === id } }).then((order: any) => {
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
