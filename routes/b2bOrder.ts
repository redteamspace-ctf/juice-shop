/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    // orderLinesData is DATA: it is parsed as JSON and never evaluated as code (no eval/sandbox of client input)
    if (body.orderLinesData !== undefined && body.orderLinesData !== '') {
      let orderLines: unknown
      try {
        orderLines = typeof body.orderLinesData === 'string' ? JSON.parse(body.orderLinesData) : body.orderLinesData
      } catch {
        res.status(400).json({ error: 'orderLinesData must be valid JSON' })
        return
      }
      if (!Array.isArray(orderLines)) {
        res.status(400).json({ error: 'orderLinesData must be a JSON array of order lines' })
        return
      }
    }
    res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
