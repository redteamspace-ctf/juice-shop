/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'

export function b2bOrder () {
  return ({ body }: Request, res: Response) => {
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
      res.status(400).json({ error: 'Invalid order data' })
      return
    }

    const orderLinesData = body.orderLinesData
    if (orderLinesData !== undefined && (typeof orderLinesData !== 'string' || orderLinesData.length > 65536)) {
      res.status(400).json({ error: 'Invalid order data' })
      return
    }

    // This legacy field is opaque input. Never interpret its contents as code
    // or parse them as JSON; older B2B clients may send serialized data here.
    res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
