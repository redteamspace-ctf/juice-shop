/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    // orderLinesData was previously run through a "sandboxed" eval
    // (notevil, inside a vm context) — arbitrary code execution as a
    // feature, which is exactly what rceChallenge/rceOccupyChallenge
    // exploit (sandbox breakout, and an infinite loop/ReDoS that hangs the
    // request past the vm timeout). Its result was never even used in the
    // response below, so there was no legitimate business logic requiring
    // code execution here in the first place — orderLinesData is accepted
    // as opaque data only.
    res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
