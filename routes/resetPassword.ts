/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

// Security answers can often be found or guessed from public information, so a
// correct answer alone must never be enough to take over an account. Resetting a
// password on the fly by answering the security question is therefore no longer
// offered; it needs a one-time link sent to the registered email address instead.
export function resetPassword () {
  return (req: Request, res: Response) => {
    res.status(401).send(res.__('Password reset via security question is no longer available. Please contact support.'))
  }
}
