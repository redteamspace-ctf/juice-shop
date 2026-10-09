/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { CaptchaModel } from '../models/captcha'

// A CAPTCHA must only be solvable by a human: the arithmetic expression is rendered as a distorted
// SVG image (glyph outlines plus noise, no text) and neither the expression nor its answer is ever sent
// to the client. Every CAPTCHA is bound to the client that requested it, expires and allows one attempt.
const captchaLifetimeMs = 5 * 60 * 1000
const issuedCaptchas = new Map<number, { client: string, issuedAt: number }>()

const clientOf = (req: Request) => req.socket.remoteAddress ?? ''

export function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const operators = ['*', '+', '-']

    const firstTerm = Math.floor((Math.random() * 10) + 1)
    const secondTerm = Math.floor((Math.random() * 10) + 1)
    const thirdTerm = Math.floor((Math.random() * 10) + 1)

    const firstOperator = operators[Math.floor((Math.random() * 3))]
    const secondOperator = operators[Math.floor((Math.random() * 3))]

    const expression = firstTerm.toString() + firstOperator + secondTerm.toString() + secondOperator + thirdTerm.toString()
    const answer = eval(expression).toString() // eslint-disable-line no-eval

    const { default: svgCaptcha } = await import('svg-captcha')
    // svg-captcha's module export renders a given text (its type definitions only declare the named helpers)
    const renderCaptcha = svgCaptcha as unknown as (text: string, options: Record<string, unknown>) => string
    const image = renderCaptcha(expression, { noise: 2, color: false, background: '#ffffff', width: 180, height: 50, fontSize: 48 })

    await CaptchaModel.build({ captchaId, captcha: expression, answer }).save()
    const now = Date.now()
    if (issuedCaptchas.size > 10000) {
      for (const [id, { issuedAt }] of issuedCaptchas) if (now - issuedAt > captchaLifetimeMs) issuedCaptchas.delete(id)
    }
    issuedCaptchas.set(captchaId, { client: clientOf(req), issuedAt: now })
    res.json({ captchaId, image })
  }
}

// At most 9 feedbacks may pass the CAPTCHA per client within any 20 second window, so 10 or more within
// 20 seconds (automated submission) is impossible, while a few legitimate submissions in a row still go through
const feedbackWindowMs = 20000
const maxFeedbacksPerWindow = 9
const acceptedFeedbacks = new Map<string, number[]>()

export const resetFeedbackThrottle = () => { acceptedFeedbacks.clear() }

export const throttleFeedback = () => (req: Request, res: Response, next: NextFunction) => {
  const client = clientOf(req)
  const now = Date.now()
  const recent = (acceptedFeedbacks.get(client) ?? []).filter(time => now - time <= feedbackWindowMs)
  if (recent.length >= maxFeedbacksPerWindow) {
    acceptedFeedbacks.set(client, recent)
    res.set('Retry-After', String(Math.max(1, Math.ceil((recent[0] + feedbackWindowMs + 1 - now) / 1000))))
    res.status(429).send(res.__('Too many feedback submissions. Please try again in a few seconds.'))
    return
  }
  if (acceptedFeedbacks.size > 10000) acceptedFeedbacks.clear()
  recent.push(now)
  acceptedFeedbacks.set(client, recent)
  next()
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const captchaId = Number(req.body.captchaId)
    const issued = Number.isSafeInteger(captchaId) ? issuedCaptchas.get(captchaId) : undefined
    issuedCaptchas.delete(captchaId)
    const captcha = issued !== undefined ? await CaptchaModel.findOne({ where: { captchaId } }) : null
    // Each CAPTCHA allows exactly one attempt, so it can be neither replayed nor brute-forced
    const consumed = issued !== undefined && await CaptchaModel.destroy({ where: { captchaId } }) === 1
    const valid = issued !== undefined && issued.client === clientOf(req) && Date.now() - issued.issuedAt <= captchaLifetimeMs
    if ((captcha != null) && consumed && valid && String(req.body.captcha ?? '').trim() === captcha.answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    next(error)
  }
}
