/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { CaptchaModel } from '../models/captcha'

const feedbackSubmissions = new Map<string, number[]>()
const feedbackWindowMs = 20_000
const maxFeedbackSubmissions = 9
let lastFeedbackCleanup = Date.now()

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

    const captcha = {
      captchaId,
      captcha: expression,
      answer
    }
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    res.json({ captchaId, captcha: expression })
  }
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!Number.isSafeInteger(req.body.captchaId) || typeof req.body.captcha !== 'string') {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
      return
    }

    const consumed = await CaptchaModel.destroy({ where: { captchaId: req.body.captchaId, answer: req.body.captcha } })
    if (consumed !== 1) {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
      return
    }

    const source = req.socket.remoteAddress ?? 'unknown'
    const now = Date.now()
    if (now - lastFeedbackCleanup >= feedbackWindowMs) {
      for (const [address, times] of feedbackSubmissions) {
        if (times.every(time => now - time >= feedbackWindowMs)) feedbackSubmissions.delete(address)
      }
      lastFeedbackCleanup = now
    }
    const recent = (feedbackSubmissions.get(source) ?? []).filter(time => now - time < feedbackWindowMs)
    if (recent.length >= maxFeedbackSubmissions) {
      feedbackSubmissions.set(source, recent)
      res.status(429).send(res.__('Too many feedback submissions. Please try again later.'))
      return
    }
    recent.push(now)
    feedbackSubmissions.set(source, recent)
    next()
  } catch (error) {
    next(error)
  }
}
