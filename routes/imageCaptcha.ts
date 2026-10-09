/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'

import { ImageCaptchaModel } from '../models/imageCaptcha'
import * as security from '../lib/insecurity'

export function imageCaptchas () {
  return async (req: Request, res: Response) => {
    try {
      const { default: svgCaptcha } = await import('svg-captcha')
      const captcha = svgCaptcha.create({ size: 5, noise: 2, color: true })

      const user = security.authenticatedUsers.from(req)
      if (!user) {
        res.status(401).send(res.__('You need to be logged in to request a CAPTCHA.'))
        return
      }

      const imageCaptcha = {
        image: captcha.data,
        answer: captcha.text,
        UserId: user.data.id
      }
      const imageCaptchaInstance = ImageCaptchaModel.build(imageCaptcha)
      await imageCaptchaInstance.save()
      // Only the picture leaves the server: the answer has to be read by a human, never by a script
      res.json({ image: imageCaptcha.image })
    } catch (error) {
      res.status(400).send(res.__('Unable to create CAPTCHA. Please try again.'))
    }
  }
}

const sameAnswer = (given: unknown, expected: string) => {
  if (typeof given !== 'string') return false
  const a = crypto.createHash('sha256').update(given.trim().toLowerCase()).digest()
  const b = crypto.createHash('sha256').update(expected.toLowerCase()).digest()
  return crypto.timingSafeEqual(a, b)
}

export const verifyImageCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = security.authenticatedUsers.from(req)
    const UserId = user?.data?.id
    if (UserId === undefined) {
      res.status(401).send(res.__('You need to be logged in to request a CAPTCHA.'))
      return
    }
    const latest = await ImageCaptchaModel.findOne({
      where: {
        UserId,
        createdAt: {
          [Op.gt]: new Date(Date.now() - 300000)
        }
      },
      order: [['createdAt', 'DESC']]
    })
    // Every attempt uses up the user's pending CAPTCHAs, so an answer can neither be reused nor guessed twice
    await ImageCaptchaModel.destroy({ where: { UserId } })
    // An export is only allowed with the answer to a CAPTCHA this server issued to this user
    if (latest !== null && sameAnswer(req.body.answer, latest.answer)) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    res.status(401).send(res.__('Something went wrong while submitting CAPTCHA. Please try again.'))
  }
}
