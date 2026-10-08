/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import fs from 'node:fs/promises'

import { themes } from '../views/themes/themes'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    let username = user.username

    // Usernames matching Pug/template interpolation syntax (#{...}) used to
    // have the inner text eval()'d as live JavaScript — full server-side
    // template injection / RCE from a profile field. A username is display
    // data, never code, regardless of what it looks like.
    username = '\\' + username

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    if (username) {
      template = template.replace(/_username_/g, username)
    }
    template = template.replace(/_emailHash_/g, security.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    try {
      const pug = (await import('pug')).default
      const fn = pug.compile(template)
      // profileImage is interpolated straight into a CSP header value — a
      // stored URL containing ';' can terminate the img-src directive and
      // inject additional ones (e.g. "script-src 'self' 'unsafe-inline'",
      // reopening the exact inline-script hole CSP exists to close). A
      // legitimate image URL/path never needs a semicolon.
      const safeProfileImage = typeof user?.profileImage === 'string' ? user.profileImage.replace(/;/g, '') : user?.profileImage
      const CSP = `img-src 'self' ${safeProfileImage}; script-src 'self' 'unsafe-eval'`

      res.set({
        'Content-Security-Policy': CSP
      })

      res.send(fn(user))
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
