/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const blockedNetworks = new net.BlockList()
for (const [address, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 3]] as const) {
  blockedNetworks.addSubnet(address, prefix, 'ipv4')
}
for (const [address, prefix] of [['::', 128], ['::1', 128], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]] as const) {
  blockedNetworks.addSubnet(address, prefix, 'ipv6')
}

function isBlockedAddress (address: string) {
  const family = net.isIP(address)
  if (family === 0) return true
  if (family === 6 && address.toLowerCase().startsWith('::ffff:')) {
    const mapped = address.substring(7)
    if (net.isIPv4(mapped)) return blockedNetworks.check(mapped, 'ipv4')
  }
  return blockedNetworks.check(address, family === 4 ? 'ipv4' : 'ipv6')
}

async function assertPublicImageUrl (rawUrl: string) {
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    throw new Error('Image URL is not a valid URL')
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Only http and https image URLs are allowed')
  }
  if (url.username || url.password) {
    throw new Error('Credentials in image URLs are not allowed')
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '')
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    throw new Error('Image URL points to an internal host')
  }
  if (net.isIP(hostname) !== 0) {
    if (isBlockedAddress(hostname)) throw new Error('Image URL points to an internal address')
    return url
  }
  const addresses = await dns.lookup(hostname, { all: true })
  if (addresses.length === 0 || addresses.some(entry => isBlockedAddress(entry.address))) {
    throw new Error('Image URL points to an internal address')
  }
  return url
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = String(req.body.imageUrl)
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const target = await assertPublicImageUrl(url)
          // No redirects: a public host must not be able to bounce the request to an internal address
          const response = await fetch(target, { redirect: 'error', signal: AbortSignal.timeout(10000) })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const extCandidate = target.pathname.split('.').slice(-1)[0].toLowerCase()
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(extCandidate) ? extCandidate : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          // The supplied URL is never stored as the profile image: it would end up in a CSP header and in the page
          logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}`)
          res.status(400)
          next(new Error('Profile image URL could not be retrieved'))
          return
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
