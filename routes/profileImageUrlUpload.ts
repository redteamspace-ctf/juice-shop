/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import dns from 'node:dns/promises'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// Address ranges the server must never be tricked into requesting (SSRF):
// loopback, private networks, link-local (incl. cloud metadata 169.254.169.254),
// carrier-grade NAT, multicast and other reserved ranges.
const internalAddresses = new net.BlockList()
internalAddresses.addSubnet('0.0.0.0', 8, 'ipv4')
internalAddresses.addSubnet('10.0.0.0', 8, 'ipv4')
internalAddresses.addSubnet('100.64.0.0', 10, 'ipv4')
internalAddresses.addSubnet('127.0.0.0', 8, 'ipv4')
internalAddresses.addSubnet('169.254.0.0', 16, 'ipv4')
internalAddresses.addSubnet('172.16.0.0', 12, 'ipv4')
internalAddresses.addSubnet('192.0.0.0', 24, 'ipv4')
internalAddresses.addSubnet('192.0.2.0', 24, 'ipv4')
internalAddresses.addSubnet('192.168.0.0', 16, 'ipv4')
internalAddresses.addSubnet('198.18.0.0', 15, 'ipv4')
internalAddresses.addSubnet('198.51.100.0', 24, 'ipv4')
internalAddresses.addSubnet('203.0.113.0', 24, 'ipv4')
internalAddresses.addSubnet('224.0.0.0', 4, 'ipv4')
internalAddresses.addSubnet('240.0.0.0', 4, 'ipv4')
internalAddresses.addAddress('::', 'ipv6')
internalAddresses.addAddress('::1', 'ipv6')
internalAddresses.addSubnet('64:ff9b::', 96, 'ipv6')
internalAddresses.addSubnet('100::', 64, 'ipv6')
internalAddresses.addSubnet('2001:db8::', 32, 'ipv6')
internalAddresses.addSubnet('fc00::', 7, 'ipv6')
internalAddresses.addSubnet('fe80::', 10, 'ipv6')
internalAddresses.addSubnet('ff00::', 8, 'ipv6')

function isInternalAddress (address: string): boolean {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)
  if (mapped !== null) {
    return internalAddresses.check(mapped[1], 'ipv4')
  }
  const family = net.isIP(address)
  if (family === 4) return internalAddresses.check(address, 'ipv4')
  if (family === 6) return internalAddresses.check(address, 'ipv6')
  return true // not an IP address at all - treat as unsafe
}

async function isSafeExternalUrl (rawUrl: string): Promise<boolean> {
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    return false
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return false
  }
  if (url.username !== '' || url.password !== '') {
    return false
  }
  const hostname = url.hostname.replace(/^\[(.*)\]$/, '$1')
  if (hostname === '') {
    return false
  }
  let addresses: string[]
  if (net.isIP(hostname) !== 0) {
    addresses = [hostname]
  } else {
    try {
      addresses = (await dns.lookup(hostname, { all: true, verbatim: true })).map(({ address }) => address)
    } catch {
      return false
    }
  }
  return addresses.length > 0 && !addresses.some(isInternalAddress)
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (typeof url !== 'string' || !(await isSafeExternalUrl(url))) {
          res.status(400).json({ status: 'error', message: 'Image URL must be a public http(s) URL.' })
          return
        }
        try {
          // redirects are not followed, so an external URL cannot bounce the request to an internal target
          const response = await fetch(url, { redirect: 'error' })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: new URL(url).href })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
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
