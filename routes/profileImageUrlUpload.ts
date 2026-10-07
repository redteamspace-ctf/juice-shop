/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

class BlockedImageUrlError extends Error {}

const internalNetworks = new net.BlockList()
for (const [address, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 3]] as const) {
  internalNetworks.addSubnet(address, prefix, 'ipv4')
}
for (const [address, prefix] of [['::', 128], ['::1', 128], ['::', 96], ['64:ff9b::', 96], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]] as const) {
  internalNetworks.addSubnet(address, prefix, 'ipv6')
}

function isInternalAddress (address: string) {
  let ip = address.toLowerCase()
  const mappedHex = ip.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/)
  if (mappedHex) {
    const high = parseInt(mappedHex[1], 16)
    const low = parseInt(mappedHex[2], 16)
    ip = [high >> 8, high & 255, low >> 8, low & 255].join('.')
  } else if (ip.startsWith('::ffff:') && net.isIPv4(ip.substring(7))) {
    ip = ip.substring(7)
  }
  if (net.isIP(ip) === 0) return true
  return internalNetworks.check(ip, net.isIPv4(ip) ? 'ipv4' : 'ipv6')
}

// Resolves the hostname and refuses internal addresses at connect time, so a DNS answer cannot change between check and use
const publicOnlyLookup: net.LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) { callback(err, '', 4); return }
    if (addresses.length === 0 || addresses.some(a => isInternalAddress(a.address))) {
      callback(new BlockedImageUrlError('Image URL points to an internal address'), '', 4)
      return
    }
    if (options.all) {
      (callback as any)(null, addresses)
    } else {
      callback(null, addresses[0].address, addresses[0].family)
    }
  })
}

// Only let the server fetch public http(s) URLs: no loopback, private, link-local or metadata addresses, and no redirects
async function fetchPublicImage (rawUrl: string) {
  const url = new URL(rawUrl)
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new BlockedImageUrlError('Only http and https image URLs are allowed')
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '')
  if (net.isIP(hostname) !== 0 && isInternalAddress(hostname)) {
    throw new BlockedImageUrlError('Image URL points to an internal address')
  }
  const client = url.protocol === 'https:' ? https : http
  return await new Promise<http.IncomingMessage>((resolve, reject) => {
    const request = client.get(url, { lookup: publicOnlyLookup, timeout: 10000 }, (response) => {
      if (response.statusCode === undefined || response.statusCode < 200 || response.statusCode >= 300) {
        response.resume()
        reject(new Error('url returned a non-OK status code'))
        return
      }
      resolve(response)
    })
    request.on('timeout', () => { request.destroy(new Error('Image URL timed out')) })
    request.on('error', reject)
  })
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetchPublicImage(url)
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(response.pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          if (error instanceof BlockedImageUrlError) {
            // Refuse the request instead of saving an internal URL as the profile image
            res.status(400)
            next(error)
            return
          }
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
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
