/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import dns from 'node:dns'
import net from 'node:net'
import http from 'node:http'
import https from 'node:https'
import { Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import config from 'config'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      // The session token may come from the cookie (web UI) or the Authorization header (API clients)
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token) ?? security.authenticatedUsers.from(req)
      if (loggedInUser) {
        const url = parseHttpUrl(req.body.imageUrl)
        let profileImage: string | undefined
        const localImage = url !== null ? localPublicImage(url, req) : null
        if (localImage !== null) {
          // The shop's own public images are copied from disk instead of being requested over the network
          profileImage = await copyLocalImage(localImage, loggedInUser.data.id)
        } else if (url === null || isInternalHost(url) || await resolvesToInternalAddress(url)) {
          // Never request (or link to) anything but plain public http(s) image links, and say so
          logger.warn(`Refused user profile image URL: ${String(req.body.imageUrl).substring(0, 200)}`)
          refuseImageUrl(res)
          return
        } else if (!isAllowListedHost(url)) {
          // OWASP SSRF Prevention (case 1): the server only ever talks to identified, trusted image hosts.
          // Any other public link is kept as a plain link that the user's browser loads, never fetched by the server.
          profileImage = url.href
        } else {
          profileImage = url.href
          try {
            profileImage = await storeDownloadedImage(url, loggedInUser.data.id)
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code === 'EBLOCKED') {
              logger.warn(`Refused user profile image from an internal address: ${url.hostname}`)
              refuseImageUrl(res)
              return
            } else {
              logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
            }
          }
        }
        if (profileImage !== undefined) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage })
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

// A refused image URL is answered explicitly instead of silently redirecting as if it had been accepted
function refuseImageUrl (res: Response) {
  res.status(400).json({ status: 'error', message: 'The profile image URL has to point to a public http(s) image.' })
}

// Trusted image hosts (exact host or a subdomain of it), e.g. application.profileImageUrlAllowlist: [cataas.com]
function allowList () {
  const hosts = config.has('application.profileImageUrlAllowlist') ? config.get<unknown>('application.profileImageUrlAllowlist') : []
  return Array.isArray(hosts) ? hosts.filter((host): host is string => typeof host === 'string' && host.trim() !== '').map(host => host.trim().toLowerCase().replace(/^\.+|\.+$/g, '')) : []
}

function isAllowListedHost (url: URL) {
  const host = url.hostname.toLowerCase().replace(/\.$/, '')
  if (net.isIP(host.replace(/^\[|\]$/g, '')) !== 0) return false // only named, trusted hosts; never raw IP addresses
  if (url.port !== '') return false // only the scheme's default port, never a user-chosen one
  if (url.username !== '' || url.password !== '') return false
  return allowList().some(allowed => host === allowed || host.endsWith('.' + allowed))
}

const maxImageBytes = 5 * 1024 * 1024

async function storeDownloadedImage (url: URL, userId: number) {
  const response = await downloadImage(url)
  const contentType = String(response.headers['content-type'] ?? '').toLowerCase()
  const contentLength = Number(response.headers['content-length'] ?? 0)
  if (response.statusCode !== 200 || !/^image\/(png|jpe?g|gif)(;|$)/.test(contentType) || contentLength > maxImageBytes) {
    response.resume()
    throw new Error('url did not return an image') // redirects (3xx) are never followed
  }
  const ext = contentType.includes('png') ? 'png' : contentType.includes('gif') ? 'gif' : 'jpg'
  let received = 0
  const limit = new Transform({
    transform (chunk: Buffer, _encoding, callback) {
      received += chunk.length
      callback(received > maxImageBytes ? new Error('image is too large') : null, chunk)
    }
  })
  const file = `${uploadsDir}/${userId}.${ext}`
  try {
    await pipeline(response, limit, fs.createWriteStream(file, { flags: 'w' }))
  } catch (error) {
    await fs.promises.rm(file, { force: true })
    throw error
  }
  return `/assets/public/images/uploads/${userId}.${ext}`
}

const publicImagesDir = path.resolve('frontend/dist/frontend/assets/public/images')
const uploadsDir = 'frontend/dist/frontend/assets/public/images/uploads'
const imageExtensions = ['jpg', 'jpeg', 'png', 'svg', 'gif']

// Links without a scheme (e.g. "cataas.com/cat") are taken as https:// links, then validated like any other URL
function parseHttpUrl (value: unknown) {
  if (typeof value !== 'string') return null
  const link = value.trim()
  try {
    const url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(link) ? link : `https://${link}`)
    return url.protocol === 'http:' || url.protocol === 'https:' ? url : null
  } catch {
    return null
  }
}

// A link to one of the shop's own public images (e.g. http://localhost:3000/assets/public/images/uploads/default.svg)
// resolves to the file on disk; nothing else on the server itself is ever reachable this way
function localPublicImage (url: URL, req: Request) {
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  const port = url.port !== '' ? Number(url.port) : (url.protocol === 'https:' ? 443 : 80)
  const sameHost = url.host.toLowerCase() === String(req.get('host') ?? '').toLowerCase()
  const loopback = host === 'localhost' || host.endsWith('.localhost') || (net.isIP(host) !== 0 && isLoopbackAddress(host))
  if (!sameHost && !(loopback && port === req.socket.localPort)) return null
  let pathname: string
  try {
    pathname = decodeURIComponent(url.pathname)
  } catch {
    return null
  }
  const prefix = '/assets/public/images/'
  if (!pathname.startsWith(prefix)) return null
  const file = path.resolve(publicImagesDir, pathname.slice(prefix.length))
  if (!file.startsWith(publicImagesDir + path.sep)) return null
  if (!imageExtensions.includes(path.extname(file).slice(1).toLowerCase())) return null
  try {
    return fs.statSync(file).isFile() ? file : null
  } catch {
    return null
  }
}

async function copyLocalImage (file: string, userId: number) {
  const ext = path.extname(file).slice(1).toLowerCase()
  const target = path.resolve(uploadsDir, `${userId}.${ext}`)
  try {
    if (file !== target) await fs.promises.copyFile(file, target)
    return `/assets/public/images/uploads/${userId}.${ext}`
  } catch (error) {
    logger.warn(`Error copying user profile image: ${utils.getErrorMessage(error)}`)
    return undefined
  }
}

const loopbackAddresses = new net.BlockList()
loopbackAddresses.addSubnet('127.0.0.0', 8, 'ipv4')
loopbackAddresses.addAddress('::1', 'ipv6')

function isLoopbackAddress (address: string) {
  return loopbackAddresses.check(address, net.isIP(address) === 6 ? 'ipv6' : 'ipv4')
}

// Loopback, private, link-local (cloud metadata), CGNAT, multicast/reserved ranges
// and their IPv6 forms; BlockList matches IPv4-mapped IPv6 (::ffff:a.b.c.d) against the IPv4 rules
const blockedAddresses = new net.BlockList()
for (const [network, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 3]] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv4')
}
for (const [network, prefix] of [['::', 96], ['64:ff9b::', 96], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]] as const) {
  blockedAddresses.addSubnet(network, prefix, 'ipv6')
}

function isBlockedAddress (address: string) {
  const family = net.isIP(address)
  return family === 0 || blockedAddresses.check(address, family === 6 ? 'ipv6' : 'ipv4')
}

// Decide on the addresses a name really points to: a host that can't be resolved, or that resolves to any
// internal address (e.g. a service name inside the server's own network), is refused before anything else
async function resolvesToInternalAddress (url: URL) {
  const host = url.hostname.replace(/^\[|\]$/g, '')
  if (net.isIP(host) !== 0) return isBlockedAddress(host)
  try {
    const addresses = await dns.promises.lookup(host, { all: true, verbatim: true })
    return addresses.length === 0 || addresses.some(({ address }) => isBlockedAddress(address))
  } catch {
    return true
  }
}

function isInternalHost (url: URL) {
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (net.isIP(host) !== 0) return isBlockedAddress(host)
  return host === 'localhost' || host.endsWith('.localhost')
}

// Resolves the host and lets the socket connect only to the addresses that were checked (no DNS rebinding)
const safeLookup: net.LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) { callback(err, ''); return }
    if (addresses.length === 0 || addresses.some(({ address }) => isBlockedAddress(address))) {
      callback(Object.assign(new Error('Image URL resolves to an internal address'), { code: 'EBLOCKED' }), '')
      return
    }
    if (options.all) callback(null, addresses)
    else callback(null, addresses[0].address, addresses[0].family)
  })
}

async function downloadImage (url: URL) {
  return await new Promise<http.IncomingMessage>((resolve, reject) => {
    const client = url.protocol === 'https:' ? https : http
    // http(s).get never follows redirects, so a public URL cannot bounce to an internal one
    client.get(url, { lookup: safeLookup, signal: AbortSignal.timeout(4000) }, resolve).on('error', reject)
  })
}
