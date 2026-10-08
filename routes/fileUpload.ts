/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      const buffer = file.buffer
      const filename = file.originalname.toLowerCase()
      const tempFile = path.join(os.tmpdir(), filename)
      fs.open(tempFile, 'w', function (err, fd) {
        if (err != null) { next(err) }
        fs.write(fd, buffer, 0, buffer.length, null, function (err) {
          if (err != null) { next(err) }
          fs.close(fd, function () {
            fs.createReadStream(tempFile)
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                const fileName = entry.path
                const targetDir = path.resolve('uploads/complaints')
                const absolutePath = path.resolve(targetDir, fileName)
                challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return absolutePath === path.resolve('ftp/legal.md') })
                // Zip entries must stay inside the complaints folder ("../" in entry names = Zip Slip)
                if (absolutePath.startsWith(targetDir + path.sep)) {
                  entry.pipe(fs.createWriteStream(absolutePath).on('error', function (err) { next(err) }))
                } else {
                  entry.autodrain()
                }
              }).on('error', function (err: unknown) { next(err) })
          })
        })
      })
    }
    res.status(204).end()
  } else {
    next()
  }
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  // The 100 kB limit shown in the UI is enforced here too, not only in the browser
  if (file != null && file.size > 100000) {
    res.status(413)
    next(new Error('File too large. Maximum size is 100 kB.'))
    return
  }
  if (file != null) {
    challengeUtils.solveIf(challenges.uploadSizeChallenge, () => { return file?.size > 100000 })
  }
  next()
}

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  // Only PDF and ZIP complaints are accepted (XML/YAML belong to the retired B2B interface)
  if (fileType === 'xml' || fileType === 'yml' || fileType === 'yaml') {
    rejectDeprecatedUpload(file!, res, next)
    return
  }
  if (fileType !== 'pdf' && fileType !== 'zip') {
    res.status(415)
    next(new Error('Only .pdf and .zip files are allowed.'))
    return
  }
  challengeUtils.solveIf(challenges.uploadTypeChallenge, () => {
    return !(fileType === 'pdf' || fileType === 'xml' || fileType === 'zip' || fileType === 'yml' || fileType === 'yaml')
  })
  next()
}

// The B2B XML/YAML complaint interface is deprecated and shut down: uploads are rejected without being parsed,
// so there is no XML parser with external entities (XXE) and no YAML parser to overload
function rejectDeprecatedUpload (file: { originalname: string }, res: Response, next: NextFunction) {
  res.status(410)
  next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file.originalname + ')'))
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null && utils.endsWith(file.originalname.toLowerCase(), '.xml')) {
    rejectDeprecatedUpload(file, res, next)
    return
  }
  next()
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null && (utils.endsWith(file.originalname.toLowerCase(), '.yml') || utils.endsWith(file.originalname.toLowerCase(), '.yaml'))) {
    rejectDeprecatedUpload(file, res, next)
    return
  }
  res.status(204).end()
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
}
