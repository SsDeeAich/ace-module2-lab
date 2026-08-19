/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

export function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file && !file.includes('/') && !file.includes('\\')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward or backward slashes!'))
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    if (file) {
      file = security.cutOffPoisonNullByte(file)

      const fileLower = file.toLowerCase()
      const isAllowedChallenge = [
        'eastere.gg',
        'package.json.bak',
        'coupons_2013.md.bak',
        'suspicious_errors.yml',
        'encrypt.pyc'
      ].includes(fileLower)

      if (endsWithAllowlistedFileType(fileLower) || fileLower === 'incident-support.kdbx' || isAllowedChallenge) {
        challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return fileLower === 'acquisitions.md' })
        verifySuccessfulPoisonNullByteExploit(file)

        res.sendFile(path.resolve('ftp/', file))
        return
      }
    }
    res.status(403)
    next(new Error('Only .md and .pdf files are allowed!'))
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
