import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

// Public (non-secret) details of the NFT wallet, only used to give helpful feedback
const address = '0x8343d2eb2B13A2495De435a1b15e85b98115Ce05'
const publicKey = '0x02c7a2a93289c9fbda5990bac6596993e9bb0a8d3f178175a80b7cfd983983f506'

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      // The wallet's secret is never part of the code base: it can only be configured on the server,
      // and without it no key unlocks the wallet
      const privateKey = process.env.NFT_WALLET_PRIVATE_KEY
      const isValidKey = typeof privateKey === 'string' && privateKey.length > 0 && req.body?.privateKey === privateKey
      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => isValidKey)
      if (isValidKey) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else {
        if (req.body.privateKey === address) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else if (req.body.privateKey === publicKey) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public key of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else {
          res.status(401).json({ success: false, message: 'Looks like you entered a non-Ethereum private key to access me.', status: challenges.nftUnlockChallenge })
        }
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
export function nftUnlocked () {
  return (req: Request, res: Response) => {
    try {
      res.status(200).json({ status: challenges.nftUnlockChallenge.solved })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
