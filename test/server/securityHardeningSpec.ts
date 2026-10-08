/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { expect } from 'chai'
import sinon from 'sinon'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import * as security from '../../lib/insecurity'
import { profileImageUrlUpload } from '../../routes/profileImageUrlUpload'
import { getUserProfile } from '../../routes/userProfile'
import { retrieveLoggedInUser } from '../../routes/currentUser'
import { UserModel } from '../../models/user'
import { handleZipFileUpload } from '../../routes/fileUpload'
import { changePassword } from '../../routes/changePassword'
import { verifyImageCaptcha } from '../../routes/imageCaptcha'
import { ImageCaptchaModel } from '../../models/imageCaptcha'
import { checkKeys } from '../../routes/checkKeys'
import { saveLoginIp } from '../../routes/saveLoginIp'

describe('security hardening', () => {
  afterEach(() => sinon.restore())

  function userRequest (role = 'customer') {
    const data = { id: 42, email: 'customer@example.test', role, username: 'Customer', profileImage: 'https://images.example.test/avatar.png', password: 'private-hash', totpSecret: 'private-secret' }
    const token = security.authorize({ data })
    security.authenticatedUsers.put(token, { data } as any)
    return { cookies: { token }, headers: { authorization: `Bearer ${token}` }, query: {}, body: {}, socket: { remoteAddress: '127.0.0.1' } } as any
  }

  function response () {
    const res = { status: sinon.stub(), json: sinon.spy(), redirect: sinon.spy(), set: sinon.spy(), send: sinon.spy(), end: sinon.spy(), __: (value: string) => value }
    res.status.returns(res)
    return res as any
  }

  it('accepts issued tokens and rejects them after expiry', () => {
    const clock = sinon.useFakeTimers()
    const token = security.authorize({ data: { id: 42 } })
    expect(security.verify(token)).to.equal(true)
    clock.tick(6 * 60 * 60 * 1000 + 1000)
    expect(security.verify(token)).to.equal(false)
    expect(security.decode(token)).to.equal(undefined)
  })

  it('stores a validated client IP and ignores arbitrary client headers', async () => {
    const req = userRequest()
    req.ip = '127.0.0.1'
    req.headers['true-client-ip'] = '<b>untrusted</b>'
    const update = sinon.stub().resolves({ lastLoginIp: '127.0.0.1', password: 'private-hash' })
    sinon.stub(UserModel, 'findByPk').resolves({ update } as any)
    const res = response()
    await saveLoginIp()(req, res, sinon.spy())
    expect(update.calledWith({ lastLoginIp: '127.0.0.1' })).to.equal(true)
    expect(res.json.firstCall.args[0]).to.deep.equal({ lastLoginIp: '127.0.0.1' })
  })

  it('requires an administrator for log access', () => {
    const next = sinon.spy()
    const res = response()
    security.isAdmin()(userRequest(), res, next)
    expect(res.status.calledWith(403)).to.equal(true)
    expect(next.called).to.equal(false)
    security.isAdmin()(userRequest('admin'), response(), next)
    expect(next.calledOnce).to.equal(true)
  })

  it('keeps credentials out of issued session payloads', () => {
    const data = { id: 42, email: 'customer@example.test', password: 'private-hash', totpSecret: 'private-secret' }
    const payload = security.decode(security.authorize({ data }))
    expect(payload.data).to.deep.equal({ id: 42, email: 'customer@example.test' })
    expect(data.password).to.equal('private-hash')
    expect(data.totpSecret).to.equal('private-secret')
  })

  it('preserves safe claims when serializing model-backed session data', () => {
    const data = {
      get: () => ({
        id: 42,
        email: 'customer@example.test',
        password: 'private-hash',
        role: 'customer',
        totpSecret: 'private-secret'
      })
    }
    const token = security.authorize({ status: 'success', data })
    const payload = security.decode(token) as { data: Record<string, unknown> }
    const next = sinon.spy()
    const res = response()

    expect(payload.data.id).to.equal(42)
    expect(payload.data.email).to.equal('customer@example.test')
    expect(payload.data.password).to.equal(undefined)
    expect(payload.data.totpSecret).to.equal(undefined)
    security.isAuthorized()({ headers: { authorization: `Bearer ${token}` } } as any, res, next)
    expect(next.calledOnce).to.equal(true)
  })

  it('returns permitted profile fields without credential fields', () => {
    const req = userRequest()
    req.query.fields = 'email,password,totpSecret'
    const res = response()
    retrieveLoggedInUser()(req, res)
    expect(res.json.firstCall.args[0]).to.deep.equal({ user: { email: 'customer@example.test' } })
  })

  it('stores a valid remote image link without making server requests', async () => {
    const fetchStub = sinon.stub(globalThis, 'fetch').rejects(new Error('Server must not fetch profile links'))
    const update = sinon.stub().resolves()
    sinon.stub(UserModel, 'findByPk').resolves({ update } as any)
    const req = userRequest()
    req.body.imageUrl = 'https://images.example.test/avatar.png'
    const res = response()
    await profileImageUrlUpload()(req, res, sinon.spy())
    expect(update.calledWith({ profileImage: req.body.imageUrl })).to.equal(true)
    expect(fetchStub.called).to.equal(false)
    expect(res.redirect.calledOnce).to.equal(true)
  })

  it('rejects image URLs with unsupported protocols', async () => {
    const req = userRequest()
    req.body.imageUrl = 'file:///tmp/avatar.png'
    const res = response()
    const lookup = sinon.stub(UserModel, 'findByPk')
    await profileImageUrlUpload()(req, res, sinon.spy())
    expect(res.status.calledWith(400)).to.equal(true)
    expect(lookup.called).to.equal(false)
  })

  for (const imageUrl of ['http://127.0.0.1/avatar.png', 'http://169.254.169.254/avatar.png', 'http://[::1]/avatar.png', 'http://localhost/avatar.png']) {
    it(`rejects a private image target: ${imageUrl}`, async () => {
      const req = userRequest()
      req.body.imageUrl = imageUrl
      const res = response()
      const lookup = sinon.stub(UserModel, 'findByPk')
      await profileImageUrlUpload()(req, res, sinon.spy())
      expect(res.status.calledWith(400)).to.equal(true)
      expect(lookup.called).to.equal(false)
    })
  }

  it('requires the current password before updating an account', async () => {
    const req = userRequest()
    req.query = { new: 'New-password-123', repeat: 'New-password-123' }
    const res = response()
    const lookup = sinon.stub(UserModel, 'findByPk')
    await changePassword()(req, res, sinon.spy())
    expect(res.status.calledWith(401)).to.equal(true)
    expect(lookup.called).to.equal(false)
  })

  it('checks the stored current password and accepts a valid change', async () => {
    const req = userRequest()
    const update = sinon.stub().resolves()
    sinon.stub(UserModel, 'findByPk').resolves({ id: 42, email: 'customer@example.test', password: security.hash('Old-password-123'), update } as any)
    req.query = { current: 'Wrong-password', new: 'New-password-123', repeat: 'New-password-123' }
    const res = response()
    await changePassword()(req, res, sinon.spy())
    expect(res.status.calledWith(401)).to.equal(true)
    expect(update.called).to.equal(false)
    req.query.current = 'Old-password-123'
    await changePassword()(req, response(), sinon.spy())
    expect(update.calledWith({ password: 'New-password-123' })).to.equal(true)
  })

  it('requires an issued image CAPTCHA for data export', async () => {
    const req = userRequest()
    req.body.answer = 'abcde'
    sinon.stub(ImageCaptchaModel, 'findAll').resolves([])
    const next = sinon.spy()
    const res = response()
    await verifyImageCaptcha()(req, res, next)
    expect(res.status.calledWith(401)).to.equal(true)
    expect(next.called).to.equal(false)
  })

  it('consumes a valid image CAPTCHA once', async () => {
    const req = userRequest()
    req.body.answer = 'abcde'
    sinon.stub(ImageCaptchaModel, 'findAll').onFirstCall().resolves([{ id: 7, answer: 'abcde' }] as any).onSecondCall().resolves([])
    const destroy = sinon.stub(ImageCaptchaModel, 'destroy').resolves(1)
    const next = sinon.spy()
    await verifyImageCaptcha()(req, response(), next)
    expect(destroy.calledWith({ where: { id: 7, UserId: 42, answer: 'abcde' } })).to.equal(true)
    const res = response()
    await verifyImageCaptcha()(req, res, next)
    expect(next.calledOnce).to.equal(true)
    expect(res.status.calledWith(401)).to.equal(true)
  })

  it('uses a configured NFT wallet instead of a published mnemonic', async () => {
    const { HDNodeWallet } = await import('ethers')
    const wallet = HDNodeWallet.createRandom()
    const previousMnemonic = process.env.NFT_WALLET_MNEMONIC
    try {
      process.env.NFT_WALLET_MNEMONIC = wallet.mnemonic!.phrase
      const req = userRequest()
      req.body.privateKey = wallet.privateKey
      const res = response()
      await checkKeys()(req, res)
      expect(res.status.calledWith(200)).to.equal(true)
      expect(res.json.firstCall.args[0].success).to.equal(true)
    } finally {
      if (previousMnemonic === undefined) delete process.env.NFT_WALLET_MNEMONIC
      else process.env.NFT_WALLET_MNEMONIC = previousMnemonic
    }
  })

  it('renders user names as escaped data', async () => {
    const req = userRequest()
    sinon.stub(UserModel, 'findByPk').resolves({ username: '<b>Customer</b> #{6 * 7}', email: 'customer@example.test', profileImage: '/avatar.png' } as any)
    const res = response()
    const next = sinon.spy()
    await getUserProfile()(req, res, next)
    expect(next.called).to.equal(false)
    expect(res.send.firstCall.args[0]).to.include('&lt;b&gt;Customer&lt;/b&gt; #{6 * 7}')
    expect(res.send.firstCall.args[0]).not.to.include('<b>Customer</b>')
  })

  it('extracts a valid archive inside its isolated upload directory', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'juice-archive-test-'))
    sinon.stub(fs, 'mkdtemp').resolves(root)
    const buffer = Buffer.from('UEsDBBQAAAAIAC59R11XvLQ3EAAAAA4AAAALAAAAcmVjZWlwdC50eHTzL0pJLVIoSk1OzSwo4QIAUEsBAhQDFAAAAAgALn1HXVe8tDcQAAAADgAAAAsAAAAAAAAAAAAAAIABAAAAAHJlY2VpcHQudHh0UEsFBgAAAAABAAEAOQAAADkAAAAAAA==', 'base64')
    const res = response()
    try {
      await handleZipFileUpload({ file: { originalname: 'receipt.zip', buffer } } as any, res, sinon.spy())
      expect(res.status.calledWith(204)).to.equal(true)
      expect(await fs.readFile(path.join(root, 'receipt.txt'), 'utf8')).to.equal('Order receipt\n')
    } finally {
      await fs.rm(root, { recursive: true, force: true })
    }
  })
})
