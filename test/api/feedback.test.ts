/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import * as utils from '../../lib/utils'
import { resetFeedbackThrottle } from '../../routes/captcha'
import { CaptchaModel } from '../../models/captcha'

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
const jsonHeader = { 'content-type': 'application/json' }

// The CAPTCHA is only shown as an image, so the tests (running in-process) look the answer up server-side
async function captchaAnswer (captchaId: number) {
  const captcha = await CaptchaModel.findOne({ where: { captchaId } })
  return captcha?.answer ?? ''
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

beforeEach(() => { resetFeedbackThrottle() })

void describe('/api/Feedbacks', () => {
  void it('GET all feedback', async () => {
    const res = await request(app)
      .get('/api/Feedbacks')
    assert.equal(res.status, 200)
  })

  void it('GET captcha returns a single-use challenge', async () => {
    const res = await request(app)
      .get('/rest/captcha')
    assert.equal(res.status, 200)
    assert.equal(typeof res.body.captchaId, 'number')
    assert.ok(res.body.image.startsWith('<svg'))
    assert.equal(res.body.captcha, undefined)
    assert.equal(res.body.answer, undefined)
  })

  void it('POST with an already used captcha is rejected', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    const feedback = { comment: 'Replay', rating: 3, captchaId: captchaRes.body.captchaId, captcha: await captchaAnswer(captchaRes.body.captchaId) }

    const first = await request(app).post('/api/Feedbacks').set(jsonHeader).send(feedback)
    assert.equal(first.status, 201)
    const replay = await request(app).post('/api/Feedbacks').set(jsonHeader).send(feedback)
    assert.equal(replay.status, 401)
  })

  void it('POST with a wrong captcha answer consumes the captcha', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    const feedback = { comment: 'Guess', rating: 3, captchaId: captchaRes.body.captchaId }

    const wrong = await request(app).post('/api/Feedbacks').set(jsonHeader).send({ ...feedback, captcha: 'definitely wrong' })
    assert.equal(wrong.status, 401)
    const retry = await request(app).post('/api/Feedbacks').set(jsonHeader).send({ ...feedback, captcha: await captchaAnswer(captchaRes.body.captchaId) })
    assert.equal(retry.status, 401)
  })

  void it('POST of 10 feedbacks within 20 seconds is throttled', async () => {
    // Start from a clean global challenge counter, so feedbacks of earlier tests (whose throttle was reset) don't count
    app.locals.captchaReqId = 1
    app.locals.captchaBypassReqTimes = []
    const statuses: number[] = []
    for (let i = 0; i < 10; i++) {
      const captchaRes = await request(app).get('/rest/captcha')
      const res = await request(app).post('/api/Feedbacks').set(jsonHeader)
        .send({ comment: 'Bot ' + i, rating: 1, captchaId: captchaRes.body.captchaId, captcha: await captchaAnswer(captchaRes.body.captchaId) })
      statuses.push(res.status)
    }
    assert.ok(statuses.slice(0, 9).every(status => status === 201))
    assert.equal(statuses[9], 429)
    assert.equal(challenges.captchaBypassChallenge.solved, false)
  })

  void it('POST of scripted feedbacks cannot solve the CAPTCHA from the API response', async () => {
    app.locals.captchaReqId = 1
    app.locals.captchaBypassReqTimes = []
    for (let i = 0; i < 12; i++) {
      const captchaRes = await request(app).get('/rest/captcha')
      const res = await request(app).post('/api/Feedbacks').set(jsonHeader)
        .send({ comment: 'Spam #' + i, rating: 3, captchaId: captchaRes.body.captchaId, captcha: `${captchaRes.body.answer}` })
      assert.equal(res.status, 401)
    }
    assert.equal(challenges.captchaBypassChallenge.solved, false)
  })

  void it('POST sanitizes unsafe HTML from comment', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: 'I am a harm<script>steal-cookie</script><img src="csrf-attack"/><iframe src="evil-content"></iframe>less comment.',
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: await captchaAnswer(captchaRes.body.captchaId)
      })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.comment, 'I am a harmless comment.')
  })

  if (utils.isChallengeEnabled(challenges.persistedXssFeedbackChallenge)) {
    void it('POST sanitizes masked XSS-attack by applying sanitization recursively', async () => {
      const captchaRes = await request(app)
        .get('/rest/captcha')
      assert.equal(captchaRes.status, 200)
      assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

      const res = await request(app)
        .post('/api/Feedbacks')
        .set(jsonHeader)
        .send({
          comment: 'The sanitize-html module up to at least version 1.4.2 has this issue: <<script>Foo</script>iframe src="javascript:alert(`xss`)">',
          rating: 1,
          captchaId: captchaRes.body.captchaId,
          captcha: await captchaAnswer(captchaRes.body.captchaId)
        })
      assert.equal(res.status, 201)
      assert.ok(!res.body.data.comment.includes('<iframe'))
    })
  }

  void it('POST feedback in another users name as anonymous user', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: 'Lousy crap! You use sequelize 1.7.x? Welcome to SQL Injection-land, morons! As if that is not bad enough, you use z85/base85 and hashids for crypto? Even MD5 to hash passwords! Srsly?!?!',
        rating: 1,
        UserId: 3,
        captchaId: captchaRes.body.captchaId,
        captcha: await captchaAnswer(captchaRes.body.captchaId)
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.UserId, 3)
  })

  void it('POST feedback in a non-existing users name as anonymous user fails with constraint error', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: 'Pickle Rick says your express-jwt 0.1.3 has Eurogium Edule and Hueteroneel in it!',
        rating: 0,
        UserId: 4711,
        captchaId: captchaRes.body.captchaId,
        captcha: await captchaAnswer(captchaRes.body.captchaId)
      })
    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(res.body.errors.includes('SQLITE_CONSTRAINT: FOREIGN KEY constraint failed'))
  })

  void it('POST feedback is associated with current user', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })

    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({
        comment: 'Stupid JWT secret and being typosquatted by epilogue-js and ngy-cookie!',
        rating: 5,
        UserId: 4,
        captchaId: captchaRes.body.captchaId,
        captcha: await captchaAnswer(captchaRes.body.captchaId)
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.UserId, 4)
  })

  void it('POST feedback is associated with any passed user ID', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })

    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({
        comment: 'Bender\'s choice award!',
        rating: 5,
        UserId: 3,
        captchaId: captchaRes.body.captchaId,
        captcha: await captchaAnswer(captchaRes.body.captchaId)
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.UserId, 3)
  })

  void it('POST feedback can be created without actually supplying comment', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: await captchaAnswer(captchaRes.body.captchaId)
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.comment, null)
    assert.equal(res.body.data.rating, 1)
  })

  void it('POST feedback cannot be created without actually supplying rating', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        captchaId: captchaRes.body.captchaId,
        captcha: await captchaAnswer(captchaRes.body.captchaId)
      })
    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.message, 'string')
    assert.ok(res.body.message.match(/notNull Violation: (Feedback\.)?rating cannot be null/))
  })

  void it('POST feedback cannot be created with wrong CAPTCHA answer', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: (await captchaAnswer(captchaRes.body.captchaId)) + 1
      })
    assert.equal(res.status, 401)
  })

  void it('POST feedback cannot be created with invalid CAPTCHA id', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        rating: 1,
        captchaId: 999999,
        captcha: 42
      })
    assert.equal(res.status, 401)
  })
})

void describe('/api/Feedbacks/:id', () => {
  void it('GET existing feedback by id is forbidden via public API', async () => {
    const res = await request(app)
      .get('/api/Feedbacks/1')
    assert.equal(res.status, 401)
  })

  void it('GET existing feedback by id', async () => {
    const res = await request(app)
      .get('/api/Feedbacks/1')
      .set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('PUT update existing feedback is forbidden via public API', async () => {
    const res = await request(app)
      .put('/api/Feedbacks/1')
      .set(jsonHeader)
      .send({
        comment: 'This sucks like nothing has ever sucked before',
        rating: 1
      })
    assert.equal(res.status, 401)
  })

  void it('PUT update existing feedback', async () => {
    const res = await request(app)
      .put('/api/Feedbacks/2')
      .set(authHeader)
      .send({
        rating: 0
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing feedback is forbidden via public API', async () => {
    const res = await request(app)
      .delete('/api/Feedbacks/1')
    assert.equal(res.status, 401)
  })

  void it('DELETE existing feedback', async () => {
    const captchaRes = await request(app)
      .get('/rest/captcha')
    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const createRes = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: 'I will be gone soon!',
        rating: 1,
        captchaId: captchaRes.body.captchaId,
        captcha: await captchaAnswer(captchaRes.body.captchaId)
      })
    assert.equal(createRes.status, 201)
    assert.equal(typeof createRes.body.data.id, 'number')

    const res = await request(app)
      .delete('/api/Feedbacks/' + createRes.body.data.id)
      .set(authHeader)
    assert.equal(res.status, 200)
  })
})
