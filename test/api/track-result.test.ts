/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results for the order id', async () => {
    const res = await request(app)
      .get('/rest/track-order/5267-f9cd5882f54c75a3')
    assert.equal(res.status, 200)
  })

  void it('GET no other orders by injecting into orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.deepEqual(res.body.data, [{ orderId: 'true' }])
  })

  void it('GET order id without HTML markup reflected back', async () => {
    const res = await request(app)
      .get('/rest/track-order/%3Ciframe%20src%3D%22javascript:alert(%60xss%60)%22%3E')
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [{ orderId: 'iframesrcjavascriptalertxss' }])
  })
})
