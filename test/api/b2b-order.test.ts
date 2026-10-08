/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize({ data: { id: 1 } }), 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/b2b/v2/orders', () => {
  for (const { name, orderLinesData } of [
    { name: 'an infinite loop', orderLinesData: '(function dos() { while(true); })()' },
    { name: 'a pathological regular expression', orderLinesData: '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")' },
    { name: 'a sandbox breakout', orderLinesData: 'this.constructor.constructor("return process")().exit()' }
  ]) {
    void it(`POST does not evaluate ${name} in orderLinesData`, async () => {
      const start = Date.now()
      const res = await request(app)
        .post('/b2b/v2/orders')
        .set(authHeader)
        .send({ orderLinesData })

      assert.ok(Date.now() - start < 1800, 'Order processing should not evaluate orderLinesData')
      assert.equal(res.status, 200)
      assert.ok(res.body.orderNo)
      assert.ok(res.body.paymentDue)
    })
  }

  void it('POST new B2B order is forbidden without authorization token', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .send({})

    assert.equal(res.status, 401)
  })

  void it('POST new B2B order accepts arbitrary valid JSON', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        foo: 'bar',
        test: 42
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    if (res.body.cid !== undefined) assert.equal(typeof res.body.cid, 'string')
    assert.equal(typeof res.body.orderNo, 'string')
    assert.equal(typeof res.body.paymentDue, 'string')
  })

  void it('POST new B2B order has passed "cid" in response', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        cid: 'test'
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.cid, 'test')
  })

  void it('POST accepts an order with a token issued by the login endpoint', async () => {
    const email = `b2b-${Date.now()}@local.test`
    const password = 'CtfTester!23'
    await request(app)
      .post('/api/Users')
      .send({ email, password, passwordRepeat: password, securityQuestion: null, securityAnswer: 'x' })

    const login = await request(app)
      .post('/rest/user/login')
      .send({ email, password })
    assert.equal(login.status, 200)

    const res = await request(app)
      .post('/b2b/v2/orders')
      .set('Authorization', `Bearer ${login.body.authentication.token}`)
      .send({ orderLinesData: 'while(true){}', cid: 'login-token-test' })

    assert.equal(res.status, 200)
    assert.ok(res.body.orderNo)
    assert.ok(res.body.paymentDue)
  })
})
