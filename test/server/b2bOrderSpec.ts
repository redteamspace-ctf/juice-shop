/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { b2bOrder } from '../../routes/b2bOrder'
const expect = chai.expect
chai.use(sinonChai)

describe('b2bOrder', () => {
  let req: any
  let res: any
  let save: any

  beforeEach(() => {
    req = { body: { } }
    res = { json: sinon.spy(), status: sinon.spy() }
    res.status = sinon.stub().returns(res)
    save = () => ({
      then () { }
    })
    challenges.rceChallenge = { solved: false, save } as unknown as Challenge
  })

  for (const { name, orderLinesData } of [
    { name: 'an infinite loop', orderLinesData: '(function dos() { while(true); })()' },
    { name: 'a pathological regular expression', orderLinesData: '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")' },
    { name: 'a sandbox breakout', orderLinesData: 'this.constructor.constructor("return process")().exit()' }
  ]) {
    it(`does not evaluate ${name} in orderLinesData`, () => {
      req.body.orderLinesData = orderLinesData

      b2bOrder()(req, res)

      expect(res.json.calledOnce).to.equal(true)
      expect(res.json.firstCall.args[0]).to.have.property('orderNo')
      expect(res.json.firstCall.args[0]).to.have.property('paymentDue')
      expect(res.status.called).to.equal(false)
      expect(challenges.rceChallenge.solved).to.equal(false)
    })
  }

  it('accepts the documented JSON string as opaque input', () => {
    req.body.orderLinesData = '{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}'

    b2bOrder()(req, res)

    expect(challenges.rceChallenge.solved).to.equal(false)
    expect(res.json.calledOnce).to.equal(true)
    expect(res.status.called).to.equal(false)
  })

  it('accepts arbitrary JSON text as opaque input', () => {
    req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

    b2bOrder()(req, res)

    expect(challenges.rceChallenge.solved).to.equal(false)
    expect(res.json.calledOnce).to.equal(true)
    expect(res.status.called).to.equal(false)
  })

  it('accepts malformed JSON text without interpreting it', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res)

    expect(challenges.rceChallenge.solved).to.equal(false)
    expect(res.json.calledOnce).to.equal(true)
    expect(res.status.called).to.equal(false)
  })

  for (const orderLinesData of [null, 42, ' '.repeat(65537)]) {
    it(`rejects invalid order data of type ${typeof orderLinesData}`, () => {
      req.body.orderLinesData = orderLinesData
      b2bOrder()(req, res)
      expect(res.status).to.have.been.calledWith(400)
      expect(res.json.firstCall.args[0]).to.have.property('error')
    })
  }

  it('accepts a new order when orderLinesData is omitted', () => {
    b2bOrder()(req, res)

    expect(res.json.calledOnce).to.equal(true)
    expect(res.status.called).to.equal(false)
  })

  for (const body of [null, [], 'invalid']) {
    it(`rejects a request body of type ${typeof body}`, () => {
      req.body = body
      b2bOrder()(req, res)

      expect(res.status).to.have.been.calledWith(400)
      expect(res.json.firstCall.args[0]).to.have.property('error')
    })
  }
})
