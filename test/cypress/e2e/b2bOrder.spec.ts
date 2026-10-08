describe('/b2b/v2/order', () => {
  it('does not evaluate an infinite-loop payload in orderLinesData', () => {
    cy.login({ email: 'admin', password: 'admin123' })

    cy.window().then(async () => {
      const start = Date.now()
      const response = await fetch(`${Cypress.config('baseUrl')}/b2b/v2/orders/`, {
        method: 'POST',
        cache: 'no-cache',
        headers: {
          'Content-type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ orderLinesData: '(function dos() { while(true); })()' })
      })

      expect(Date.now() - start).to.be.lessThan(1800)
      expect(response.status).to.equal(200)
      const body = await response.json()
      expect(body.orderNo).to.be.a('string')
      expect(body.paymentDue).to.be.a('string')
    })
  })

  it('does not evaluate a pathological regular expression in orderLinesData', () => {
    cy.login({ email: 'admin', password: 'admin123' })

    cy.window().then(async () => {
      const start = Date.now()
      const response = await fetch(`${Cypress.config('baseUrl')}/b2b/v2/orders/`, {
        method: 'POST',
        cache: 'no-cache',
        headers: {
          'Content-type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          orderLinesData: "/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')"
        })
      })

      expect(Date.now() - start).to.be.lessThan(1800)
      expect(response.status).to.equal(200)
      const body = await response.json()
      expect(body.orderNo).to.be.a('string')
      expect(body.paymentDue).to.be.a('string')
    })
  })
})
