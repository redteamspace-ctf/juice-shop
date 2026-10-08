/* Rate limiting */
  app.set('trust proxy', 'loopback')
  app.use('/rest/user/reset-password', rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100,
    keyGenerator ({ headers, ip }) { return headers['Forwarded'] ?? ip }
  }))