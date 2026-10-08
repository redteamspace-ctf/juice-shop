/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TestBed } from '@angular/core/testing'
import { CookieService } from './cookie.service'

describe('CookieService', () => {
  const cookieName = 'cookie service test'
  let service: CookieService

  beforeEach(() => {
    document.cookie = `${encodeURIComponent(cookieName)}=; Max-Age=0; path=/; SameSite=Lax`
    TestBed.configureTestingModule({})
    service = TestBed.inject(CookieService)
  })

  afterEach(() => {
    service.remove(cookieName)
  })

  it('returns undefined when a cookie is missing', () => {
    expect(service.get(cookieName)).toBeUndefined()
  })

  it('round-trips encoded names and values and removes them', () => {
    const value = 'value with spaces; separators=%'
    const expires = new Date('2030-01-01T00:00:00.000Z')

    service.put(cookieName, value, { expires })

    expect(service.get(cookieName)).toBe(value)

    service.remove(cookieName)
    expect(service.get(cookieName)).toBeUndefined()
  })

  it('returns a malformed encoded value without throwing', () => {
    document.cookie = `${encodeURIComponent(cookieName)}=%E0; path=/`

    expect(service.get(cookieName)).toBe('%E0')
  })
})
