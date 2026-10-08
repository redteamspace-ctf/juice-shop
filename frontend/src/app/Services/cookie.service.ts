/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { DOCUMENT } from '@angular/common'
import { Injectable, inject } from '@angular/core'

interface CookieOptions {
  expires?: Date
}

@Injectable({ providedIn: 'root' })
export class CookieService {
  private readonly document = inject(DOCUMENT)

  get (name: string): string | undefined {
    const prefix = `${encodeURIComponent(name)}=`
    const cookie = this.document.cookie
      .split(';')
      .map((entry) => entry.trim())
      .find((entry) => entry.startsWith(prefix))

    if (!cookie) {
      return undefined
    }

    const value = cookie.slice(prefix.length)

    try {
      return decodeURIComponent(value)
    } catch {
      return value
    }
  }

  put (name: string, value: string, options?: CookieOptions): void {
    const cookie = `${encodeURIComponent(name)}=${encodeURIComponent(value)}; path=/; SameSite=Lax`
    const expires = options?.expires
    this.document.cookie = expires ? `${cookie}; expires=${expires.toUTCString()}` : cookie
  }

  remove (name: string): void {
    this.document.cookie = `${encodeURIComponent(name)}=; Max-Age=0; path=/; SameSite=Lax`
  }
}
