/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type CanActivate, Router } from '@angular/router'
import { jwtDecode } from 'jwt-decode'
import { roles } from './roles'
import { Injectable, NgZone, inject } from '@angular/core'
import { firstValueFrom } from 'rxjs'
import { UserService } from './Services/user.service'

@Injectable()
export class LoginGuard implements CanActivate {
  private readonly router = inject(Router)
  private readonly ngZone = inject(NgZone)


  canActivate () {
    if (localStorage.getItem('token')) {
      return true
    } else {
      this.forbidRoute('UNAUTHORIZED_ACCESS_ERROR')
      return false
    }
  }

  forbidRoute (error = 'UNAUTHORIZED_PAGE_ACCESS_ERROR') {
    this.ngZone.run(async () => await this.router.navigate(['403'], {
      skipLocationChange: true,
      queryParams: { error }
    }))
  }

  tokenDecode () {
    let payload: any = null
    const token = localStorage.getItem('token')
    if (token) {
      try {
        payload = jwtDecode(token)
      } catch (err) {
        console.log(err)
      }
    }
    return payload
  }
}

@Injectable()
export class AdminGuard implements CanActivate {
  private readonly loginGuard = inject(LoginGuard)
  private readonly userService = inject(UserService)

  // The token in localStorage is only decoded, never verified, in the browser - so the role it claims is
  // confirmed by the server (which verifies the signature) before the administration page is rendered
  async canActivate () {
    const payload = this.loginGuard.tokenDecode()
    if (payload?.data && payload.data.role === roles.admin) {
      try {
        const user: any = await firstValueFrom(this.userService.whoAmI(['role']))
        if (user?.role === roles.admin) {
          return true
        }
      } catch (err) {
        console.log(err)
      }
    }
    this.loginGuard.forbidRoute()
    return false
  }
}

@Injectable()
export class AccountingGuard implements CanActivate {
  private readonly loginGuard = inject(LoginGuard)


  canActivate () {
    const payload = this.loginGuard.tokenDecode()
    if (payload?.data && payload.data.role === roles.accounting) {
      return true
    } else {
      this.loginGuard.forbidRoute()
      return false
    }
  }
}

@Injectable()
export class DeluxeGuard {
  private readonly loginGuard = inject(LoginGuard)


  isDeluxe () {
    const payload = this.loginGuard.tokenDecode()
    return payload?.data && payload.data.role === roles.deluxe
  }
}
