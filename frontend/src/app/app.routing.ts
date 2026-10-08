/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* eslint-disable @typescript-eslint/no-unused-vars */
import { OAuthComponent } from './oauth/oauth.component'
import { BasketComponent } from './basket/basket.component'
import { TrackResultComponent } from './track-result/track-result.component'
import { ContactComponent } from './contact/contact.component'
import { RegisterComponent } from './register/register.component'
import { ForgotPasswordComponent } from './forgot-password/forgot-password.component'
import { SearchResultComponent } from './search-result/search-result.component'
import { LoginComponent } from './login/login.component'
import { AdministrationComponent } from './administration/administration.component'
import { ChangePasswordComponent } from './change-password/change-password.component'
import { ComplaintComponent } from './complaint/complaint.component'
import { RouterModule, type Routes, type UrlMatchResult, type UrlSegment } from '@angular/router'
import { TwoFactorAuthEnterComponent } from './two-factor-auth-enter/two-factor-auth-enter.component'
import { ErrorPageComponent } from './error-page/error-page.component'
import { PrivacySecurityComponent } from './privacy-security/privacy-security.component'
import { TwoFactorAuthComponent } from './two-factor-auth/two-factor-auth.component'
import { DataExportComponent } from './data-export/data-export.component'
import { LastLoginIpComponent } from './last-login-ip/last-login-ip.component'
import { PrivacyPolicyComponent } from './privacy-policy/privacy-policy.component'
import { AddressCreateComponent } from './address-create/address-create.component'
import { AddressSelectComponent } from './address-select/address-select.component'
import { SavedAddressComponent } from './saved-address/saved-address.component'
import { PaymentComponent } from './payment/payment.component'
import { SavedPaymentMethodsComponent } from './saved-payment-methods/saved-payment-methods.component'
import { AccountingComponent } from './accounting/accounting.component'
import { OrderCompletionComponent } from './order-completion/order-completion.component'
import { OrderSummaryComponent } from './order-summary/order-summary.component'
import { WalletComponent } from './wallet/wallet.component'
import { OrderHistoryComponent } from './order-history/order-history.component'
import { DeliveryMethodComponent } from './delivery-method/delivery-method.component'
import { PhotoWallComponent } from './photo-wall/photo-wall.component'
import { DeluxeUserComponent } from './deluxe-user/deluxe-user.component'
import { AccountingGuard, AdminGuard, LoginGuard } from './app.guard'
import { NFTUnlockComponent } from './nft-unlock/nft-unlock.component'
import { ScoreBoardComponent } from './score-board/score-board.component'
import { ChatbotComponent } from './chatbot/chatbot.component'
import { ChatWelcomePageComponent } from './chatbot/chat-welcome-page/chat-welcome-page.component'
import { ChatConversationComponent } from './chatbot/chat-conversation/chat-conversation.component'


const loadCodingChallenge = async () => {
  const module = await import('./coding-challenge-page/coding-challenge-page.component')
  return module.CodingChallengePageComponent
}

const loadRecycleComponent = async () => {
  const module = await import('./recycle/recycle.component')
  return module.RecycleComponent
}

const loadAboutComponent = async () => {
  const module = await import('./about/about.component')
  return module.AboutComponent
}

// vuln-code-snippet start adminSectionChallenge scoreBoardChallenge web3SandboxChallenge
const routes: Routes = [
  { // vuln-code-snippet neutral-line adminSectionChallenge
    path: 'administration', // vuln-code-snippet vuln-line adminSectionChallenge
    component: AdministrationComponent, // vuln-code-snippet neutral-line adminSectionChallenge
    canActivate: [AdminGuard] // vuln-code-snippet neutral-line adminSectionChallenge
  }, // vuln-code-snippet neutral-line adminSectionChallenge
  {
    path: 'accounting',
    component: AccountingComponent,
    canActivate: [AccountingGuard]
  },
  {
    path: 'about',
    loadComponent: async () => await loadAboutComponent()
  },
  {
    path: 'address/select',
    component: AddressSelectComponent,
    canActivate: [LoginGuard]
  },
  {
    path: 'address/saved',
    component: SavedAddressComponent,
    canActivate: [LoginGuard]
  },
  {
    path: 'address/create',
    component: AddressCreateComponent,
    canActivate: [LoginGuard]
  },
  {
    path: 'address/edit/:addressId',
    component: AddressCreateComponent,
    canActivate: [LoginGuard]
  },
  {
    path: 'delivery-method',
    component: DeliveryMethodComponent
  },
  {
    path: 'deluxe-membership',
    component: DeluxeUserComponent,
    canActivate: [LoginGuard]
  },
  {
    path: 'saved-payment-methods',
    component: SavedPaymentMethodsComponent
  },
  {
    path: 'basket',
    component: BasketComponent
  },
  {
    path: 'order-completion/:id',
    component: OrderCompletionComponent
  },
  {
    path: 'contact',
    component: ContactComponent
  },
  {
    path: 'photo-wall',
    component: PhotoWallComponent
  },
  {
    path: 'complain',
    component: ComplaintComponent
  },
  {
    path: 'order-summary',
    component: OrderSummaryComponent
  },
  {
    path: 'order-history',
    component: OrderHistoryComponent
  },
  {
    path: 'payment/:entity',
    component: PaymentComponent
  },
  {
    path: 'wallet',
    component: WalletComponent
  },
  {
    path: 'login',
    component: LoginComponent
  },
  {
    path: 'forgot-password',
    component: ForgotPasswordComponent
  },
  {
    path: 'recycle',
    loadComponent: async () => await loadRecycleComponent()
  },
  {
    path: 'register',
    component: RegisterComponent
  },
  {
    path: 'search',
    component: SearchResultComponent
  },
  {
    path: 'hacking-instructor',
    component: SearchResultComponent
  },
  { // vuln-code-snippet neutral-line scoreBoardChallenge
    path: 'score-board', // vuln-code-snippet vuln-line scoreBoardChallenge
    component: ScoreBoardComponent // vuln-code-snippet neutral-line scoreBoardChallenge
  }, // vuln-code-snippet neutral-line scoreBoardChallenge
  {
    path: 'track-result',
    component: TrackResultComponent
  },
  {
    path: 'track-result/new',
    component: TrackResultComponent,
    data: {
      type: 'new'
    }
  },
  {
    path: '2fa/enter',
    component: TwoFactorAuthEnterComponent
  },
  {
    path: 'privacy-security',
    component: PrivacySecurityComponent,
    children: [
      {
        path: 'privacy-policy',
        component: PrivacyPolicyComponent
      },
      {
        path: 'change-password',
        component: ChangePasswordComponent
      },
      {
        path: 'two-factor-authentication',
        component: TwoFactorAuthComponent
      },
      {
        path: 'data-export',
        component: DataExportComponent
      },
      {
        path: 'last-login-ip',
        component: LastLoginIpComponent
      }
    ]
  },
  {
    path: 'juicy-nft',
    component: NFTUnlockComponent
  },
  // the web3 code sandbox is a development tool and is no longer routed in production builds // vuln-code-snippet vuln-line web3SandboxChallenge
  {
    path: 'chatbot',
    component: ChatbotComponent,
    children: [
      { path: '', component: ChatWelcomePageComponent },
      { path: 'conversation/:id', component: ChatConversationComponent }
    ]
  },
  // Web3 wallet and Bee Haven (Honey Pot NFT) pages are offline until their vulnerable contracts are replaced
  // vuln-code-snippet start tokenSaleChallenge
  {
    matcher: oauthMatcher,
    data: { params: (window.location.href).substr(window.location.href.indexOf('#')) },
    component: OAuthComponent
  },
  // the unannounced token sale page is not routed until its official launch // vuln-code-snippet vuln-line tokenSaleChallenge
  {
    path: 'coding-challenge/:challengeKey',
    loadComponent: async () => await loadCodingChallenge()
  },
  {
    path: '403',
    component: ErrorPageComponent
  },
  {
    path: '**',
    component: SearchResultComponent
  }
]
// vuln-code-snippet end adminSectionChallenge scoreBoardChallenge web3SandboxChallenge

export const Routing = RouterModule.forRoot(routes, { useHash: true })

export function oauthMatcher (url: UrlSegment[]): UrlMatchResult {
  if (url.length === 0) {
    return null as unknown as UrlMatchResult
  }
  const path = window.location.href
  if (path.includes('#access_token=')) {
    return ({ consumed: url })
  }

  return null as unknown as UrlMatchResult
}

// (the obfuscated token sale URL matcher was removed together with the unreleased page)
// vuln-code-snippet end tokenSaleChallenge
