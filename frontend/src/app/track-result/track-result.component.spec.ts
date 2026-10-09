/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { provideHttpClientTesting } from '@angular/common/http/testing'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { TranslateModule } from '@ngx-translate/core'
import { Status, TrackResultComponent } from './track-result.component'
import { MatTableModule } from '@angular/material/table'
import { MatCardModule } from '@angular/material/card'
import { RouterTestingModule } from '@angular/router/testing'
import { TrackOrderService } from '../Services/track-order.service'
import { of } from 'rxjs'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('TrackResultComponent', () => {
    let component: TrackResultComponent
    let fixture: ComponentFixture<TrackResultComponent>
    let trackOrderService: any

    beforeEach(async () => {
        trackOrderService = {
            find: vi.fn().mockName("TrackOrderService.find")
        }
        trackOrderService.find.mockReturnValue(of({ data: [{}] }))

        TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(),
                RouterTestingModule,
                MatCardModule,
                MatTableModule,
                TrackResultComponent],
            providers: [
                { provide: TrackOrderService, useValue: trackOrderService },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
            .compileComponents()
    })

    beforeEach(() => {
        fixture = TestBed.createComponent(TrackResultComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })

    it('should render order number as text instead of HTML', () => {
        component.orderId = '<iframe src="javascript:alert(`xss`)">'
        trackOrderService.find.mockReturnValue(of({ data: [{ orderId: component.orderId }] }))
        component.ngOnInit()
        fixture.detectChanges()

        const orderNo = fixture.nativeElement.querySelector('h1 code')
        expect(orderNo.textContent).toBe('<iframe src="javascript:alert(`xss`)">')
        expect(fixture.nativeElement.querySelector('iframe')).toBeNull()
    })

    it('should set "delivered" status for delivered orders', () => {
        trackOrderService.find.mockReturnValue(of({ data: [{ delivered: true }] }))
        component.ngOnInit()

        expect(component.status).toBe(Status.Delivered)
    })

    it('should set "packing" status for undelivered orders with ETA over 2 days', () => {
        trackOrderService.find.mockReturnValue(of({ data: [{ eta: 3 }] }))
        component.ngOnInit()

        expect(component.status).toBe(Status.Packing)
    })

    it('should set "transit" status for undelivered orders with ETA under 3 days', () => {
        trackOrderService.find.mockReturnValue(of({ data: [{ eta: 2 }] }))
        component.ngOnInit()

        expect(component.status).toBe(Status.Transit)
    })
})
