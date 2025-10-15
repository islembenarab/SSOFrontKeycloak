import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { ReactiveFormsModule } from '@angular/forms';
import {HTTP_INTERCEPTORS, provideHttpClient} from '@angular/common/http';
import { RouterModule, Routes } from '@angular/router';


import {App} from './app';
import {LoginComponent} from './components/login-component/login-component';
import {RegisterComponent} from './components/register-component/register-component';
import {DashboardComponent} from './components/dashboard-component/dashboard-component';
import {AuthGuard} from './guards/auth-guard-guard';
import {KeycloakService} from './services/keycloak-service';
import {AuthInterceptor} from './interceptors/auth-interceptor-interceptor';
import {environment} from '../environments/environment';

const routes: Routes = [
  { path: '', redirectTo: '/dashboard', pathMatch: 'full' },
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegisterComponent },
  { path: 'dashboard', component: DashboardComponent, canActivate: [AuthGuard] },
  { path: '**', redirectTo: '/dashboard' }
];

@NgModule({
  declarations: [
    App,
    LoginComponent,
    RegisterComponent,
    DashboardComponent
  ],
  imports: [
    BrowserModule,
    ReactiveFormsModule,
    RouterModule.forRoot(routes)
  ],
  providers: [
    provideHttpClient(),
    KeycloakService,
    AuthGuard,
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true
    }
  ],
  bootstrap: [App]
})
export class AppModule {
  constructor(private keycloakService: KeycloakService) {
    this.keycloakService.configure({
      url: environment.keycloak.url,
      realm: environment.keycloak.realm,
      clientId: environment.keycloak.clientId,
      clientSecret: environment.keycloak.clientSecret
    });
  }
}
