// keycloak.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, BehaviorSubject, throwError } from 'rxjs';
import { map, catchError } from 'rxjs/operators';
import {environment} from '../../environments/environment';

export interface KeycloakConfig {
  url: string;
  realm: string;
  clientId: string;
  clientSecret?: string;
}

export interface User {
  id?: string;
  username: string;
  email: string;
  firstName?: string;
  lastName?: string;
  enabled?: boolean;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface RegisterUser {
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

@Injectable({
  providedIn: 'root'
})
export class KeycloakService {
  private config: KeycloakConfig = {
    url: environment.keycloak.url,
    realm: environment.keycloak.realm,
    clientId: environment.keycloak.clientId,
    clientSecret: environment.keycloak.clientSecret
  };

  private currentUserSubject = new BehaviorSubject<User | null>(null);
  private tokenSubject = new BehaviorSubject<string | null>(null);

  public currentUser$ = this.currentUserSubject.asObservable();
  public token$ = this.tokenSubject.asObservable();

  constructor(private http: HttpClient) {
    this.loadTokenFromStorage();
  }

  /**
   * Configure Keycloak connection
   */
  configure(config: Partial<KeycloakConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Login user with username and password
   */
  login(credentials: LoginCredentials): Observable<TokenResponse> {
    const tokenUrl = `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/token`;

    const headers = new HttpHeaders({
      'Content-Type': 'application/x-www-form-urlencoded'
    });

    const body = new URLSearchParams();
    body.set('grant_type', 'password');
    body.set('client_id', this.config.clientId);
    body.set('username', credentials.username);
    body.set('password', credentials.password);
    body.set('scope', 'openid profile email'); // Add scopes here
    if (this.config.clientSecret) {
      body.set('client_secret', this.config.clientSecret);
    }

    return this.http.post<TokenResponse>(tokenUrl, body.toString(), { headers })
      .pipe(
        map(response => {
          this.storeToken(response.access_token);
          this.loadUserInfo();
          return response;
        }),
        catchError(error => {
          console.error('Login failed:', error);
          return throwError(error);
        })
      );
  }

  /**
   * Register a new user
   */
  register(userData: RegisterUser): Observable<any> {
        const usersUrl = `${this.config.url}/admin/realms/${this.config.realm}/users`;

        const headers = new HttpHeaders({
          'Content-Type': 'application/json',
          // 'Authorization': `Bearer ${adminToken}`
        });

        const user = {
          username: userData.username,
          email: userData.email,
          firstName: userData.firstName,
          lastName: userData.lastName,
          enabled: true,
          credentials: [{
            type: 'password',
            value: userData.password,
            temporary: false
          }]
        };

        return this.http.post(usersUrl, user, { headers });

  }


  /**
   * Load user information using current token
   */
  private loadUserInfo(): void {
    const token = this.getToken();

    if (!token) {
      console.error('No access token available');
      return;
    }

    // Check if token is expired
    if (this.isTokenExpired(token)) {
      console.error('Access token is expired');
      this.clearTokens();
      return;
    }

    // Keycloak userinfo endpoint
    const userInfoUrl = `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/userinfo`;

    const headers = new HttpHeaders({
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    });

    console.log('Fetching user info from:', userInfoUrl);
    console.log('Using token:', token.substring(0, 20) + '...');

    this.http.get<any>(userInfoUrl, { headers }).subscribe({
      next: (userInfo) => {
        console.log('User info received:', userInfo);

        // Map Keycloak user info to your User interface
        const user: User = {
          id: userInfo.sub,
          username: userInfo.preferred_username || userInfo.username,
          email: userInfo.email,
          firstName: userInfo.given_name,
          lastName: userInfo.family_name,
          enabled: true
        };

        this.currentUserSubject.next(user);
      },
      error: (error) => {
        console.error('Failed to load user info:', error);
        console.error('Error status:', error.status);
        console.error('Error message:', error.message);

        // If unauthorized, clear tokens
        if (error.status === 401) {
          console.error('Token is invalid or expired');
          this.clearTokens();
        }
      }
    });
  }

  /**
   * Refresh access token
   */
  refreshToken(): Observable<TokenResponse> {
    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) {
      return throwError(()=> 'No refresh token available');
    }

    const tokenUrl = `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/token`;

    const headers = new HttpHeaders({
      'Content-Type': 'application/x-www-form-urlencoded'
    });

    const body = new URLSearchParams();
    body.set('grant_type', 'refresh_token');
    body.set('client_id', this.config.clientId);
    body.set('refresh_token', refreshToken);

    if (this.config.clientSecret) {
      body.set('client_secret', this.config.clientSecret);
    }

    return this.http.post<TokenResponse>(tokenUrl, body.toString(), { headers })
      .pipe(
        map(response => {
          this.storeToken(response.access_token);
          if (response.refresh_token) {
            localStorage.setItem('refresh_token', response.refresh_token);
          }
          return response;
        }),
        catchError(error => {
          this.logout();
          return throwError(()=> error);
        })
      );
  }

  /**
   * Logout user
   */
  logout(): Observable<any> {
    const token = this.getToken();
    const refreshToken = localStorage.getItem('refresh_token');

    if (token && refreshToken) {
      const logoutUrl = `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/logout`;

      const headers = new HttpHeaders({
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Bearer ${token}`
      });

      const body = new URLSearchParams();
      body.set('client_id', this.config.clientId);
      body.set('refresh_token', refreshToken);

      return this.http.post(logoutUrl, body.toString(), { headers })
        .pipe(
          map(() => {
            this.clearTokens();
            return true;
          }),
          catchError(error => {
            console.error('Logout failed:', error);
            this.clearTokens(); // Clear tokens anyway
            return throwError(()=> error);
          })
        );
    } else {
      this.clearTokens();
      return new Observable(observer => {
        observer.next(true);
        observer.complete();
      });
    }
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    const token = this.getToken();
    return token !== null && !this.isTokenExpired(token);
  }

  /**
   * Get current access token
   */
  getToken(): string | null {
    return localStorage.getItem('access_token');
  }

  /**
   * Get current user
   */
  getCurrentUser(): User | null {
    return this.currentUserSubject.value;
  }

  /**
   * Store token in localStorage and update subject
   */
  private storeToken(token: string): void {
    localStorage.setItem('access_token', token);
    this.tokenSubject.next(token);
  }

  /**
   * Load token from localStorage on service initialization
   */
  private loadTokenFromStorage(): void {
    const token = localStorage.getItem('access_token');
    if (token && !this.isTokenExpired(token)) {
      this.tokenSubject.next(token);
      this.loadUserInfo();
    } else {
      this.clearTokens();
    }
  }

  /**
   * Clear all stored tokens
   */
  private clearTokens(): void {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    this.tokenSubject.next(null);
    this.currentUserSubject.next(null);
  }

  /**
   * Check if token is expired
   */
  private isTokenExpired(token: string): boolean {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      const now = Math.floor(Date.now() / 1000);
      return payload.exp < now;
    } catch (error) {
      return true;
    }
  }
}
