# Browser-Based Codex Auth Flow Guide

This guide explains how to implement ChatGPT OAuth authentication (OpenAI Codex) in a browser-based agent and invoke the OpenAI API.

## Authentication Flow Overview

The Codex authentication flow follows the OAuth 2.0 Authorization Code flow with PKCE:

```
User → Authorization URL → OpenAI Login → Callback with Code → Exchange for Tokens → API Access
```

**Key Components:**
- **Client ID**: `app_EMoamEEZ73f0CkXaXp7hrann`
- **Authorization URL**: `https://auth.openai.com/oauth/authorize`
- **Token URL**: `https://auth.openai.com/oauth/token`
- **API Base URL**: `https://chatgpt.com/backend-api`
- **Scope**: `openid profile email offline_access`

## Step 1: PKCE Generation

PKCE (Proof Key for Code Exchange) adds security to the OAuth flow. Generate a random verifier and its SHA-256 challenge.

```typescript
/**
 * Generate PKCE code verifier and challenge using Web Crypto API
 */
async function generatePKCE(): Promise<{ verifier: string; challenge: string }> {
  // Generate random verifier (32 bytes)
  const verifierBytes = new Uint8Array(32);
  crypto.getRandomValues(verifierBytes);
  const verifier = base64urlEncode(verifierBytes);

  // Compute SHA-256 challenge
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const challenge = base64urlEncode(new Uint8Array(hashBuffer));

  return { verifier, challenge };
}

/**
 * Encode bytes as base64url (URL-safe base64 without padding)
 */
function base64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
```

---

## Step 2: Authorization URL

Create the authorization URL and redirect the user to OpenAI's login page.

```typescript
/**
 * OAuth configuration constants
 */
const OAUTH_CONFIG = {
  CLIENT_ID: 'app_EMoamEEZ73f0CkXaXp7hrann',
  AUTHORIZE_URL: 'https://auth.openai.com/oauth/authorize',
  TOKEN_URL: 'https://auth.openai.com/oauth/token',
  REDIRECT_URI: 'https://yourapp.com/auth/callback', // Your callback URL
  SCOPE: 'openid profile email offline_access',
};

/**
 * Generate a random state parameter for CSRF protection
 */
function generateState(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Initiate the OAuth flow
 */
async function startAuthFlow(): Promise<void> {
  // Generate PKCE parameters
  const { verifier, challenge } = await generatePKCE();
  const state = generateState();

  // Store verifier and state in sessionStorage (needed for callback)
  sessionStorage.setItem('pkce_verifier', verifier);
  sessionStorage.setItem('oauth_state', state);

  // Build authorization URL
  const url = new URL(OAUTH_CONFIG.AUTHORIZE_URL);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', OAUTH_CONFIG.CLIENT_ID);
  url.searchParams.set('redirect_uri', OAUTH_CONFIG.REDIRECT_URI);
  url.searchParams.set('scope', OAUTH_CONFIG.SCOPE);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', state);
  url.searchParams.set('id_token_add_organizations', 'true');
  url.searchParams.set('codex_cli_simplified_flow', 'true');
  url.searchParams.set('originator', 'codex_cli_rs');

  // Redirect to OpenAI login
  window.location.href = url.toString();
}
```

**Usage:**
```typescript
// Trigger auth flow on button click
document.getElementById('login-btn')?.addEventListener('click', startAuthFlow);
```

---

## Step 3: Handle OAuth Callback

After user authentication, OpenAI redirects to your callback URL with the authorization code.

```typescript
/**
 * Handle OAuth callback (on /auth/callback page)
 */
async function handleOAuthCallback(): Promise<void> {
  // Parse URL parameters
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');
  const error = params.get('error');

  // Check for errors
  if (error) {
    throw new Error(`OAuth error: ${error}`);
  }

  // Validate state to prevent CSRF attacks
  const savedState = sessionStorage.getItem('oauth_state');
  if (!state || state !== savedState) {
    throw new Error('State mismatch - possible CSRF attack');
  }

  // Get stored PKCE verifier
  const verifier = sessionStorage.getItem('pkce_verifier');
  if (!code || !verifier) {
    throw new Error('Missing authorization code or verifier');
  }

  // Exchange code for tokens
  const credentials = await exchangeCodeForTokens(code, verifier);

  // Store credentials securely
  localStorage.setItem('codex_credentials', JSON.stringify(credentials));

  // Clean up
  sessionStorage.removeItem('pkce_verifier');
  sessionStorage.removeItem('oauth_state');

  // Redirect to app
  window.location.href = '/';
}
```

---

## Step 4: Exchange Code for Tokens

Exchange the authorization code for access and refresh tokens.

```typescript
interface TokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

interface OAuthCredentials {
  access: string;
  refresh: string;
  expires: number;
  accountId: string;
}

/**
 * Exchange authorization code for access and refresh tokens
 */
async function exchangeCodeForTokens(
  code: string,
  verifier: string
): Promise<OAuthCredentials> {
  const response = await fetch(OAUTH_CONFIG.TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: OAUTH_CONFIG.CLIENT_ID,
      code: code,
      code_verifier: verifier,
      redirect_uri: OAUTH_CONFIG.REDIRECT_URI,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token exchange failed: ${response.status} ${errorText}`);
  }

  const data: TokenResponse = await response.json();

  // Calculate expiry timestamp
  const expiresAt = Date.now() + data.expires_in * 1000;

  // Extract account ID from access token
  const accountId = extractAccountId(data.access_token);

  return {
    access: data.access_token,
    refresh: data.refresh_token,
    expires: expiresAt,
    accountId,
  };
}
```

---

## Step 5: Extract Account ID

The account ID is embedded in the access token JWT and required for API calls.

```typescript
const JWT_CLAIM_PATH = 'https://api.openai.com/auth';

interface JwtPayload {
  [JWT_CLAIM_PATH]?: {
    chatgpt_account_id?: string;
  };
  [key: string]: unknown;
}

/**
 * Decode JWT token (without verification - server-side should verify)
 */
function decodeJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const payload = parts[1];
    if (!payload) return null;

    // Decode base64url
    const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(decoded) as JwtPayload;
  } catch {
    return null;
  }
}

/**
 * Extract ChatGPT account ID from access token
 */
function extractAccountId(accessToken: string): string {
  const payload = decodeJwt(accessToken);
  const auth = payload?.[JWT_CLAIM_PATH];
  const accountId = auth?.chatgpt_account_id;

  if (!accountId) {
    throw new Error('Failed to extract accountId from token');
  }

  return accountId;
}
```

---

## Step 6: Token Refresh

Access tokens expire after a certain time. Use the refresh token to get a new access token.

```typescript
/**
 * Refresh expired access token
 */
async function refreshAccessToken(refreshToken: string): Promise<OAuthCredentials> {
  const response = await fetch(OAUTH_CONFIG.TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: OAUTH_CONFIG.CLIENT_ID,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token refresh failed: ${response.status} ${errorText}`);
  }

  const data: TokenResponse = await response.json();
  const expiresAt = Date.now() + data.expires_in * 1000;
  const accountId = extractAccountId(data.access_token);

  return {
    access: data.access_token,
    refresh: data.refresh_token,
    expires: expiresAt,
    accountId,
  };
}

/**
 * Get valid access token, refreshing if needed
 */
async function getValidAccessToken(): Promise<{ access: string; accountId: string }> {
  const stored = localStorage.getItem('codex_credentials');
  if (!stored) {
    throw new Error('No credentials found - please login');
  }

  let credentials: OAuthCredentials = JSON.parse(stored);

  // Check if token is expired (with 5 minute buffer)
  if (Date.now() >= credentials.expires - 5 * 60 * 1000) {
    // Refresh token
    credentials = await refreshAccessToken(credentials.refresh);
    localStorage.setItem('codex_credentials', JSON.stringify(credentials));
  }

  return {
    access: credentials.access,
    accountId: credentials.accountId,
  };
}
```

---

## Step 7: Invoke OpenAI API

Now you can make API calls to ChatGPT's backend with your access token.

```typescript
const API_CONFIG = {
  BASE_URL: 'https://chatgpt.com/backend-api',
  ENDPOINT: '/codex/responses',
};

interface Message {
  role: 'user' | 'assistant';
  content: Array<{ type: 'input_text'; text: string }>;
}

interface ChatRequest {
  model: string;
  input: Message[];
  stream: boolean;
  max_output_tokens?: number;
  temperature?: number;
  instructions?: string;
}

/**
 * Send a chat message to OpenAI Codex API
 */
async function sendChatMessage(
  message: string,
  options?: {
    model?: string;
    temperature?: number;
    maxTokens?: number;
    instructions?: string;
  }
): Promise<void> {
  // Get valid credentials
  const { access, accountId } = await getValidAccessToken();

  // Prepare request
  const requestBody: ChatRequest = {
    model: options?.model || 'gpt-4o',
    input: [
      {
        role: 'user',
        content: [{ type: 'input_text', text: message }],
      },
    ],
    stream: true,
    ...(options?.maxTokens && { max_output_tokens: options.maxTokens }),
    ...(options?.temperature !== undefined && { temperature: options.temperature }),
    ...(options?.instructions && { instructions: options.instructions }),
  };

  // Make API request
  const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINT}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'text/event-stream',
      'Authorization': `Bearer ${access}`,
      'chatgpt-account-id': accountId,
      'OpenAI-Beta': 'responses=experimental',
      'originator': 'codex_cli_rs',
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`API request failed: ${response.status} ${errorText}`);
  }

  // Handle streaming response
  await handleStreamingResponse(response);
}

/**
 * Parse and handle Server-Sent Events (SSE) stream
 */
async function handleStreamingResponse(response: Response): Promise<void> {
  const reader = response.body?.getReader();
  if (!reader) {
    throw new Error('No response body');
  }

  const decoder = new TextDecoder();
  let buffer = '';

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const data = line.slice(6);
          if (data === '[DONE]') continue;

          try {
            const event = JSON.parse(data);
            handleStreamEvent(event);
          } catch (e) {
            console.error('Failed to parse SSE event:', e);
          }
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}

/**
 * Handle individual stream events
 */
function handleStreamEvent(event: any): void {
  const eventType = event.type;

  switch (eventType) {
    case 'response.output_item.added':
      console.log('New item:', event.item?.type);
      break;

    case 'response.output_text.delta':
      // Text delta - append to UI
      const textDelta = event.delta || '';
      console.log('Text:', textDelta);
      // Append textDelta to your UI here
      break;

    case 'response.completed':
      console.log('Response completed');
      console.log('Usage:', event.response?.usage);
      break;

    case 'error':
      console.error('Stream error:', event.message);
      break;

    default:
      console.log('Event:', eventType);
  }
}
```

---

## Complete Example

Here's a complete working example that ties everything together:

```typescript
/**
 * Complete Browser-Based Codex Auth Example
 */

class CodexClient {
  private config = {
    clientId: 'app_EMoamEEZ73f0CkXaXp7hrann',
    authorizeUrl: 'https://auth.openai.com/oauth/authorize',
    tokenUrl: 'https://auth.openai.com/oauth/token',
    redirectUri: window.location.origin + '/auth/callback',
    scope: 'openid profile email offline_access',
    apiBaseUrl: 'https://chatgpt.com/backend-api',
  };

  /**
   * Start OAuth login flow
   */
  async login(): Promise<void> {
    const { verifier, challenge } = await this.generatePKCE();
    const state = this.generateState();

    sessionStorage.setItem('pkce_verifier', verifier);
    sessionStorage.setItem('oauth_state', state);

    const url = new URL(this.config.authorizeUrl);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', this.config.redirectUri);
    url.searchParams.set('scope', this.config.scope);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('state', state);
    url.searchParams.set('codex_cli_simplified_flow', 'true');

    window.location.href = url.toString();
  }

  /**
   * Handle OAuth callback
   */
  async handleCallback(): Promise<void> {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');

    const savedState = sessionStorage.getItem('oauth_state');
    const verifier = sessionStorage.getItem('pkce_verifier');

    if (!code || !verifier || state !== savedState) {
      throw new Error('Invalid callback state');
    }

    const credentials = await this.exchangeCode(code, verifier);
    localStorage.setItem('codex_credentials', JSON.stringify(credentials));

    sessionStorage.removeItem('pkce_verifier');
    sessionStorage.removeItem('oauth_state');

    window.location.href = '/';
  }

  /**
   * Send a chat message
   */
  async chat(message: string, onDelta: (text: string) => void): Promise<void> {
    const { access, accountId } = await this.getValidToken();

    const response = await fetch(`${this.config.apiBaseUrl}/codex/responses`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream',
        'Authorization': `Bearer ${access}`,
        'chatgpt-account-id': accountId,
        'OpenAI-Beta': 'responses=experimental',
        'originator': 'codex_cli_rs',
      },
      body: JSON.stringify({
        model: 'gpt-4o',
        input: [{
          role: 'user',
          content: [{ type: 'input_text', text: message }],
        }],
        stream: true,
      }),
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    await this.streamResponse(response, onDelta);
  }

  /**
   * Check if user is logged in
   */
  isLoggedIn(): boolean {
    return !!localStorage.getItem('codex_credentials');
  }

  /**
   * Logout
   */
  logout(): void {
    localStorage.removeItem('codex_credentials');
  }

  // Private helper methods

  private async generatePKCE(): Promise<{ verifier: string; challenge: string }> {
    const verifierBytes = new Uint8Array(32);
    crypto.getRandomValues(verifierBytes);
    const verifier = this.base64urlEncode(verifierBytes);

    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(verifier));
    const challenge = this.base64urlEncode(new Uint8Array(hashBuffer));

    return { verifier, challenge };
  }

  private generateState(): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  }

  private base64urlEncode(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private async exchangeCode(code: string, verifier: string): Promise<any> {
    const response = await fetch(this.config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: this.config.clientId,
        code,
        code_verifier: verifier,
        redirect_uri: this.config.redirectUri,
      }),
    });

    if (!response.ok) throw new Error('Token exchange failed');

    const data = await response.json();
    const accountId = this.extractAccountId(data.access_token);

    return {
      access: data.access_token,
      refresh: data.refresh_token,
      expires: Date.now() + data.expires_in * 1000,
      accountId,
    };
  }

  private async getValidToken(): Promise<{ access: string; accountId: string }> {
    const stored = localStorage.getItem('codex_credentials');
    if (!stored) throw new Error('Not logged in');

    let creds = JSON.parse(stored);

    if (Date.now() >= creds.expires - 5 * 60 * 1000) {
      creds = await this.refreshToken(creds.refresh);
      localStorage.setItem('codex_credentials', JSON.stringify(creds));
    }

    return { access: creds.access, accountId: creds.accountId };
  }

  private async refreshToken(refreshToken: string): Promise<any> {
    const response = await fetch(this.config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.config.clientId,
      }),
    });

    if (!response.ok) throw new Error('Token refresh failed');

    const data = await response.json();
    const accountId = this.extractAccountId(data.access_token);

    return {
      access: data.access_token,
      refresh: data.refresh_token,
      expires: Date.now() + data.expires_in * 1000,
      accountId,
    };
  }

  private extractAccountId(token: string): string {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid JWT');

    const payload = JSON.parse(atob(parts[1]!.replace(/-/g, '+').replace(/_/g, '/')));
    const accountId = payload['https://api.openai.com/auth']?.chatgpt_account_id;

    if (!accountId) throw new Error('No account ID in token');
    return accountId;
  }

  private async streamResponse(response: Response, onDelta: (text: string) => void): Promise<void> {
    const reader = response.body?.getReader();
    if (!reader) throw new Error('No response body');

    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6);
            if (data === '[DONE]') continue;

            try {
              const event = JSON.parse(data);
              if (event.type === 'response.output_text.delta') {
                onDelta(event.delta || '');
              }
            } catch (e) {
              // Ignore parse errors
            }
          }
        }
      }
    } finally {
      reader.releaseLock();
    }
  }
}

// Usage Example
const client = new CodexClient();

// Login button
document.getElementById('login-btn')?.addEventListener('click', () => {
  client.login();
});

// Handle callback page
if (window.location.pathname === '/auth/callback') {
  client.handleCallback().catch(console.error);
}

// Chat button
document.getElementById('send-btn')?.addEventListener('click', async () => {
  const input = document.getElementById('message-input') as HTMLInputElement;
  const output = document.getElementById('output') as HTMLDivElement;

  output.textContent = '';

  await client.chat(input.value, (delta) => {
    output.textContent += delta;
  });
});
```
