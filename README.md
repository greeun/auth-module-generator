# Auth Module Generator

Next.js 15 App Router 기반 완전한 인증 시스템을 생성하는 Claude Code 스킬입니다.

## Features

- **ID/Password 인증** - bcrypt 해싱, JWT 토큰 발급
- **OAuth 인증** - Google, GitHub 지원
- **Magic Link** - 이메일 일회용 로그인 링크
- **토큰 관리** - Access/Refresh 토큰, 블랙리스트
- **보안** - HttpOnly 쿠키, CSRF 보호, Rate Limiting

## Installation

### 1. 스킬 디렉토리 생성

```bash
mkdir -p ~/.claude/skills/auth-module-generator
```

### 2. 스킬 파일 복사

`SKILL.md` 파일을 `~/.claude/skills/auth-module-generator/` 디렉토리에 복사합니다.

### 3. 설치 확인

```bash
ls ~/.claude/skills/auth-module-generator/
# SKILL.md  README.md
```

## Usage

### 트리거 키워드

다음 키워드로 스킬을 자동 호출할 수 있습니다:

| 한국어 | English |
|--------|---------|
| 인증 모듈 | auth module |
| 로그인 구현 | login implementation |
| OAuth 설정 | OAuth setup |
| JWT 인증 | JWT authentication |
| 이메일 로그인 | email login |
| magic link | magic link |

### 사용 예시

```
# Claude Code 실행 후
> 인증 모듈 추가해줘

# 또는 직접 호출
> /auth-module-generator
```

### 대화 예시

```
사용자: 새 프로젝트에 로그인 기능 추가하고 싶어

Claude: auth-module-generator 스킬을 사용하여 인증 시스템을 구현하겠습니다.
        어떤 인증 방식을 사용하시겠습니까?
        1. ID/Password (기본)
        2. OAuth (Google, GitHub)
        3. Magic Link (이메일)
        4. 모두 포함
```

## Generated Structure

스킬 실행 시 다음 구조가 생성됩니다:

```
src/
├── app/api/auth/
│   ├── login/route.ts           # POST - JWT 로그인
│   ├── register/route.ts        # POST - 회원가입
│   ├── logout/route.ts          # POST - 로그아웃
│   ├── refresh/route.ts         # POST - 토큰 갱신
│   ├── me/route.ts              # GET - 현재 사용자
│   ├── oauth/
│   │   ├── login/route.ts       # POST - OAuth 시작
│   │   ├── google/
│   │   │   └── callback/route.ts
│   │   └── github/
│   │       └── callback/route.ts
│   └── magic-link/
│       ├── send/route.ts        # POST - 링크 발송
│       └── verify/route.ts      # GET - 링크 검증
├── shared/@withwiz/
│   ├── auth/core/jwt/
│   │   ├── index.ts             # JWTManager 클래스
│   │   └── types.ts             # 타입 정의
│   └── middleware/
│       ├── auth.ts              # 인증 미들웨어
│       └── wrappers.ts          # API 래퍼 함수
└── lib/
    ├── services/auth/
    │   └── refreshTokenService.ts
    └── utils/
        ├── jwt.ts
        └── oauth.ts
```

## Configuration

### 환경 변수 (.env)

```env
# JWT (필수)
JWT_SECRET=your-secret-key-at-least-32-characters
JWT_EXPIRES_IN=7d
JWT_REFRESH_TOKEN_EXPIRES_IN=30d

# OAuth - Google (선택)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:3000/api/auth/oauth/google/callback

# OAuth - GitHub (선택)
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_REDIRECT_URI=http://localhost:3000/api/auth/oauth/github/callback

# Magic Link (선택)
MAGIC_LINK_SECRET=your-magic-link-secret-32-chars
MAGIC_LINK_EXPIRES_IN=15m
EMAIL_FROM=noreply@example.com

# Redis - 토큰 블랙리스트 (선택)
UPSTASH_REDIS_REST_URL=your-redis-url
UPSTASH_REDIS_REST_TOKEN=your-redis-token
```

### Prisma Schema

```prisma
model User {
  id            String    @id @default(cuid())
  email         String    @unique
  password      String?
  name          String?
  role          Role      @default(USER)
  emailVerified DateTime?
  isActive      Boolean   @default(true)

  oauthAccounts OAuthAccount[]
  magicLinks    MagicLink[]

  lastLoginAt   DateTime?
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @updatedAt
}

model OAuthAccount {
  id           String  @id @default(cuid())
  userId       String
  provider     String
  providerId   String
  accessToken  String?
  refreshToken String?

  user         User    @relation(fields: [userId], references: [id])

  @@unique([provider, providerId])
}

model MagicLink {
  id        String    @id @default(cuid())
  userId    String
  token     String    @unique
  expiresAt DateTime
  usedAt    DateTime?

  user      User      @relation(fields: [userId], references: [id])
}

enum Role {
  USER
  ADMIN
}
```

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/auth/register` | POST | - | 회원가입 |
| `/api/auth/login` | POST | - | 로그인 (JWT 발급) |
| `/api/auth/logout` | POST | Required | 로그아웃 |
| `/api/auth/refresh` | POST | - | 토큰 갱신 |
| `/api/auth/me` | GET | Required | 현재 사용자 정보 |
| `/api/auth/oauth/login` | POST | - | OAuth 로그인 시작 |
| `/api/auth/oauth/google/callback` | GET | - | Google 콜백 |
| `/api/auth/oauth/github/callback` | GET | - | GitHub 콜백 |
| `/api/auth/magic-link/send` | POST | - | Magic Link 발송 |
| `/api/auth/magic-link/verify` | GET | - | Magic Link 검증 |

## Security

| Feature | Implementation |
|---------|---------------|
| Password | bcrypt (salt rounds: 10+) |
| JWT | HS256, HttpOnly Cookie |
| OAuth | CSRF protection (state parameter) |
| Magic Link | 15min expiry, one-time use |
| Rate Limit | Login: 10/min, API: 120/min |
| Token Revocation | Redis + In-memory hybrid |

## Client Integration

### React Context Example

```typescript
import { createContext, useContext, useState } from 'react';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);

  const login = async (email: string, password: string) => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
      credentials: 'include',
    });
    const data = await res.json();
    setUser(data.user);
    return data;
  };

  const logout = async () => {
    await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include',
    });
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
```

### Usage in Components

```typescript
function LoginForm() {
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    await login(formData.get('email'), formData.get('password'));
  };

  return (
    <form onSubmit={handleSubmit}>
      <input name="email" type="email" required />
      <input name="password" type="password" required />
      <button type="submit">Login</button>
    </form>
  );
}
```

## Error Codes

| Code | Key | HTTP | Description |
|------|-----|------|-------------|
| 40101 | UNAUTHORIZED | 401 | 인증 필요/실패 |
| 40102 | INVALID_TOKEN | 401 | 유효하지 않은 토큰 |
| 40103 | TOKEN_EXPIRED | 401 | 토큰 만료 |
| 40106 | OAUTH_FAILED | 401 | OAuth 인증 실패 |
| 40107 | MAGIC_LINK_EXPIRED | 401 | Magic Link 만료 |
| 40301 | ACCOUNT_DISABLED | 403 | 계정 비활성화 |
| 40305 | EMAIL_NOT_VERIFIED | 403 | 이메일 미인증 |

## OAuth Setup

### Google

1. [Google Cloud Console](https://console.cloud.google.com/) 접속
2. 새 프로젝트 생성 또는 기존 프로젝트 선택
3. **APIs & Services** → **Credentials** → **Create Credentials** → **OAuth 2.0 Client ID**
4. Application type: **Web application**
5. Authorized redirect URIs에 추가:
   ```
   http://localhost:3000/api/auth/oauth/google/callback
   https://your-domain.com/api/auth/oauth/google/callback
   ```
6. Client ID와 Client Secret을 환경 변수에 설정

### GitHub

1. [GitHub Developer Settings](https://github.com/settings/developers) 접속
2. **OAuth Apps** → **New OAuth App**
3. 설정:
   - Application name: Your App Name
   - Homepage URL: `http://localhost:3000`
   - Authorization callback URL:
     ```
     http://localhost:3000/api/auth/oauth/github/callback
     ```
4. Client ID와 Client Secret을 환경 변수에 설정

## Dependencies

```json
{
  "dependencies": {
    "jose": "^5.0.0",
    "bcrypt": "^5.1.0",
    "zod": "^3.22.0",
    "@upstash/redis": "^1.25.0"
  },
  "devDependencies": {
    "@types/bcrypt": "^5.0.0"
  }
}
```

## Checklist

프로젝트에 적용 시 확인할 항목:

- [ ] JWT_SECRET 32자 이상 설정
- [ ] Prisma 스키마에 User, OAuthAccount, MagicLink 모델 추가
- [ ] `npx prisma migrate dev` 실행
- [ ] OAuth 제공자 콘솔에서 Redirect URI 설정
- [ ] 이메일 발송 서비스 연동 (Magic Link 사용 시)
- [ ] Redis 연결 설정 (토큰 블랙리스트용)
- [ ] Rate Limiting 미들웨어 설정
- [ ] 에러 코드 및 메시지 다국어 지원
- [ ] 로그인 성공/실패 후 리다이렉트 경로 설정
- [ ] 프론트엔드 AuthContext/AuthProvider 구현

## License

MIT

## Contributing

이슈나 PR을 환영합니다.

## Related Skills

- `nextjs-project-wizard` - Next.js 15 프로젝트 생성
- `api-endpoint-creator` - API 엔드포인트 생성
- `webapp-testing` - 웹앱 테스트
