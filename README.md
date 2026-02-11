# Auth Module Generator

프로젝트 구조를 자동 감지하여 인증 시스템을 생성하는 Claude Code 스킬입니다.

## Features

- **프레임워크 자동 감지** - Next.js, Express, Fastify, NestJS, Hono, SvelteKit, Nuxt, Astro, Elysia
- **ORM 자동 감지** - Prisma, Drizzle, TypeORM, Mongoose, Supabase, Raw SQL
- **기존 구조 준수** - 프로젝트의 디렉토리 구조, 네이밍 컨벤션, import alias를 따름
- **ID/Password 인증** - bcrypt 해싱, JWT 토큰 발급
- **OAuth 인증** - Google, GitHub 등
- **Magic Link** - 이메일 일회용 로그인 링크
- **토큰 관리** - Access/Refresh 토큰, 블랙리스트
- **보안** - HttpOnly 쿠키, CSRF 보호, Rate Limiting

## Installation

```bash
# 심볼릭 링크로 설치
ln -s "$(pwd)" ~/.claude/skills/auth-module-generator
```

## Usage

### 트리거 키워드

| 한국어 | English |
|--------|---------|
| 인증 모듈 | auth module |
| 로그인 구현 | authentication |
| OAuth 설정 | OAuth setup |
| JWT 인증 | JWT auth |
| magic link | magic link |
| 회원가입 | signup / sign in |

### 사용 예시

```
# Claude Code에서
> 인증 모듈 추가해줘
> Add authentication to this project
> /auth-module-generator
```

## How It Works

### Phase 0: 프로젝트 감지 (자동)

스킬이 호출되면 코드 생성 전에 프로젝트를 분석합니다:

1. **프레임워크 감지** - `package.json`, 설정 파일, 디렉토리 구조로 판별
2. **ORM/DB 감지** - 스키마 파일, 의존성으로 판별
3. **프로젝트 구조 감지** - 소스 루트, 미들웨어 패턴, import alias
4. **기존 인증 감지** - NextAuth, Passport 등 기존 시스템 충돌 확인
5. **패키지 매니저 감지** - lock 파일로 npm/yarn/pnpm/bun 판별

감지 결과를 사용자에게 보여주고 확인을 받은 후 코드를 생성합니다.

### Phase 1: 인증 방식 선택

사용자가 필요한 인증 방식을 선택합니다:
- ID/Password
- OAuth (Google, GitHub)
- Magic Link
- Session 기반

### Phase 2-5: 코드 생성

감지된 프레임워크와 ORM에 맞는 코드를 생성합니다.

## Supported Frameworks

| Framework | Routing | Middleware |
|-----------|---------|-----------|
| Next.js App Router | `app/api/**/route.ts` | 래퍼 함수 / `middleware.ts` |
| Next.js Pages Router | `pages/api/**/*.ts` | HOF 래퍼 |
| Express | 라우터 기반 | `(req, res, next)` |
| Fastify | 플러그인 기반 | `addHook('preHandler')` |
| Hono | 메서드 체이닝 | `app.use()` |
| NestJS | 데코레이터 기반 | `@UseGuards()` |
| SvelteKit | `+server.ts` | `hooks.server.ts` |
| Nuxt 3 | `server/api/` | `server/middleware/` |
| Astro | `pages/api/` | 미들웨어 |
| Elysia (Bun) | 메서드 체이닝 | 플러그인 |

## Supported ORMs

| ORM | Schema Format |
|-----|--------------|
| Prisma | `.prisma` 파일 |
| Drizzle | TypeScript 스키마 |
| TypeORM | 데코레이터 엔티티 |
| Mongoose | 스키마 정의 |
| Supabase | SQL migration |
| Raw SQL | SQL 파일 |

## Dependencies

프레임워크에 따라 자동으로 결정됩니다:

```
# 공통
jose          # JWT (Edge Runtime 호환)
bcryptjs      # 비밀번호 해싱
zod           # 입력 검증

# 선택적
@upstash/redis  # 토큰 블랙리스트
nodemailer      # Magic Link 이메일 발송
```

## Security

| Feature | Implementation |
|---------|---------------|
| Password | bcrypt (salt rounds: 10+) |
| JWT | HS256, HttpOnly Cookie |
| OAuth | CSRF protection (state parameter) |
| Magic Link | 15min expiry, one-time use |
| Rate Limit | 프레임워크별 rate limiter |
| Token Revocation | Redis / in-memory blacklist |
| Error Messages | 사용자 존재 여부 미노출 |

## License

MIT
