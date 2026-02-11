---
name: auth-module-generator
description: Use when creating authentication system for any web project. Auto-detects framework (Next.js, Express, Fastify, NestJS, Hono, SvelteKit, Nuxt, etc.), ORM, and project conventions. Triggers on "인증 모듈", "auth module", "로그인 구현", "OAuth 설정", "JWT 인증", "magic link", "이메일 로그인", "authentication", "signup", "sign in" requests.
---

# Auth Module Generator

프로젝트 구조를 자동 감지하여 인증 모듈을 생성하는 프레임워크 독립 스킬.

## Phase 0: 프로젝트 감지 (필수 - 코드 생성 전에 반드시 실행)

스킬이 호출되면 **코드를 생성하기 전에** 아래 감지 단계를 반드시 수행한다.

### 0.1 프레임워크 감지

다음 파일들을 순서대로 확인하여 프레임워크를 결정한다:

| 감지 파일 | 프레임워크 | 라우팅 방식 |
|-----------|-----------|------------|
| `next.config.*` + `app/` 디렉터리 | Next.js App Router | 파일 기반 (`route.ts`) |
| `next.config.*` + `pages/` 디렉터리 | Next.js Pages Router | 파일 기반 (`pages/api/`) |
| `nuxt.config.*` | Nuxt 3 | 파일 기반 (`server/api/`) |
| `svelte.config.*` | SvelteKit | 파일 기반 (`+server.ts`) |
| `astro.config.*` | Astro | 파일 기반 (`pages/api/`) |
| `src/main.ts` + `@nestjs/core` in deps | NestJS | 데코레이터 기반 |
| `fastify` in deps | Fastify | 플러그인 기반 |
| `hono` in deps | Hono | 메서드 체이닝 |
| `express` in deps | Express | 라우터 기반 |
| `elysia` in deps | Elysia (Bun) | 메서드 체이닝 |

**감지 방법:**
```
1. Glob: package.json, next.config.*, nuxt.config.*, svelte.config.*, astro.config.*
2. Read: package.json → dependencies, devDependencies 확인
3. Glob: app/**/route.ts, pages/api/**, src/main.ts, server/api/**
```

### 0.2 ORM/DB 감지

| 감지 파일/의존성 | ORM | 스키마 형식 |
|----------------|-----|-----------|
| `prisma/schema.prisma` 또는 `@prisma/client` | Prisma | `.prisma` |
| `drizzle.config.*` 또는 `drizzle-orm` | Drizzle | TypeScript 스키마 |
| `typeorm` in deps | TypeORM | 데코레이터 엔티티 |
| `mongoose` in deps | Mongoose | 스키마 정의 |
| `@supabase/supabase-js` | Supabase | SQL migration |
| `better-sqlite3` / `@libsql/client` | Raw SQL | SQL |
| 감지 실패 | 없음 (인메모리 또는 사용자에게 질문) | — |

### 0.3 기존 프로젝트 구조 감지

```
1. Glob: src/**/*, app/**/*, lib/**/*, utils/**/*, helpers/**/*
2. 소스 루트 결정: src/ 존재 여부
3. 기존 미들웨어 패턴 확인: middleware.ts, middleware/**, plugins/**
4. 기존 에러 핸들링 패턴 확인: errors/**, exceptions/**
5. 기존 유틸/헬퍼 위치 확인: lib/, utils/, helpers/, common/
6. 기존 서비스 레이어 확인: services/**, modules/**
7. 기존 import alias 확인: tsconfig.json → paths (예: @/*, ~/*, #/*)
```

### 0.4 기존 인증 관련 코드 감지

```
1. Grep: "auth", "login", "session", "jwt", "bcrypt", "passport" 등
2. 이미 NextAuth/Auth.js 사용 중인지 확인: next-auth in deps
3. 이미 Passport.js 사용 중인지 확인: passport in deps
4. 이미 자체 인증이 있는지 확인: auth 관련 라우트/모듈 존재 여부
```

> 기존 인증 시스템이 발견되면 사용자에게 보고하고, 통합/교체/공존 여부를 질문한다.

### 0.5 패키지 매니저 감지

| 감지 파일 | 매니저 | 설치 명령 |
|-----------|--------|----------|
| `bun.lockb` / `bun.lock` | bun | `bun add` |
| `pnpm-lock.yaml` | pnpm | `pnpm add` |
| `yarn.lock` | yarn | `yarn add` |
| `package-lock.json` | npm | `npm install` |

### 0.6 감지 결과 요약

모든 감지가 끝나면 **반드시** 사용자에게 아래 형식으로 요약을 보여주고 확인을 받는다:

```
## 프로젝트 감지 결과

| 항목 | 감지 결과 |
|------|----------|
| 프레임워크 | {framework} {version} |
| 라우팅 방식 | {routing_style} |
| ORM/DB | {orm} |
| 소스 루트 | {src_root} |
| 미들웨어 패턴 | {middleware_pattern} |
| Import alias | {alias} |
| 패키지 매니저 | {pkg_manager} |
| 기존 인증 | {existing_auth} |
```

---

## Phase 1: 인증 방식 선택

사용자에게 AskUserQuestion으로 필요한 인증 방식을 질문한다:

| 방식 | 설명 | 필요 의존성 |
|------|------|-----------|
| ID/Password | 이메일+비밀번호, bcrypt 해싱 | `bcryptjs`, `jose` |
| OAuth | Google, GitHub, etc. | `jose` |
| Magic Link | 이메일 일회용 링크 | `jose`, 이메일 서비스 |
| Session 기반 | 서버 세션 + 쿠키 | `express-session` 등 (프레임워크별) |

추가 옵션:
- 토큰 저장 방식: HttpOnly Cookie (권장) vs Authorization Header
- 토큰 블랙리스트: Redis / 인메모리 / DB
- Refresh Token 사용 여부

---

## Phase 2: 코드 생성 (감지된 구조에 맞춤)

### 2.1 생성할 파일 결정

감지된 프레임워크에 따라 파일 경로를 동적으로 결정한다.
**절대로 하드코딩된 경로를 사용하지 않는다.** 감지된 `{src_root}`, `{api_base}`, `{util_dir}` 등의 변수를 사용한다.

#### 프레임워크별 라우트 매핑

**Next.js App Router:**
```
{src_root}/app/api/auth/login/route.ts
{src_root}/app/api/auth/register/route.ts
{src_root}/app/api/auth/logout/route.ts
{src_root}/app/api/auth/refresh/route.ts
{src_root}/app/api/auth/me/route.ts
{src_root}/app/api/auth/oauth/[provider]/callback/route.ts
{src_root}/app/api/auth/magic-link/send/route.ts
{src_root}/app/api/auth/magic-link/verify/route.ts
```

**Next.js Pages Router:**
```
{src_root}/pages/api/auth/login.ts
{src_root}/pages/api/auth/register.ts
{src_root}/pages/api/auth/logout.ts
{src_root}/pages/api/auth/refresh.ts
{src_root}/pages/api/auth/me.ts
{src_root}/pages/api/auth/oauth/[provider]/callback.ts
{src_root}/pages/api/auth/magic-link/send.ts
{src_root}/pages/api/auth/magic-link/verify.ts
```

**Express / Fastify / Hono:**
```
{src_root}/{routes_dir}/auth.ts          (또는 auth/index.ts)
{src_root}/{routes_dir}/auth/login.ts
{src_root}/{routes_dir}/auth/register.ts
{src_root}/{routes_dir}/auth/oauth.ts
{src_root}/{routes_dir}/auth/magic-link.ts
```

**NestJS:**
```
{src_root}/auth/auth.module.ts
{src_root}/auth/auth.controller.ts
{src_root}/auth/auth.service.ts
{src_root}/auth/guards/jwt-auth.guard.ts
{src_root}/auth/strategies/jwt.strategy.ts
{src_root}/auth/dto/login.dto.ts
{src_root}/auth/dto/register.dto.ts
```

**SvelteKit:**
```
src/routes/api/auth/login/+server.ts
src/routes/api/auth/register/+server.ts
src/routes/api/auth/logout/+server.ts
src/routes/api/auth/oauth/[provider]/callback/+server.ts
```

**Nuxt 3:**
```
server/api/auth/login.post.ts
server/api/auth/register.post.ts
server/api/auth/logout.post.ts
server/api/auth/me.get.ts
server/api/auth/oauth/[provider]/callback.get.ts
```

#### 공통 유틸리티 파일

감지된 구조에 맞는 위치에 생성:
```
{util_dir}/auth/jwt.ts              # JWT 생성/검증
{util_dir}/auth/password.ts         # 비밀번호 해싱
{util_dir}/auth/oauth.ts            # OAuth 유틸 (선택)
{util_dir}/auth/token-blacklist.ts  # 토큰 무효화 (선택)
{service_dir}/auth.service.ts       # 인증 서비스 로직 (서비스 레이어 존재 시)
{middleware_dir}/auth.ts            # 인증 미들웨어/가드
{types_dir}/auth.ts                 # 타입 정의
```

### 2.2 DB 스키마 생성

감지된 ORM에 따라 스키마를 생성한다.

#### Prisma
```prisma
model User {
  id            String    @id @default(cuid())
  email         String    @unique
  password      String?
  name          String?
  role          String    @default("user")
  emailVerified DateTime?
  isActive      Boolean   @default(true)
  oauthAccounts OAuthAccount[]
  magicLinks    MagicLink[]
  lastLoginAt   DateTime?
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @updatedAt
}

model OAuthAccount {
  id         String @id @default(cuid())
  userId     String
  provider   String
  providerId String
  user       User   @relation(fields: [userId], references: [id])
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
```

#### Drizzle
```typescript
import { pgTable, text, timestamp, boolean, unique } from 'drizzle-orm/pg-core';
import { createId } from '@paralleldrive/cuid2';

export const users = pgTable('users', {
  id: text('id').primaryKey().$defaultFn(() => createId()),
  email: text('email').notNull().unique(),
  password: text('password'),
  name: text('name'),
  role: text('role').notNull().default('user'),
  emailVerified: timestamp('email_verified'),
  isActive: boolean('is_active').notNull().default(true),
  lastLoginAt: timestamp('last_login_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

export const oauthAccounts = pgTable('oauth_accounts', {
  id: text('id').primaryKey().$defaultFn(() => createId()),
  userId: text('user_id').notNull().references(() => users.id),
  provider: text('provider').notNull(),
  providerId: text('provider_id').notNull(),
}, (t) => [unique().on(t.provider, t.providerId)]);

export const magicLinks = pgTable('magic_links', {
  id: text('id').primaryKey().$defaultFn(() => createId()),
  userId: text('user_id').notNull().references(() => users.id),
  token: text('token').notNull().unique(),
  expiresAt: timestamp('expires_at').notNull(),
  usedAt: timestamp('used_at'),
});
```

#### TypeORM
```typescript
@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid') id: string;
  @Column({ unique: true }) email: string;
  @Column({ nullable: true }) password: string;
  @Column({ nullable: true }) name: string;
  @Column({ default: 'user' }) role: string;
  @Column({ type: 'timestamp', nullable: true }) emailVerified: Date;
  @Column({ default: true }) isActive: boolean;
  @OneToMany(() => OAuthAccount, (oa) => oa.user) oauthAccounts: OAuthAccount[];
  @CreateDateColumn() createdAt: Date;
  @UpdateDateColumn() updatedAt: Date;
}
```

#### Mongoose
```typescript
const userSchema = new Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String },
  name: { type: String },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  emailVerified: { type: Date },
  isActive: { type: Boolean, default: true },
  lastLoginAt: { type: Date },
}, { timestamps: true });
```

#### Supabase (SQL migration)
```sql
create table users (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  password text,
  name text,
  role text not null default 'user',
  email_verified timestamptz,
  is_active boolean not null default true,
  last_login_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
```

### 2.3 JWT 유틸 (프레임워크 독립)

```typescript
// {util_dir}/auth/jwt.ts
import { SignJWT, jwtVerify } from 'jose';

const secret = new TextEncoder().encode(process.env.JWT_SECRET);

export async function createAccessToken(payload: { userId: string; email: string; role: string }) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(process.env.JWT_EXPIRES_IN || '7d')
    .sign(secret);
}

export async function createRefreshToken(userId: string) {
  return new SignJWT({ userId, type: 'refresh' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(process.env.JWT_REFRESH_EXPIRES_IN || '30d')
    .sign(secret);
}

export async function verifyToken(token: string) {
  const { payload } = await jwtVerify(token, secret);
  return payload;
}

export function extractBearerToken(header: string | null): string | null {
  if (!header?.startsWith('Bearer ')) return null;
  return header.slice(7);
}
```

### 2.4 비밀번호 유틸 (프레임워크 독립)

```typescript
// {util_dir}/auth/password.ts
import bcrypt from 'bcryptjs';

const SALT_ROUNDS = 10;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
```

### 2.5 인증 미들웨어 (프레임워크별 적응)

생성 시 감지된 프레임워크의 미들웨어 패턴을 따른다.

**프레임워크별 미들웨어 패턴:**

| 프레임워크 | 패턴 |
|-----------|------|
| Next.js App Router | `middleware.ts` 또는 래퍼 함수 |
| Next.js Pages Router | HOF 래퍼 또는 `middleware.ts` |
| Express | `(req, res, next) => {}` |
| Fastify | `fastify.addHook('preHandler', ...)` 또는 플러그인 |
| Hono | `app.use('*', async (c, next) => {})` |
| NestJS | `@UseGuards(JwtAuthGuard)` |
| SvelteKit | `hooks.server.ts` + `handle` |
| Nuxt 3 | `server/middleware/auth.ts` |

코드 생성 시 **기존 프로젝트에 미들웨어 패턴이 이미 있으면 그 패턴을 따르고**, 없으면 프레임워크 표준 패턴을 사용한다.

### 2.6 API 핸들러 (프레임워크별 적응)

각 프레임워크의 요청/응답 API에 맞게 핸들러를 생성한다.
프레임워크별 차이점:

| 기능 | Next.js App Router | Express | Hono | NestJS |
|------|-------------------|---------|------|--------|
| 요청 body | `request.json()` | `req.body` | `c.req.json()` | `@Body() dto` |
| 응답 | `NextResponse.json()` | `res.json()` | `c.json()` | `return dto` |
| 쿼리 파라미터 | `request.nextUrl.searchParams` | `req.query` | `c.req.query()` | `@Query()` |
| 헤더 | `request.headers.get()` | `req.headers[]` | `c.req.header()` | `@Headers()` |
| 쿠키 설정 | `response.cookies.set()` | `res.cookie()` | `setCookie(c, ...)` | `@Res() res` |
| 리다이렉트 | `NextResponse.redirect()` | `res.redirect()` | `c.redirect()` | `@Redirect()` |
| 검증 | `zod` | `zod` / `joi` | `zod` / `@hono/zod-validator` | `class-validator` |

---

## Phase 3: 환경 변수 설정

선택된 인증 방식에 따라 `.env.example` 에 추가할 변수 목록을 제시한다.

```env
# === Auth Core (필수) ===
JWT_SECRET=                          # 최소 32자
JWT_EXPIRES_IN=7d
JWT_REFRESH_EXPIRES_IN=30d

# === OAuth - Google (OAuth 선택 시) ===
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://localhost:{port}/api/auth/oauth/google/callback

# === OAuth - GitHub (OAuth 선택 시) ===
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_REDIRECT_URI=http://localhost:{port}/api/auth/oauth/github/callback

# === Magic Link (Magic Link 선택 시) ===
MAGIC_LINK_SECRET=
MAGIC_LINK_EXPIRES_IN=15m
EMAIL_FROM=noreply@example.com

# === Token Blacklist - Redis (선택) ===
REDIS_URL=
# 또는 Upstash:
# UPSTASH_REDIS_REST_URL=
# UPSTASH_REDIS_REST_TOKEN=
```

`{port}` 는 프로젝트의 기본 포트를 감지하여 결정한다 (package.json scripts, 설정 파일 등).

---

## Phase 4: 의존성 설치

감지된 패키지 매니저로 필요한 패키지를 설치한다.

```
# 공통 필수
jose            # JWT (Edge Runtime 호환, jsonwebtoken 대신 사용)
bcryptjs        # 비밀번호 해싱
zod             # 입력 검증 (NestJS는 class-validator 사용)

# 선택적
@upstash/redis  # 토큰 블랙리스트 (Redis 선택 시)
nodemailer      # Magic Link 이메일 발송 시
```

NestJS인 경우: `@nestjs/jwt`, `@nestjs/passport`, `passport-jwt`, `class-validator`, `class-transformer` 를 대신 사용할 수 있다.

---

## Phase 5: 보안 체크리스트

| 항목 | 구현 |
|------|------|
| 비밀번호 | bcrypt 해싱 (salt rounds: 10+) |
| JWT | HS256 알고리즘, HttpOnly 쿠키 저장 권장 |
| OAuth | CSRF 보호 (state 파라미터) |
| Magic Link | 15분 만료, 일회용, 토큰 해시 저장 |
| Rate Limit | 프레임워크에 맞는 rate limiter 적용 |
| 토큰 무효화 | Redis 또는 인메모리 블랙리스트 |
| 에러 메시지 | 사용자 존재 여부를 노출하지 않는 일관된 에러 |
| CORS | 프로덕션 도메인만 허용 |

---

## 핵심 규칙

1. **감지 우선**: 코드 생성 전에 반드시 Phase 0 프로젝트 감지를 완료한다.
2. **기존 패턴 준수**: 프로젝트에 이미 있는 코드 스타일, 네이밍, 디렉토리 구조를 따른다.
3. **최소 의존성**: 프레임워크에 이미 포함된 기능은 외부 패키지 대신 활용한다.
4. **점진적 생성**: 사용자가 선택한 인증 방식에 해당하는 파일만 생성한다.
5. **충돌 방지**: 기존 파일을 덮어쓰지 않고, 충돌 가능성이 있으면 사용자에게 확인한다.
6. **import 경로**: 감지된 tsconfig paths alias를 사용한다.
