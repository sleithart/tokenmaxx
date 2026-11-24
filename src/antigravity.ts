import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { z } from 'zod'
import {
	type Account,
	AccountEmailSchema,
	type FetchImplementation,
	type ProviderProbeResult,
	type UsageSnapshot,
	type UsageWindow
} from './domain.ts'
import { ApplicationError, loginFailureMessage } from './errors.ts'
import { type CredentialVault, exclusive } from './vault.ts'

const nativeKeychainService = 'gemini'
const nativeKeychainAccount = 'antigravity'
const goKeyringBase64Prefix = 'go-keyring-base64:'
const cloudCodeBase = 'https://daily-cloudcode-pa.googleapis.com'
const loadCodeAssistEndpoint = `${cloudCodeBase}/v1internal:loadCodeAssist`
const fetchAvailableModelsEndpoint = `${cloudCodeBase}/v1internal:fetchAvailableModels`
const userinfoEndpoint = 'https://www.googleapis.com/oauth2/v2/userinfo'
const oauthTokenEndpoint = 'https://oauth2.googleapis.com/token'
const refreshMarginMilliseconds = 120_000
const userAgent = 'antigravity/1.5.16'

const AntigravityTokenSchema = z
	.object({
		access_token: z.string().min(1),
		expires_in: z.number().optional(),
		expiry: z.string().min(1),
		refresh_token: z.string().min(1),
		token_type: z.string().optional()
	})
	.passthrough()

export const AntigravityAuthSchema = z
	.object({
		auth_method: z.string().optional(),
		id_token_email: z.string().optional(),
		token: AntigravityTokenSchema
	})
	.passthrough()
export type AntigravityAuth = z.infer<typeof AntigravityAuthSchema>

const UserinfoSchema = z
	.object({
		email: z.string().optional(),
		id: z.string().min(1).optional(),
		sub: z.string().min(1).optional()
	})
	.passthrough()

const TokenRefreshResponseSchema = z
	.object({
		access_token: z.string().min(1),
		expires_in: z.number().positive(),
		refresh_token: z.string().min(1).optional(),
		token_type: z.string().optional()
	})
	.passthrough()

const LoadCodeAssistResponseSchema = z
	.object({
		cloudaicompanionProject: z
			.union([z.string(), z.object({ id: z.string().optional() }).passthrough()])
			.nullish(),
		currentTier: z.object({ id: z.string().optional() }).passthrough().nullish(),
		paidTier: z.object({ id: z.string().optional() }).passthrough().nullish()
	})
	.passthrough()

const ModelQuotaInfoSchema = z
	.object({
		remainingFraction: z.number().min(0).max(1).optional(),
		resetTime: z.string().nullish()
	})
	.passthrough()

const AvailableModelSchema = z
	.object({
		displayName: z.string().optional(),
		quotaInfo: ModelQuotaInfoSchema.nullish()
	})
	.passthrough()

const FetchAvailableModelsResponseSchema = z
	.object({
		models: z.record(z.string(), AvailableModelSchema).optional()
	})
	.passthrough()

export interface AntigravityKeychain {
	read(): Promise<string | null>
	write(raw: string): Promise<void>
	remove(): Promise<void>
}

export interface AntigravityLoginDependencies {
	interactive(
		command: readonly string[],
		environment: Record<string, string | undefined>
	): Promise<{ exitCode: number; stderr: string }>
}

interface SecurityCommandResult {
	exitCode: number
	stdout: string
	stderr: string
}

interface SecurityCommandRunner {
	run(command: readonly string[], stdinText?: string): Promise<SecurityCommandResult>
}

function defaultSecurityRunner(): SecurityCommandRunner {
	return {
		async run(command, stdinText) {
			const child = Bun.spawn([...command], {
				stderr: 'pipe',
				stdin: 'pipe',
				stdout: 'pipe'
			})
			if (stdinText !== undefined) {
				child.stdin.write(stdinText)
			}
			child.stdin.end()
			const [exitCode, stdout, stderr] = await Promise.all([
				child.exited,
				new Response(child.stdout).text(),
				new Response(child.stderr).text()
			])
			return { exitCode, stderr, stdout }
		}
	}
}

export function createNativeAntigravityKeychain(
	runner: SecurityCommandRunner = defaultSecurityRunner()
): AntigravityKeychain {
	return {
		async read() {
			const result = await runner.run([
				'security',
				'find-generic-password',
				'-s',
				nativeKeychainService,
				'-a',
				nativeKeychainAccount,
				'-w'
			])
			if (result.exitCode === 44) {
				return null
			}
			if (result.exitCode !== 0) {
				throw new ApplicationError(
					'KEYCHAIN_READ_FAILED',
					result.stderr.trim() || 'Could not read Antigravity credential from macOS Keychain'
				)
			}
			return result.stdout.trim()
		},
		async remove() {
			const result = await runner.run([
				'security',
				'delete-generic-password',
				'-s',
				nativeKeychainService,
				'-a',
				nativeKeychainAccount
			])
			if (result.exitCode !== 0 && result.exitCode !== 44) {
				throw new ApplicationError(
					'KEYCHAIN_DELETE_FAILED',
					result.stderr.trim() || 'Could not remove Antigravity credential from macOS Keychain'
				)
			}
		},
		async write(raw) {
			const command = `add-generic-password -U -s ${nativeKeychainService} -a ${nativeKeychainAccount} -w ${raw}\n`
			const result = await runner.run(['security', '-i'], command)
			if (result.exitCode !== 0) {
				throw new ApplicationError(
					'KEYCHAIN_WRITE_FAILED',
					result.stderr.trim() || 'Could not write Antigravity credential to macOS Keychain'
				)
			}
		}
	}
}

function defaultLoginDependencies(): AntigravityLoginDependencies {
	return {
		async interactive(command, environment) {
			const child = Bun.spawn([...command], {
				env: { ...process.env, ...environment },
				stderr: 'pipe',
				stdin: 'inherit',
				stdout: 'inherit'
			})
			const decoder = new TextDecoder()
			let stderr = ''
			for await (const chunk of child.stderr) {
				process.stderr.write(chunk)
				stderr = `${stderr}${decoder.decode(chunk, { stream: true })}`.slice(-4_096)
			}
			return { exitCode: await child.exited, stderr }
		}
	}
}

export function encodeAntigravityKeychainPayload(credential: AntigravityAuth): string {
	const encoded = Buffer.from(JSON.stringify(credential), 'utf8').toString('base64')
	return `${goKeyringBase64Prefix}${encoded}`
}

export function decodeAntigravityKeychainPayload(raw: string): AntigravityAuth {
	let text = raw.trim()
	if (/^[0-9a-fA-F]+$/.test(text) && text.length % 2 === 0) {
		const hexDecoded = Buffer.from(text, 'hex').toString('utf8')
		if (hexDecoded.startsWith(goKeyringBase64Prefix) || hexDecoded.trimStart().startsWith('{')) {
			text = hexDecoded.trim()
		}
	}
	if (text.startsWith(goKeyringBase64Prefix)) {
		text = Buffer.from(text.slice(goKeyringBase64Prefix.length), 'base64').toString('utf8')
	}
	let parsed: unknown
	try {
		parsed = JSON.parse(text)
	} catch (error) {
		throw new ApplicationError(
			'CREDENTIAL_MISSING',
			'Antigravity Keychain entry is not valid JSON; sign in with agy again',
			{ cause: error }
		)
	}
	const result = AntigravityAuthSchema.safeParse(parsed)
	if (!result.success) {
		throw new ApplicationError(
			'CREDENTIAL_MISSING',
			'Antigravity Keychain entry is missing required OAuth token fields; sign in with agy again'
		)
	}
	return result.data
}

export function normalizeAntigravityPlan(rawTier: string | null | undefined): string | null {
	if (rawTier == null) {
		return null
	}
	const cleaned = rawTier.trim().toLowerCase()
	if (cleaned.length === 0) {
		return null
	}
	const stripped = cleaned.replace(/^g1-/, '').replace(/-tier$/, '')
	return stripped.length > 0 ? stripped : cleaned
}

function isoOrNull(value: string | null | undefined): string | null {
	if (value == null) {
		return null
	}
	const millis = Date.parse(value)
	return Number.isFinite(millis) ? new Date(millis).toISOString() : null
}

function clampPercent(value: number): number {
	return Math.max(0, Math.min(100, Math.round(value * 10) / 10))
}

type QuotaBucketKey = 'gemini' | 'claude' | 'gpt' | 'other'

function classifyModelBucket(modelId: string): QuotaBucketKey | null {
	const lower = modelId.toLowerCase()
	if (lower.startsWith('tab_')) {
		return null
	}
	if (lower.startsWith('gemini')) {
		return 'gemini'
	}
	if (lower.startsWith('claude')) {
		return 'claude'
	}
	if (lower.startsWith('gpt')) {
		return 'gpt'
	}
	return 'other'
}

const bucketLabels: Record<QuotaBucketKey, string> = {
	claude: 'Claude',
	gemini: 'Gemini',
	gpt: 'GPT',
	other: 'Models'
}

const bucketOrder: readonly QuotaBucketKey[] = ['gemini', 'claude', 'gpt', 'other']

export function extractAntigravityWindows(
	body: z.infer<typeof FetchAvailableModelsResponseSchema>
): UsageWindow[] {
	const buckets = new Map<QuotaBucketKey, { remainingFraction: number; resetAt: string | null }>()
	for (const [modelId, model] of Object.entries(body.models ?? {})) {
		const remaining = model.quotaInfo?.remainingFraction
		if (remaining === undefined) {
			continue
		}
		const bucket = classifyModelBucket(modelId)
		if (bucket === null) {
			continue
		}
		const resetAt = isoOrNull(model.quotaInfo?.resetTime)
		const current = buckets.get(bucket)
		if (current === undefined) {
			buckets.set(bucket, { remainingFraction: remaining, resetAt })
			continue
		}
		const worstRemaining = Math.min(current.remainingFraction, remaining)
		const earliestReset =
			current.resetAt === null
				? resetAt
				: resetAt === null
					? current.resetAt
					: Date.parse(resetAt) < Date.parse(current.resetAt)
						? resetAt
						: current.resetAt
		buckets.set(bucket, { remainingFraction: worstRemaining, resetAt: earliestReset })
	}

	const claude = buckets.get('claude')
	const gpt = buckets.get('gpt')
	if (
		claude !== undefined &&
		gpt !== undefined &&
		clampPercent((1 - claude.remainingFraction) * 100) ===
			clampPercent((1 - gpt.remainingFraction) * 100) &&
		claude.resetAt === gpt.resetAt
	) {
		buckets.delete('gpt')
	}

	const windows: UsageWindow[] = []
	for (const key of bucketOrder) {
		const entry = buckets.get(key)
		if (entry === undefined) {
			continue
		}
		windows.push({
			id: `antigravity:${key}`,
			kind: 'hard',
			label: bucketLabels[key],
			resetAt: entry.resetAt,
			usedPercent: clampPercent((1 - entry.remainingFraction) * 100)
		})
	}
	return windows
}

function defaultAntigravityWindow(): UsageWindow {
	return {
		id: 'antigravity:gemini',
		kind: 'hard',
		label: 'Gemini',
		resetAt: null,
		usedPercent: 0
	}
}

async function readStoredCredential(
	vault: CredentialVault,
	reference: string
): Promise<AntigravityAuth> {
	const serialized = await vault.read(reference)
	if (serialized === null) {
		throw new ApplicationError('CREDENTIAL_MISSING', `Missing credential ${reference}`)
	}
	return AntigravityAuthSchema.parse(JSON.parse(serialized))
}

function tokenExpiryMillis(credential: AntigravityAuth): number | null {
	const millis = Date.parse(credential.token.expiry)
	return Number.isFinite(millis) ? millis : null
}

function isTokenStale(credential: AntigravityAuth, nowMillis: number): boolean {
	const expiry = tokenExpiryMillis(credential)
	return expiry !== null && expiry - nowMillis <= refreshMarginMilliseconds
}

async function fetchUserinfo(
	accessToken: string,
	fetchImplementation: FetchImplementation
): Promise<{ email: string | null; id: string | null }> {
	const response = await fetchImplementation(userinfoEndpoint, {
		headers: { Authorization: `Bearer ${accessToken}` },
		signal: AbortSignal.timeout(7_000)
	})
	if (response.status === 401) {
		throw new ApplicationError('ACCESS_TOKEN_REJECTED', 'Antigravity access token was rejected')
	}
	if (!response.ok) {
		throw new ApplicationError(
			'PROVIDER_UNREACHABLE',
			`Google userinfo endpoint returned HTTP ${response.status}`
		)
	}
	const parsed = UserinfoSchema.parse(await response.json())
	return { email: parsed.email ?? null, id: parsed.id ?? parsed.sub ?? null }
}

function cloudCodeHeaders(accessToken: string): Record<string, string> {
	return {
		Authorization: `Bearer ${accessToken}`,
		'Content-Type': 'application/json',
		'User-Agent': userAgent
	}
}

async function fetchCodeAssistStatus(
	accessToken: string,
	fetchImplementation: FetchImplementation
): Promise<{ plan: string | null; project: string | null }> {
	const response = await fetchImplementation(loadCodeAssistEndpoint, {
		body: JSON.stringify({
			metadata: {
				ideType: 'IDE_UNSPECIFIED',
				platform: 'PLATFORM_UNSPECIFIED',
				pluginType: 'GEMINI'
			}
		}),
		headers: cloudCodeHeaders(accessToken),
		method: 'POST',
		signal: AbortSignal.timeout(10_000)
	})
	if (response.status === 401) {
		throw new ApplicationError('ACCESS_TOKEN_REJECTED', 'Antigravity access token was rejected')
	}
	if (response.status === 429) {
		throw new ApplicationError(
			'USAGE_RATE_LIMITED',
			'Antigravity loadCodeAssist rate-limited the probe'
		)
	}
	if (!response.ok) {
		throw new ApplicationError(
			'PROVIDER_UNREACHABLE',
			`Antigravity loadCodeAssist returned HTTP ${response.status}`
		)
	}
	const body = LoadCodeAssistResponseSchema.parse(await response.json())
	const project =
		typeof body.cloudaicompanionProject === 'string'
			? body.cloudaicompanionProject
			: (body.cloudaicompanionProject?.id ?? null)
	const plan = normalizeAntigravityPlan(body.paidTier?.id ?? body.currentTier?.id ?? null)
	return { plan, project }
}

async function fetchAvailableModels(
	accessToken: string,
	project: string | null,
	fetchImplementation: FetchImplementation
): Promise<UsageWindow[]> {
	const response = await fetchImplementation(fetchAvailableModelsEndpoint, {
		body: JSON.stringify(project === null ? {} : { project }),
		headers: cloudCodeHeaders(accessToken),
		method: 'POST',
		signal: AbortSignal.timeout(10_000)
	})
	if (response.status === 401) {
		throw new ApplicationError('ACCESS_TOKEN_REJECTED', 'Antigravity access token was rejected')
	}
	if (response.status === 429) {
		throw new ApplicationError(
			'USAGE_RATE_LIMITED',
			'Antigravity quota endpoint rate-limited the probe'
		)
	}
	if (!response.ok) {
		throw new ApplicationError(
			'PROVIDER_UNREACHABLE',
			`Antigravity quota endpoint returned HTTP ${response.status}`
		)
	}
	const body = FetchAvailableModelsResponseSchema.parse(await response.json())
	return extractAntigravityWindows(body)
}

export async function defaultRefreshViaAgyCli(): Promise<void> {
	const binary = Bun.which('agy')
	if (binary === null) {
		return
	}
	const tempDir = await mkdtemp(join(tmpdir(), 'tokenmaxx-agy-refresh-'))
	try {
		const logFile = join(tempDir, 'acp.log')
		const child = Bun.spawn([binary, 'acp', '--gemini-dir', tempDir, '--log-file', logFile], {
			stderr: 'ignore',
			stdin: 'pipe',
			stdout: 'pipe'
		})
		const initRequest = `${JSON.stringify({
			id: 1,
			jsonrpc: '2.0',
			method: 'initialize',
			params: { clientCapabilities: {}, protocolVersion: 1 }
		})}\n`
		const newSessionRequest = `${JSON.stringify({
			id: 2,
			jsonrpc: '2.0',
			method: 'session/new',
			params: { cwd: tempDir, mcpServers: [] }
		})}\n`
		child.stdin.write(initRequest)
		const reader = child.stdout.getReader()
		const decoder = new TextDecoder()
		let buffer = ''
		let sentSession = false
		let finished = false
		const timer = setTimeout(() => {
			try {
				child.kill()
			} catch {}
		}, 10_000)
		try {
			while (!finished) {
				const { done, value } = await reader.read()
				if (done) {
					break
				}
				buffer += decoder.decode(value, { stream: true })
				const lines = buffer.split('\n')
				buffer = lines.pop() ?? ''
				for (const line of lines) {
					if (line.trim().length === 0) {
						continue
					}
					try {
						const message = JSON.parse(line) as { id?: number }
						if (message.id === 1 && !sentSession) {
							sentSession = true
							child.stdin.write(newSessionRequest)
						} else if (message.id === 2) {
							finished = true
							break
						}
					} catch {}
				}
			}
		} finally {
			clearTimeout(timer)
			try {
				child.kill()
			} catch {}
			await child.exited.catch(() => undefined)
		}
	} finally {
		await rm(tempDir, { force: true, recursive: true }).catch(() => undefined)
	}
}

export async function syncActiveAntigravityFromKeychain(input: {
	account: Extract<Account, { provider: 'antigravity' }>
	vault: CredentialVault
	keychain?: AntigravityKeychain
}): Promise<AntigravityAuth> {
	const stored = await readStoredCredential(input.vault, input.account.secretReference)
	const keychain = input.keychain ?? createNativeAntigravityKeychain()
	const liveRaw = await keychain.read().catch(() => null)
	if (liveRaw === null) {
		return stored
	}
	let live: AntigravityAuth
	try {
		live = decodeAntigravityKeychainPayload(liveRaw)
	} catch {
		return stored
	}
	const liveEmail = AccountEmailSchema.safeParse(live.id_token_email)
	if (!liveEmail.success || liveEmail.data !== input.account.identity) {
		return stored
	}
	const storedExpiry = tokenExpiryMillis(stored) ?? 0
	const liveExpiry = tokenExpiryMillis(live) ?? 0
	if (liveExpiry > storedExpiry || live.token.access_token !== stored.token.access_token) {
		if (liveExpiry >= storedExpiry) {
			await input.vault.write(input.account.secretReference, JSON.stringify(live))
			return live
		}
	}
	return stored
}

export async function activateAntigravityAccount(input: {
	account: Extract<Account, { provider: 'antigravity' }>
	vault: CredentialVault
	keychain?: AntigravityKeychain
}): Promise<void> {
	const credential = await readStoredCredential(input.vault, input.account.secretReference)
	const keychain = input.keychain ?? createNativeAntigravityKeychain()
	await keychain.write(encodeAntigravityKeychainPayload(credential))
}

export async function refreshAntigravityCredential(input: {
	reference: string
	identity: string
	vault: CredentialVault
	isActive: boolean
	keychain?: AntigravityKeychain
	fetchImplementation?: FetchImplementation
	refreshViaCli?: () => Promise<void>
	environment?: NodeJS.ProcessEnv
	staleAccessToken?: string
}): Promise<AntigravityAuth | null> {
	return exclusive(input.reference, async () => {
		const current = await readStoredCredential(input.vault, input.reference)
		if (
			input.staleAccessToken !== undefined &&
			current.token.access_token !== input.staleAccessToken
		) {
			return current
		}
		const env = input.environment ?? process.env
		const clientId = env.TOKENMAXX_ANTIGRAVITY_OAUTH_CLIENT_ID?.trim()
		const clientSecret = env.TOKENMAXX_ANTIGRAVITY_OAUTH_CLIENT_SECRET?.trim()
		if (clientId && clientSecret) {
			const response = await (input.fetchImplementation ?? fetch)(oauthTokenEndpoint, {
				body: new URLSearchParams({
					client_id: clientId,
					client_secret: clientSecret,
					grant_type: 'refresh_token',
					refresh_token: current.token.refresh_token
				}),
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				method: 'POST',
				signal: AbortSignal.timeout(7_000)
			})
			if (response.status === 400 || response.status === 401) {
				throw new ApplicationError(
					'REAUTHENTICATION_REQUIRED',
					'Antigravity refresh token was rejected'
				)
			}
			if (!response.ok) {
				throw new ApplicationError(
					'PROVIDER_UNREACHABLE',
					`Antigravity token refresh returned HTTP ${response.status}`
				)
			}
			const refreshed = TokenRefreshResponseSchema.parse(await response.json())
			const updated = AntigravityAuthSchema.parse({
				...current,
				token: {
					...current.token,
					access_token: refreshed.access_token,
					expires_in: refreshed.expires_in,
					expiry: new Date(Date.now() + refreshed.expires_in * 1000).toISOString(),
					refresh_token: refreshed.refresh_token ?? current.token.refresh_token,
					token_type: refreshed.token_type ?? current.token.token_type
				}
			})
			await input.vault.write(input.reference, JSON.stringify(updated))
			if (input.isActive) {
				const keychain = input.keychain ?? createNativeAntigravityKeychain()
				await keychain.write(encodeAntigravityKeychainPayload(updated)).catch(() => undefined)
			}
			return updated
		}
		if (!input.isActive) {
			return null
		}
		const keychain = input.keychain ?? createNativeAntigravityKeychain()
		await (input.refreshViaCli ?? defaultRefreshViaAgyCli)()
		const raw = await keychain.read().catch(() => null)
		if (raw === null) {
			return null
		}
		const live = decodeAntigravityKeychainPayload(raw)
		const liveEmail = AccountEmailSchema.safeParse(live.id_token_email)
		if (liveEmail.success && liveEmail.data !== input.identity) {
			return null
		}
		if (
			live.token.access_token === current.token.access_token &&
			(tokenExpiryMillis(live) ?? 0) <= (tokenExpiryMillis(current) ?? 0)
		) {
			return null
		}
		await input.vault.write(input.reference, JSON.stringify(live))
		return live
	})
}

async function resolveIdentityAndPlan(
	credential: AntigravityAuth,
	fetchImplementation: FetchImplementation
): Promise<{ email: string; externalAccountId: string | null; plan: string | null }> {
	let emailCandidate = credential.id_token_email ?? null
	let externalAccountId: string | null = null
	try {
		const info = await fetchUserinfo(credential.token.access_token, fetchImplementation)
		emailCandidate = info.email ?? emailCandidate
		externalAccountId = info.id
	} catch (error) {
		if (emailCandidate === null) {
			throw error
		}
	}
	const parsedEmail = AccountEmailSchema.safeParse(emailCandidate)
	if (!parsedEmail.success) {
		throw new ApplicationError(
			'ACCOUNT_EMAIL_MISSING',
			'Antigravity did not return a verified account email; the login was not stored'
		)
	}
	let plan: string | null = null
	try {
		const status = await fetchCodeAssistStatus(credential.token.access_token, fetchImplementation)
		plan = status.plan
	} catch {}
	return {
		email: parsedEmail.data,
		externalAccountId: externalAccountId ?? parsedEmail.data,
		plan
	}
}

export async function registerAntigravityAccount(input: {
	vault: CredentialVault
	importCurrent?: boolean
	keychain?: AntigravityKeychain
	dependencies?: AntigravityLoginDependencies
	fetchImplementation?: FetchImplementation
}): Promise<Account> {
	const keychain = input.keychain ?? createNativeAntigravityKeychain()
	const fetchImplementation = input.fetchImplementation ?? fetch
	let credential: AntigravityAuth

	if (input.importCurrent === true) {
		const raw = await keychain.read()
		if (raw === null) {
			throw new ApplicationError(
				'CREDENTIAL_MISSING',
				'No active agy login found in macOS Keychain — run: tokenmaxx login agy'
			)
		}
		credential = decodeAntigravityKeychainPayload(raw)
	} else {
		const dependencies = input.dependencies ?? defaultLoginDependencies()
		const previousRaw = await keychain.read()
		await keychain.remove()
		try {
			const login = await dependencies.interactive(['agy', 'acp', '--login'], {})
			if (login.exitCode !== 0) {
				throw new ApplicationError('LOGIN_FAILED', loginFailureMessage('agy acp --login', login))
			}
			const raw = await keychain.read()
			if (raw === null) {
				throw new ApplicationError(
					'CREDENTIAL_MISSING',
					'agy acp --login finished without storing a credential in macOS Keychain'
				)
			}
			credential = decodeAntigravityKeychainPayload(raw)
		} finally {
			if (previousRaw !== null) {
				await keychain.write(previousRaw).catch(() => undefined)
			} else {
				await keychain.remove().catch(() => undefined)
			}
		}
	}

	const identity = await resolveIdentityAndPlan(credential, fetchImplementation)
	const id = crypto.randomUUID()
	const secretReference = `antigravity:${id}`
	await input.vault.write(secretReference, JSON.stringify(credential))
	const now = new Date().toISOString()
	return {
		auth: 'oauth',
		createdAt: now,
		enabled: true,
		externalAccountId: identity.externalAccountId,
		externalUserId: null,
		health: 'ready',
		id,
		identity: identity.email,
		label: identity.email,
		onThreshold: 'switch',
		plan: identity.plan,
		profilePath: null,
		provider: 'antigravity',
		secretReference,
		updatedAt: now
	}
}

function carriedForwardWindows(existing: UsageSnapshot | null, nowMillis: number): UsageWindow[] {
	const windows = (existing?.windows ?? []).map(window => {
		if (window.resetAt !== null && Date.parse(window.resetAt) <= nowMillis) {
			return { ...window, resetAt: null, usedPercent: 0 }
		}
		return window
	})
	return windows.length > 0 ? windows : [defaultAntigravityWindow()]
}

export async function probeAntigravity(input: {
	account: Extract<Account, { provider: 'antigravity' }>
	vault: CredentialVault
	fetchImplementation: FetchImplementation
	now(): Date
	existing: UsageSnapshot | null
	isActive: boolean
	keychain?: AntigravityKeychain
	refreshViaCli?: () => Promise<void>
	environment?: NodeJS.ProcessEnv
}): Promise<ProviderProbeResult> {
	const { account, vault, fetchImplementation, isActive, keychain } = input
	const now = input.now()
	const nowMillis = now.getTime()

	let credential = isActive
		? await syncActiveAntigravityFromKeychain({ account, keychain, vault })
		: await readStoredCredential(vault, account.secretReference)

	const storedEmail = AccountEmailSchema.safeParse(credential.id_token_email)
	if (storedEmail.success && storedEmail.data !== account.identity) {
		throw new ApplicationError(
			'IDENTITY_CHANGED',
			'Stored Antigravity credential belongs to a different account'
		)
	}

	const tryRefresh = (staleAccessToken: string) =>
		refreshAntigravityCredential({
			environment: input.environment,
			fetchImplementation,
			identity: account.identity,
			isActive,
			keychain,
			reference: account.secretReference,
			refreshViaCli: input.refreshViaCli,
			staleAccessToken,
			vault
		})

	if (isTokenStale(credential, nowMillis)) {
		const refreshed = await tryRefresh(credential.token.access_token)
		if (refreshed !== null) {
			credential = refreshed
		} else {
			const windows = carriedForwardWindows(input.existing, nowMillis)
			return {
				account: { ...account, health: 'ready', updatedAt: now.toISOString() },
				usage: {
					accountId: account.id,
					extraUsage: null,
					hardLimitReached: windows.some(window => window.kind === 'hard' && window.usedPercent >= 100),
					measuredSpendUsd: null,
					observedAt: now.toISOString(),
					provider: 'antigravity',
					resetCredits: null,
					source: 'antigravityProbe',
					windows
				}
			}
		}
	}

	const runLiveProbe = async (activeCredential: AntigravityAuth) => {
		const status = await fetchCodeAssistStatus(
			activeCredential.token.access_token,
			fetchImplementation
		)
		const windows = await fetchAvailableModels(
			activeCredential.token.access_token,
			status.project,
			fetchImplementation
		)
		return { plan: status.plan, windows }
	}

	let liveResult: { plan: string | null; windows: UsageWindow[] }
	try {
		liveResult = await runLiveProbe(credential)
	} catch (error) {
		if (!(error instanceof ApplicationError) || error.code !== 'ACCESS_TOKEN_REJECTED') {
			throw error
		}
		const refreshed = await tryRefresh(credential.token.access_token)
		if (refreshed === null) {
			if (isActive) {
				throw new ApplicationError(
					'REAUTHENTICATION_REQUIRED',
					'Antigravity credential expired and could not be refreshed automatically'
				)
			}
			const windows = carriedForwardWindows(input.existing, nowMillis)
			return {
				account: { ...account, health: 'ready', updatedAt: now.toISOString() },
				usage: {
					accountId: account.id,
					extraUsage: null,
					hardLimitReached: windows.some(window => window.kind === 'hard' && window.usedPercent >= 100),
					measuredSpendUsd: null,
					observedAt: now.toISOString(),
					provider: 'antigravity',
					resetCredits: null,
					source: 'antigravityProbe',
					windows
				}
			}
		}
		credential = refreshed
		liveResult = await runLiveProbe(credential)
	}

	const windows = liveResult.windows.length > 0 ? liveResult.windows : [defaultAntigravityWindow()]
	return {
		account: {
			...account,
			health: 'ready',
			plan: liveResult.plan ?? account.plan ?? null,
			updatedAt: now.toISOString()
		},
		usage: {
			accountId: account.id,
			extraUsage: null,
			hardLimitReached: windows.some(window => window.kind === 'hard' && window.usedPercent >= 100),
			measuredSpendUsd: null,
			observedAt: now.toISOString(),
			provider: 'antigravity',
			resetCredits: null,
			source: 'antigravityProbe',
			windows
		}
	}
}
