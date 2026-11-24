import { describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
	type AntigravityAuth,
	type AntigravityKeychain,
	antigravityUpstream,
	decodeAntigravityKeychainPayload,
	encodeAntigravityKeychainPayload,
	extractAntigravityQuotaSummaryWindows,
	extractAntigravityWindows,
	normalizeAntigravityPlan,
	probeAntigravity,
	refreshAntigravityCredential,
	registerAntigravityAccount,
	syncActiveAntigravityFromKeychain
} from './antigravity.ts'
import {
	clientConfigPaths,
	installAntigravityConfig,
	installStatus,
	uninstallAntigravityConfig
} from './config-install.ts'
import type { Account } from './domain.ts'
import { applicationPaths } from './paths.ts'
import type { CredentialVault } from './vault.ts'

function memoryVault(initial: Record<string, string>): CredentialVault & {
	items: Map<string, string>
} {
	const items = new Map(Object.entries(initial))
	return {
		items,
		read: async reference => items.get(reference) ?? null,
		remove: async reference => {
			items.delete(reference)
		},
		write: async (reference, value) => {
			items.set(reference, value)
		}
	}
}

function memoryKeychain(initial: string | null = null): AntigravityKeychain & {
	value: string | null
} {
	const state = { value: initial }
	return {
		async read() {
			return state.value
		},
		async remove() {
			state.value = null
		},
		get value() {
			return state.value
		},
		set value(next: string | null) {
			state.value = next
		},
		async write(raw: string) {
			state.value = raw
		}
	}
}

const reference = 'antigravity:test'
const stored: AntigravityAuth = {
	auth_method: 'consumer',
	cloudaicompanion_project: 'proj-1',
	id_token_email: 'user@example.com',
	token: {
		access_token: 'access-1',
		expires_in: 3599,
		expiry: '2026-11-24T20:00:00.000Z',
		refresh_token: 'refresh-1',
		token_type: 'Bearer'
	}
}

const account: Extract<Account, { provider: 'antigravity' }> = {
	auth: 'oauth',
	createdAt: '2026-11-20T00:00:00.000Z',
	enabled: true,
	externalAccountId: 'google-user-1',
	externalUserId: null,
	health: 'ready',
	id: '00000000-0000-4000-8000-000000000099',
	identity: 'user@example.com',
	label: 'user@example.com',
	onThreshold: 'switch',
	plan: 'ultra',
	profilePath: null,
	provider: 'antigravity',
	secretReference: reference,
	updatedAt: '2026-11-20T00:00:00.000Z'
}

describe('antigravity keychain codec', () => {
	test('round-trips credentials with go-keyring-base64 encoding and strips internal project field', () => {
		const encoded = encodeAntigravityKeychainPayload(stored)
		expect(encoded.startsWith('go-keyring-base64:')).toBe(true)
		const decoded = decodeAntigravityKeychainPayload(encoded)
		expect(decoded.token).toEqual(stored.token)
		expect(decoded.cloudaicompanion_project).toBeUndefined()
	})

	test('decodes hex-wrapped go-keyring payloads from macOS security', () => {
		const encoded = encodeAntigravityKeychainPayload(stored)
		const hex = Buffer.from(encoded, 'utf8').toString('hex')
		expect(decodeAntigravityKeychainPayload(hex).token).toEqual(stored.token)
	})

	test('normalizes Antigravity tier identifiers', () => {
		expect(normalizeAntigravityPlan('g1-ultra-tier')).toBe('ultra')
		expect(normalizeAntigravityPlan('g1-pro-tier')).toBe('pro')
		expect(normalizeAntigravityPlan('free-tier')).toBe('free')
		expect(normalizeAntigravityPlan(null)).toBeNull()
	})
})

describe('quota extraction', () => {
	test('extracts ordered 5h and weekly windows from retrieveUserQuotaSummary', () => {
		const windows = extractAntigravityQuotaSummaryWindows({
			groups: [
				{
					buckets: [
						{
							bucketId: 'gemini-weekly',
							remainingFraction: 0.6865,
							resetTime: '2026-11-30T20:04:46Z',
							window: 'weekly'
						},
						{
							bucketId: 'gemini-5h',
							remainingFraction: 0.8851,
							resetTime: '2026-11-24T20:15:53Z',
							window: '5h'
						}
					],
					displayName: 'Gemini Models'
				},
				{
					buckets: [
						{
							bucketId: '3p-weekly',
							remainingFraction: 1,
							resetTime: '2026-12-01T18:13:09Z',
							window: 'weekly'
						},
						{
							bucketId: '3p-5h',
							remainingFraction: 0.75,
							resetTime: '2026-11-24T23:15:07Z',
							window: '5h'
						}
					],
					displayName: 'Claude and GPT models'
				}
			]
		})
		expect(windows).toEqual([
			{
				id: 'antigravity:gemini-5h',
				kind: 'hard',
				label: 'Gemini 5h',
				resetAt: '2026-11-24T20:15:53.000Z',
				usedPercent: 11.5
			},
			{
				id: 'antigravity:gemini-weekly',
				kind: 'hard',
				label: 'Gemini 7d',
				resetAt: '2026-11-30T20:04:46.000Z',
				usedPercent: 31.4
			},
			{
				id: 'antigravity:3p-5h',
				kind: 'hard',
				label: 'Claude 5h',
				resetAt: '2026-11-24T23:15:07.000Z',
				usedPercent: 25
			},
			{
				id: 'antigravity:3p-weekly',
				kind: 'hard',
				label: 'Claude 7d',
				resetAt: '2026-12-01T18:13:09.000Z',
				usedPercent: 0
			}
		])
	})

	test('falls back to fetchAvailableModels buckets and ignores internal tab models', () => {
		const windows = extractAntigravityWindows({
			models: {
				'claude-opus-5-5-high': {
					quotaInfo: { remainingFraction: 0.65, resetTime: '2026-11-24T22:00:00Z' }
				},
				'gemini-2.5-pro': {
					quotaInfo: { remainingFraction: 0.91, resetTime: '2026-11-24T20:15:00Z' }
				},
				'gpt-oss-120b-medium': {
					quotaInfo: { remainingFraction: 0.65, resetTime: '2026-11-24T22:00:00Z' }
				},
				tab_flash_lite_preview: {
					quotaInfo: { remainingFraction: 1 }
				}
			}
		})
		expect(windows).toEqual([
			{
				id: 'antigravity:gemini',
				kind: 'hard',
				label: 'Gemini 5h',
				resetAt: '2026-11-24T20:15:00.000Z',
				usedPercent: 9
			},
			{
				id: 'antigravity:claude',
				kind: 'hard',
				label: 'Claude 5h',
				resetAt: '2026-11-24T22:00:00.000Z',
				usedPercent: 35
			}
		])
	})
})

describe('registerAntigravityAccount', () => {
	const mockFetch = async (input: string | URL | Request) => {
		const url = String(input)
		if (url.includes('/userinfo')) {
			return Response.json({ email: 'Second@Example.com', id: 'google-user-2' })
		}
		if (url.includes('loadCodeAssist')) {
			return Response.json({
				cloudaicompanionProject: 'proj-2',
				currentTier: { id: 'free-tier' },
				paidTier: { id: 'g1-pro-tier' }
			})
		}
		return new Response('', { status: 404 })
	}

	test('imports the currently signed-in keychain login and persists its project id', async () => {
		const vault = memoryVault({})
		const keychain = memoryKeychain(encodeAntigravityKeychainPayload(stored))
		const registered = await registerAntigravityAccount({
			fetchImplementation: mockFetch,
			importCurrent: true,
			keychain,
			vault
		})
		expect(registered.provider).toBe('antigravity')
		expect(registered.identity).toBe('second@example.com')
		expect(registered.externalAccountId).toBe('google-user-2')
		expect(registered.plan).toBe('pro')
		expect(
			JSON.parse(vault.items.get(registered.secretReference ?? '') ?? '{}').cloudaicompanion_project
		).toBe('proj-2')
	})

	test('runs isolated agy acp --login with CLOUD_CODE_URL unset and restores previous keychain', async () => {
		const previousRaw = encodeAntigravityKeychainPayload(stored)
		const newCredential: AntigravityAuth = {
			auth_method: 'consumer',
			id_token_email: 'second@example.com',
			token: { ...stored.token, access_token: 'access-2', refresh_token: 'refresh-2' }
		}
		const keychain = memoryKeychain(previousRaw)
		const vault = memoryVault({})

		const registered = await registerAntigravityAccount({
			dependencies: {
				interactive: async (command, env) => {
					expect(command).toEqual(['agy', 'acp', '--login'])
					expect(env.CLOUD_CODE_URL).toBeUndefined()
					expect(keychain.value).toBeNull()
					await keychain.write(encodeAntigravityKeychainPayload(newCredential))
					return { exitCode: 0, stderr: '' }
				}
			},
			fetchImplementation: mockFetch,
			keychain,
			vault
		})
		expect(registered.identity).toBe('second@example.com')
		expect(keychain.value).toBe(previousRaw)
		expect(
			JSON.parse(vault.items.get(registered.secretReference ?? '') ?? '{}').token.access_token
		).toBe('access-2')
	})
})

describe('antigravityUpstream and refresh', () => {
	test('injects bearer token, antigravity dialect, and cached project id', async () => {
		const injection = await antigravityUpstream({
			account,
			forceRefresh: false,
			keychain: memoryKeychain(null),
			now: () => Date.parse('2026-11-24T19:00:00.000Z'),
			vault: memoryVault({ [reference]: JSON.stringify(stored) })
		})
		expect(injection.baseUrl).toBe('https://daily-cloudcode-pa.googleapis.com')
		expect(injection.dialect).toBe('antigravity')
		expect(injection.projectId).toBe('proj-1')
		expect(injection.headers.authorization).toBe('Bearer access-1')
	})

	test('refreshes via OAuth endpoint when client credentials are configured', async () => {
		const vault = memoryVault({ [reference]: JSON.stringify(stored) })
		const refreshed = await refreshAntigravityCredential({
			environment: {
				TOKENMAXX_ANTIGRAVITY_OAUTH_CLIENT_ID: 'cid',
				TOKENMAXX_ANTIGRAVITY_OAUTH_CLIENT_SECRET: 'csec'
			},
			fetchImplementation: async (input, init) => {
				expect(String(input)).toBe('https://oauth2.googleapis.com/token')
				const params = new URLSearchParams(String(init?.body))
				expect(params.get('client_id')).toBe('cid')
				expect(params.get('client_secret')).toBe('csec')
				expect(params.get('refresh_token')).toBe('refresh-1')
				return Response.json({ access_token: 'access-new', expires_in: 3600 })
			},
			identity: account.identity,
			keychain: memoryKeychain(null),
			reference,
			vault
		})
		expect(refreshed.token.access_token).toBe('access-new')
		expect(refreshed.cloudaicompanion_project).toBe('proj-1')
	})

	test('refreshes an expired token via agy CLI keychain swap and restores previous keychain', async () => {
		const otherRaw = encodeAntigravityKeychainPayload({
			auth_method: 'consumer',
			id_token_email: 'other@example.com',
			token: { ...stored.token, access_token: 'other-access' }
		})
		const expired: AntigravityAuth = {
			...stored,
			token: { ...stored.token, access_token: 'old-access', expiry: '2026-11-24T18:00:00.000Z' }
		}
		const refreshed: AntigravityAuth = {
			auth_method: 'consumer',
			id_token_email: 'user@example.com',
			token: { ...stored.token, access_token: 'fresh-access', expiry: '2026-11-24T21:00:00.000Z' }
		}
		const keychain = memoryKeychain(otherRaw)
		const vault = memoryVault({ [reference]: JSON.stringify(expired) })

		const result = await probeAntigravity({
			account,
			environment: {},
			existing: null,
			fetchImplementation: async (input, init) => {
				const auth = (init?.headers as Record<string, string>)?.Authorization
				expect(auth).toBe('Bearer fresh-access')
				if (String(input).includes('loadCodeAssist')) {
					return Response.json({
						cloudaicompanionProject: 'proj-1',
						paidTier: { id: 'g1-ultra-tier' }
					})
				}
				if (String(input).includes('retrieveUserQuotaSummary')) {
					return Response.json({
						groups: [
							{
								buckets: [
									{
										bucketId: 'gemini-5h',
										remainingFraction: 0.9,
										resetTime: '2026-11-24T22:00:00Z',
										window: '5h'
									}
								],
								displayName: 'Gemini Models'
							}
						]
					})
				}
				return Response.json({})
			},
			isActive: false,
			keychain,
			now: () => new Date('2026-11-24T19:00:00.000Z'),
			refreshViaCli: async () => {
				expect(decodeAntigravityKeychainPayload(keychain.value ?? '').token.access_token).toBe(
					'old-access'
				)
				await keychain.write(encodeAntigravityKeychainPayload(refreshed))
			},
			vault
		})
		expect(result.usage.windows[0]?.usedPercent).toBe(10)
		expect(keychain.value).toBe(otherRaw)
		expect(JSON.parse(vault.items.get(reference) ?? '{}').token.access_token).toBe('fresh-access')
	})

	test('syncActiveAntigravityFromKeychain pulls a fresher token back into the vault', async () => {
		const fresher: AntigravityAuth = {
			...stored,
			token: {
				...stored.token,
				access_token: 'access-fresher',
				expiry: '2026-11-24T22:00:00.000Z'
			}
		}
		const vault = memoryVault({ [reference]: JSON.stringify(stored) })
		const keychain = memoryKeychain(encodeAntigravityKeychainPayload(fresher))
		const synced = await syncActiveAntigravityFromKeychain({ account, keychain, vault })
		expect(synced.token.access_token).toBe('access-fresher')
		expect(synced.cloudaicompanion_project).toBe('proj-1')
	})
})

describe('antigravity shell config install', () => {
	test('detects fish, zsh, and bash config paths from SHELL', () => {
		expect(clientConfigPaths({ SHELL: '/opt/homebrew/bin/fish' }).antigravity).toEndWith(
			join('.config', 'fish', 'conf.d', 'tokenmaxx.fish')
		)
		expect(clientConfigPaths({ SHELL: '/bin/zsh' }).antigravity).toEndWith('.zshrc')
		expect(clientConfigPaths({ SHELL: '/bin/zsh', ZDOTDIR: '/tmp/custom-zsh' }).antigravity).toBe(
			'/tmp/custom-zsh/.zshrc'
		)
		expect(clientConfigPaths({ SHELL: '/bin/bash' }).antigravity).toEndWith('.bash_profile')
		expect(clientConfigPaths({}).antigravity).toEndWith('.zshrc')
		expect(
			clientConfigPaths({
				SHELL: '/opt/homebrew/bin/fish',
				TOKENMAXX_AGY_ENV_FILE: '/tmp/override.zsh'
			}).antigravity
		).toBe('/tmp/override.zsh')
	})

	test('writes and removes fish CLOUD_CODE_URL config cleanly', async () => {
		const home = mkdtempSync(join(tmpdir(), 'tokenmaxx-agy-env-'))
		const prev = process.env.TOKENMAXX_AGY_ENV_FILE
		const envFile = join(home, 'fish', 'conf.d', 'tokenmaxx.fish')
		process.env.TOKENMAXX_AGY_ENV_FILE = envFile
		try {
			const paths = applicationPaths({ TOKENMAXX_HOME: join(home, 'state') })
			expect((await installStatus(paths)).routed.antigravity).toBe(false)

			await installAntigravityConfig(paths, envFile)
			const written = await readFile(envFile, 'utf8')
			expect(written).toContain('set -gx CLOUD_CODE_URL "http://127.0.0.1:8459/antigravity"')
			expect((await installStatus(paths)).routed.antigravity).toBe(true)

			await uninstallAntigravityConfig(paths, envFile)
			expect(await Bun.file(envFile).exists()).toBe(false)
			expect((await installStatus(paths)).routed.antigravity).toBe(false)
		} finally {
			if (prev === undefined) delete process.env.TOKENMAXX_AGY_ENV_FILE
			else process.env.TOKENMAXX_AGY_ENV_FILE = prev
			rmSync(home, { force: true, recursive: true })
		}
	})

	test('writes export CLOUD_CODE_URL to zshrc and preserves user lines on uninstall', async () => {
		const home = mkdtempSync(join(tmpdir(), 'tokenmaxx-agy-zsh-'))
		const prev = process.env.TOKENMAXX_AGY_ENV_FILE
		const zshrc = join(home, '.zshrc')
		process.env.TOKENMAXX_AGY_ENV_FILE = zshrc
		try {
			await writeFile(zshrc, 'export EDITOR=vim\n')
			const paths = applicationPaths({ TOKENMAXX_HOME: join(home, 'state') })
			await installAntigravityConfig(paths, zshrc)
			const written = await readFile(zshrc, 'utf8')
			expect(written).toContain('export EDITOR=vim')
			expect(written).toContain('export CLOUD_CODE_URL="http://127.0.0.1:8459/antigravity"')
			expect((await installStatus(paths)).routed.antigravity).toBe(true)

			await uninstallAntigravityConfig(paths, zshrc)
			expect(await readFile(zshrc, 'utf8')).toBe('export EDITOR=vim\n')
			expect((await installStatus(paths)).routed.antigravity).toBe(false)
		} finally {
			if (prev === undefined) delete process.env.TOKENMAXX_AGY_ENV_FILE
			else process.env.TOKENMAXX_AGY_ENV_FILE = prev
			rmSync(home, { force: true, recursive: true })
		}
	})
})
