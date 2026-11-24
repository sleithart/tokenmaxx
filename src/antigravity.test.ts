import { describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
	type AntigravityAuth,
	type AntigravityKeychain,
	activateAntigravityAccount,
	decodeAntigravityKeychainPayload,
	encodeAntigravityKeychainPayload,
	extractAntigravityWindows,
	normalizeAntigravityPlan,
	probeAntigravity,
	refreshAntigravityCredential,
	registerAntigravityAccount,
	syncActiveAntigravityFromKeychain
} from './antigravity.ts'
import { installAntigravityConfig, uninstallAntigravityConfig } from './config-install.ts'
import type { Account, UsageSnapshot } from './domain.ts'
import { AccountManager } from './manager.ts'
import { applicationPaths, ensureApplicationPaths } from './paths.ts'
import { createStateStore } from './storage.ts'
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
	test('round-trips credentials with go-keyring-base64 encoding', () => {
		const encoded = encodeAntigravityKeychainPayload(stored)
		expect(encoded.startsWith('go-keyring-base64:')).toBe(true)
		expect(decodeAntigravityKeychainPayload(encoded)).toEqual(stored)
	})

	test('decodes hex-wrapped go-keyring payloads from macOS security', () => {
		const encoded = encodeAntigravityKeychainPayload(stored)
		const hex = Buffer.from(encoded, 'utf8').toString('hex')
		expect(decodeAntigravityKeychainPayload(hex)).toEqual(stored)
	})

	test('normalizes Antigravity tier identifiers', () => {
		expect(normalizeAntigravityPlan('g1-ultra-tier')).toBe('ultra')
		expect(normalizeAntigravityPlan('g1-pro-tier')).toBe('pro')
		expect(normalizeAntigravityPlan('free-tier')).toBe('free')
		expect(normalizeAntigravityPlan(null)).toBeNull()
	})
})

describe('extractAntigravityWindows', () => {
	test('groups Gemini and third-party model quotas and ignores internal tab models', () => {
		const windows = extractAntigravityWindows({
			models: {
				'claude-opus-5-5-high': {
					quotaInfo: { remainingFraction: 0.65, resetTime: '2026-11-24T22:00:00Z' }
				},
				'claude-sonnet-5-5-medium': {
					quotaInfo: { remainingFraction: 0.7, resetTime: '2026-11-24T22:00:00Z' }
				},
				'gemini-2.5-pro': {
					quotaInfo: { remainingFraction: 0.91, resetTime: '2026-11-24T20:15:00Z' }
				},
				'gemini-3-flash': {
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
				label: 'Gemini',
				resetAt: '2026-11-24T20:15:00.000Z',
				usedPercent: 9
			},
			{
				id: 'antigravity:claude',
				kind: 'hard',
				label: 'Claude',
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

	test('imports the currently signed-in keychain login without launching agy', async () => {
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
		expect(vault.items.has(registered.secretReference ?? '')).toBe(true)
	})

	test('runs isolated agy acp --login and restores the previous keychain entry afterwards', async () => {
		const previousRaw = encodeAntigravityKeychainPayload(stored)
		const newCredential: AntigravityAuth = {
			...stored,
			id_token_email: 'second@example.com',
			token: { ...stored.token, access_token: 'access-2', refresh_token: 'refresh-2' }
		}
		const keychain = memoryKeychain(previousRaw)
		const vault = memoryVault({})

		const registered = await registerAntigravityAccount({
			dependencies: {
				interactive: async command => {
					expect(command).toEqual(['agy', 'acp', '--login'])
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
		expect(JSON.parse(vault.items.get(registered.secretReference ?? '') ?? '{}')).toEqual(
			newCredential
		)
	})
})

describe('keychain activation and sync', () => {
	test('activateAntigravityAccount writes go-keyring-base64 payload to native keychain', async () => {
		const vault = memoryVault({ [reference]: JSON.stringify(stored) })
		const keychain = memoryKeychain(null)
		await activateAntigravityAccount({ account, keychain, vault })
		expect(keychain.value).toBe(encodeAntigravityKeychainPayload(stored))
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
		expect(JSON.parse(vault.items.get(reference) ?? '{}').token.access_token).toBe('access-fresher')
	})
})

describe('refreshAntigravityCredential and probeAntigravity', () => {
	const now = () => new Date('2026-11-24T19:00:00.000Z')

	test('refreshes via OAuth endpoint when client credentials are configured', async () => {
		const vault = memoryVault({ [reference]: JSON.stringify(stored) })
		const keychain = memoryKeychain(null)
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
			isActive: true,
			keychain,
			reference,
			vault
		})
		expect(refreshed?.token.access_token).toBe('access-new')
		expect(decodeAntigravityKeychainPayload(keychain.value ?? '').token.access_token).toBe(
			'access-new'
		)
	})

	test('probes live quota and plan from Cloud Code endpoints', async () => {
		const vault = memoryVault({ [reference]: JSON.stringify(stored) })
		const result = await probeAntigravity({
			account,
			existing: null,
			fetchImplementation: async input => {
				const url = String(input)
				if (url.includes('loadCodeAssist')) {
					return Response.json({
						cloudaicompanionProject: 'proj-1',
						paidTier: { id: 'g1-ultra-tier' }
					})
				}
				return Response.json({
					models: {
						'claude-opus-5-5-high': {
							quotaInfo: { remainingFraction: 0.4, resetTime: '2026-11-24T22:00:00Z' }
						},
						'gemini-2.5-pro': {
							quotaInfo: { remainingFraction: 0.85, resetTime: '2026-11-24T20:00:00Z' }
						}
					}
				})
			},
			isActive: false,
			keychain: memoryKeychain(null),
			now,
			vault
		})
		expect(result.account.health).toBe('ready')
		expect(result.account.plan).toBe('ultra')
		expect(result.usage.source).toBe('antigravityProbe')
		expect(result.usage.hardLimitReached).toBe(false)
		expect(result.usage.windows).toEqual([
			{
				id: 'antigravity:gemini',
				kind: 'hard',
				label: 'Gemini',
				resetAt: '2026-11-24T20:00:00.000Z',
				usedPercent: 15
			},
			{
				id: 'antigravity:claude',
				kind: 'hard',
				label: 'Claude',
				resetAt: '2026-11-24T22:00:00.000Z',
				usedPercent: 60
			}
		])
	})

	test('keeps an expired inactive account ready and resets passed windows when no OAuth secret is set', async () => {
		const expired: AntigravityAuth = {
			...stored,
			token: { ...stored.token, expiry: '2026-11-24T18:00:00.000Z' }
		}
		const existing: UsageSnapshot = {
			accountId: account.id,
			extraUsage: null,
			hardLimitReached: true,
			measuredSpendUsd: null,
			observedAt: '2026-11-24T17:30:00.000Z',
			provider: 'antigravity',
			resetCredits: null,
			source: 'antigravityProbe',
			windows: [
				{
					id: 'antigravity:gemini',
					kind: 'hard',
					label: 'Gemini',
					resetAt: '2026-11-24T18:30:00.000Z',
					usedPercent: 100
				},
				{
					id: 'antigravity:claude',
					kind: 'hard',
					label: 'Claude',
					resetAt: '2026-11-24T21:00:00.000Z',
					usedPercent: 40
				}
			]
		}
		const result = await probeAntigravity({
			account,
			environment: {},
			existing,
			fetchImplementation: async () => {
				throw new Error('should not call network when inactive token is expired without client secret')
			},
			isActive: false,
			keychain: memoryKeychain(null),
			now,
			vault: memoryVault({ [reference]: JSON.stringify(expired) })
		})
		expect(result.account.health).toBe('ready')
		expect(result.usage.hardLimitReached).toBe(false)
		expect(result.usage.windows).toEqual([
			{
				id: 'antigravity:gemini',
				kind: 'hard',
				label: 'Gemini',
				resetAt: null,
				usedPercent: 0
			},
			{
				id: 'antigravity:claude',
				kind: 'hard',
				label: 'Claude',
				resetAt: '2026-11-24T21:00:00.000Z',
				usedPercent: 40
			}
		])
	})

	test('refreshes an expired active account via agy CLI and probes live quota', async () => {
		const expired: AntigravityAuth = {
			...stored,
			token: { ...stored.token, access_token: 'old-access', expiry: '2026-11-24T18:00:00.000Z' }
		}
		const refreshed: AntigravityAuth = {
			...stored,
			token: { ...stored.token, access_token: 'fresh-access', expiry: '2026-11-24T20:00:00.000Z' }
		}
		const keychain = memoryKeychain(encodeAntigravityKeychainPayload(expired))
		const vault = memoryVault({ [reference]: JSON.stringify(expired) })
		let cliRefreshes = 0
		const result = await probeAntigravity({
			account,
			environment: {},
			existing: null,
			fetchImplementation: async (input, init) => {
				const auth = (init?.headers as Record<string, string>)?.Authorization
				expect(auth).toBe('Bearer fresh-access')
				if (String(input).includes('loadCodeAssist')) {
					return Response.json({ paidTier: { id: 'g1-ultra-tier' } })
				}
				return Response.json({
					models: {
						'gemini-2.5-pro': {
							quotaInfo: { remainingFraction: 0.9, resetTime: '2026-11-24T20:00:00Z' }
						}
					}
				})
			},
			isActive: true,
			keychain,
			now,
			refreshViaCli: async () => {
				cliRefreshes += 1
				await keychain.write(encodeAntigravityKeychainPayload(refreshed))
			},
			vault
		})
		expect(cliRefreshes).toBe(1)
		expect(result.usage.windows[0]?.usedPercent).toBe(10)
		expect(JSON.parse(vault.items.get(reference) ?? '{}').token.access_token).toBe('fresh-access')
	})
})

describe('AccountManager antigravity switching', () => {
	test('writes target credential to native keychain on switch when routed, and skips when unrouted', async () => {
		const home = mkdtempSync(join(tmpdir(), 'tokenmaxx-agy-mgr-'))
		try {
			const paths = applicationPaths({ TOKENMAXX_HOME: home })
			await ensureApplicationPaths(paths)
			const store = createStateStore(paths.database)
			const secondCredential: AntigravityAuth = {
				...stored,
				id_token_email: 'second@example.com',
				token: { ...stored.token, access_token: 'access-2', refresh_token: 'refresh-2' }
			}
			const secondAccount: Extract<Account, { provider: 'antigravity' }> = {
				...account,
				externalAccountId: 'google-user-2',
				id: '00000000-0000-4000-8000-000000000100',
				identity: 'second@example.com',
				label: 'second@example.com',
				secretReference: 'antigravity:second'
			}
			const vault = memoryVault({
				[reference]: JSON.stringify(stored),
				'antigravity:second': JSON.stringify(secondCredential)
			})
			const keychain = memoryKeychain(null)
			const manager = new AccountManager({
				dependencies: {
					antigravityKeychain: keychain,
					fetchImplementation: async input => {
						if (String(input).includes('loadCodeAssist')) {
							return Response.json({ paidTier: { id: 'g1-pro-tier' } })
						}
						return Response.json({
							models: {
								'gemini-2.5-pro': {
									quotaInfo: { remainingFraction: 0.8, resetTime: '2026-11-24T21:00:00Z' }
								}
							}
						})
					},
					now: () => new Date('2026-11-24T19:00:00.000Z')
				},
				paths,
				store,
				vault
			})

			await manager.saveAccount({
				account,
				removePrevious: { profilePath: null, secretReference: null }
			})
			// Not routed yet -> native keychain untouched
			expect(keychain.value).toBeNull()

			await installAntigravityConfig(paths)
			await manager.syncActiveProvider('antigravity')
			expect(keychain.value).toBe(encodeAntigravityKeychainPayload(stored))

			await manager.saveAccount({
				account: secondAccount,
				removePrevious: { profilePath: null, secretReference: null }
			})
			await manager.switchAccount('antigravity', secondAccount.id, 'manual')
			expect(keychain.value).toBe(encodeAntigravityKeychainPayload(secondCredential))

			await uninstallAntigravityConfig(paths)
			await manager.switchAccount('antigravity', account.id, 'manual')
			// Unrouted again -> native keychain stays as it was
			expect(keychain.value).toBe(encodeAntigravityKeychainPayload(secondCredential))

			store.close()
		} finally {
			rmSync(home, { force: true, recursive: true })
		}
	})
})
