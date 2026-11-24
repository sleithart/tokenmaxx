import { describe, expect, test } from 'bun:test'
import {
	adaptAntigravityRequest,
	adaptChatGptRequest,
	createUsageObserver,
	proxyIdentity,
	startProxy
} from './proxy.ts'

type Observed = {
	model: string | null
	inputTokens: number
	outputTokens: number
	cacheReadTokens: number
	cacheCreationTokens: number
}

function observe(
	provider: 'openai' | 'anthropic' | 'antigravity',
	body: string,
	chunkSize = 7
): Observed | null {
	let seen: Observed | null = null
	const observer = createUsageObserver(provider, usage => {
		seen = usage
	})
	const bytes = new TextEncoder().encode(body)
	for (let offset = 0; offset < bytes.length; offset += chunkSize) {
		observer.push(bytes.slice(offset, offset + chunkSize))
	}
	observer.finish()
	return seen
}

describe('chatgpt dialect adapter', () => {
	test('lifts system messages into instructions and drops max_output_tokens', () => {
		const adapted = JSON.parse(
			adaptChatGptRequest(
				JSON.stringify({
					input: [
						{ content: [{ text: 'You are a helpful agent.', type: 'input_text' }], role: 'system' },
						{ content: [{ text: 'hi', type: 'input_text' }], role: 'user' }
					],
					max_output_tokens: 4096,
					model: 'gpt-5.6-sol',
					store: false,
					stream: true
				})
			)
		)
		expect(adapted.instructions).toBe('You are a helpful agent.')
		expect(adapted.input).toHaveLength(1)
		expect(adapted.input[0].role).toBe('user')
		expect(adapted.max_output_tokens).toBeUndefined()
	})

	test('merges lifted system messages after existing instructions', () => {
		const adapted = JSON.parse(
			adaptChatGptRequest(
				JSON.stringify({
					input: [{ content: [{ text: 'Prefer short replies.', type: 'input_text' }], role: 'system' }],
					instructions: 'You are a coding agent.'
				})
			)
		)
		expect(adapted.instructions).toBe('You are a coding agent.\n\nPrefer short replies.')
		expect(adapted.input).toHaveLength(0)
	})

	test('keeps developer messages in input', () => {
		const adapted = JSON.parse(
			adaptChatGptRequest(
				JSON.stringify({
					input: [
						{ content: [{ text: 'You are working inside bb.', type: 'input_text' }], role: 'developer' },
						{ content: [{ text: 'Drop this one.', type: 'input_text' }], role: 'system' },
						{ content: [{ text: 'hi', type: 'input_text' }], role: 'user' }
					],
					instructions: 'You are Codex.'
				})
			)
		)
		expect(adapted.instructions).toBe('You are Codex.\n\nDrop this one.')
		expect(adapted.input.map((item: { role: string }) => item.role)).toEqual(['developer', 'user'])
	})

	test('leaves codex-shaped requests and non-json bodies alone', () => {
		const codexShaped = JSON.stringify({
			input: [{ content: [{ text: 'hi', type: 'input_text' }], role: 'user' }],
			instructions: 'You are Codex.'
		})
		expect(JSON.parse(adaptChatGptRequest(codexShaped))).toEqual(JSON.parse(codexShaped))
		expect(adaptChatGptRequest('not json')).toBe('not json')
	})
})

describe('createUsageObserver', () => {
	test('codex SSE stream without content-type', () => {
		const body = [
			'event: response.created',
			'data: {"type":"response.created","response":{"id":"resp_1"}}',
			'',
			'event: response.output_text.delta',
			'data: {"type":"response.output_text.delta","delta":"OK"}',
			'',
			'event: response.completed',
			'data: {"type":"response.completed","response":{"model":"gpt-5.6-sol","usage":{"input_tokens":21,"input_tokens_details":{"cache_write_tokens":0,"cached_tokens":16},"output_tokens":5,"total_tokens":26}}}',
			''
		].join('\n')
		expect(observe('openai', body)).toEqual({
			cacheCreationTokens: 0,
			cacheReadTokens: 16,
			inputTokens: 5,
			model: 'gpt-5.6-sol',
			outputTokens: 5
		})
	})

	test('anthropic SSE stream separates cache creation from input', () => {
		const body = [
			'event: message_start',
			'data: {"type":"message_start","message":{"model":"claude-fable-5","usage":{"input_tokens":8,"cache_creation_input_tokens":1200,"cache_read_input_tokens":90000,"output_tokens":1}}}',
			'',
			'event: message_delta',
			'data: {"type":"message_delta","delta":{},"usage":{"output_tokens":417}}',
			'',
			'data: [DONE]',
			''
		].join('\n')
		expect(observe('anthropic', body)).toEqual({
			cacheCreationTokens: 1200,
			cacheReadTokens: 90000,
			inputTokens: 8,
			model: 'claude-fable-5',
			outputTokens: 417
		})
	})

	test('anthropic non-streaming JSON response', () => {
		const body = JSON.stringify({
			content: [{ text: 'Hello', type: 'text' }],
			model: 'claude-haiku-4-5-20251001',
			type: 'message',
			usage: {
				cache_creation_input_tokens: 0,
				cache_read_input_tokens: 0,
				input_tokens: 8,
				output_tokens: 1
			}
		})
		expect(observe('anthropic', body)).toEqual({
			cacheCreationTokens: 0,
			cacheReadTokens: 0,
			inputTokens: 8,
			model: 'claude-haiku-4-5-20251001',
			outputTokens: 1
		})
	})

	test('openai non-streaming JSON response', () => {
		const body = JSON.stringify({
			model: 'gpt-5.6-sol',
			object: 'response',
			usage: {
				input_tokens: 100,
				input_tokens_details: { cached_tokens: 60 },
				output_tokens: 20
			}
		})
		expect(observe('openai', body)).toEqual({
			cacheCreationTokens: 0,
			cacheReadTokens: 60,
			inputTokens: 40,
			model: 'gpt-5.6-sol',
			outputTokens: 20
		})
	})

	test('emits nothing for bodies without usage', () => {
		expect(observe('anthropic', '{"type":"error","error":{"message":"nope"}}')).toBeNull()
		expect(observe('openai', 'not json at all')).toBeNull()
	})

	test('final SSE line without trailing newline still counts', () => {
		const body =
			'data: {"type":"response.completed","response":{"model":"gpt-5.6-sol","usage":{"input_tokens":10,"output_tokens":2}}}'
		expect(observe('openai', body)?.outputTokens).toBe(2)
	})

	test('antigravity SSE stream parses usageMetadata and separates cached input', () => {
		const body = [
			'data: {"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]}}],"usageMetadata":{"promptTokenCount":20000,"cachedContentTokenCount":12000,"candidatesTokenCount":10,"thoughtsTokenCount":25,"totalTokenCount":20035},"modelVersion":"gemini-3.8-flash"}}',
			'',
			'data: {"response":{"candidates":[{"content":{"role":"model","parts":[{"text":" there"}]}}],"usageMetadata":{"promptTokenCount":20000,"cachedContentTokenCount":12000,"candidatesTokenCount":40,"thoughtsTokenCount":25,"totalTokenCount":20065},"modelVersion":"gemini-3.8-flash"}}',
			''
		].join('\n')
		expect(observe('antigravity', body)).toEqual({
			cacheCreationTokens: 0,
			cacheReadTokens: 12000,
			inputTokens: 8000,
			model: 'gemini-3.8-flash',
			outputTokens: 65
		})
	})
})

describe('antigravity project rewrite', () => {
	test('rewrites top-level project string while leaving other payloads untouched', () => {
		const body = JSON.stringify({
			model: 'gemini-3.8-flash-low',
			project: 'account-a-project',
			request: { contents: [] }
		})
		const adapted = JSON.parse(adaptAntigravityRequest(body, 'account-b-project'))
		expect(adapted.project).toBe('account-b-project')
		expect(adapted.model).toBe('gemini-3.8-flash-low')

		const noProject = JSON.stringify({ metadata: { ideType: 'IDE_UNSPECIFIED' } })
		expect(adaptAntigravityRequest(noProject, 'account-b-project')).toBe(noProject)
		expect(adaptAntigravityRequest('not json', 'account-b-project')).toBe('not json')
	})

	test('proxy rewrites project and retries 429 on the next antigravity account', async () => {
		const seen: Array<{ auth: string | null; project: string | null }> = []
		let active = 0
		const upstream = Bun.serve({
			async fetch(request) {
				const parsed = (await request.json()) as { project?: string }
				seen.push({
					auth: request.headers.get('authorization'),
					project: parsed.project ?? null
				})
				if (seen.length === 1) {
					return new Response('{"error":{"code":429}}', {
						headers: { 'content-type': 'application/json', 'retry-after': '60' },
						status: 429
					})
				}
				return new Response(
					'data: {"response":{"candidates":[],"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":5,"totalTokenCount":105},"modelVersion":"gemini-3.8-flash"}}\n\n',
					{ headers: { 'content-type': 'text/event-stream' }, status: 200 }
				)
			},
			hostname: '127.0.0.1',
			port: 0
		})
		const accounts = [
			{ accountId: 'acct-a', projectId: 'proj-a', token: 'tok-a' },
			{ accountId: 'acct-b', projectId: 'proj-b', token: 'tok-b' }
		]
		const proxy = startProxy({
			observeLimits: () => {
				active = 1
			},
			source: {
				refresh: async () => undefined,
				resolve: async () => {
					const current = accounts[active]
					if (current === undefined) return null
					return {
						accountId: current.accountId,
						baseUrl: `http://127.0.0.1:${upstream.port}`,
						dialect: 'antigravity',
						headers: { authorization: `Bearer ${current.token}` },
						projectId: current.projectId
					}
				}
			}
		})
		const response = await fetch(
			`http://127.0.0.1:${proxy.port}/antigravity/v1internal:streamGenerateContent?alt=sse`,
			{
				body: JSON.stringify({ model: 'gemini-3.8-flash-low', project: 'stale-project' }),
				headers: { 'content-type': 'application/json' },
				method: 'POST'
			}
		)
		expect(response.status).toBe(200)
		await response.text()
		expect(seen).toEqual([
			{ auth: 'Bearer tok-a', project: 'proj-a' },
			{ auth: 'Bearer tok-b', project: 'proj-b' }
		])
		await proxy.stop()
		await upstream.stop(true)
	})
})

describe('proxyIdentity', () => {
	test('recognizes any tokenmaxx proxy by its unknown-route response', async () => {
		const proxy = startProxy({
			source: { refresh: async () => undefined, resolve: async () => null }
		})
		expect(await proxyIdentity(proxy.port)).toBe('tokenmaxx')
		await proxy.stop()
	})

	test('reports a foreign listener without claiming it', async () => {
		const server = Bun.serve({
			fetch: () => new Response('hello'),
			hostname: '127.0.0.1',
			port: 0
		})
		const port = server.port
		if (port === undefined) {
			throw new Error('server did not bind')
		}
		expect(await proxyIdentity(port)).toBe('foreign')
		await server.stop(true)
	})

	test('reports a free port as nothing listening', async () => {
		const server = Bun.serve({
			fetch: () => new Response(''),
			hostname: '127.0.0.1',
			port: 0
		})
		const port = server.port
		if (port === undefined) {
			throw new Error('server did not bind')
		}
		await server.stop(true)
		expect(await proxyIdentity(port)).toBe(null)
	})
})

describe('metering', () => {
	test('records usage when the client hangs up before the stream ends', async () => {
		type Recorded = { inputTokens: number; outputTokens: number; model: string | null }
		let recorded = null as Recorded | null
		const upstream = Bun.serve({
			fetch: () =>
				new Response(
					new ReadableStream({
						start(controller) {
							controller.enqueue(
								new TextEncoder().encode(
									'data: {"type":"response.completed","response":{"model":"gpt-5.6-sol","usage":{"input_tokens":11,"output_tokens":3}}}\n\n'
								)
							)
							// The connection stays open, codex-style: the client reads the
							// final event and hangs up without waiting for EOF.
						}
					}),
					{ headers: { 'content-type': 'text/event-stream' } }
				),
			hostname: '127.0.0.1',
			port: 0
		})
		const proxy = startProxy({
			record: event => {
				recorded = {
					inputTokens: event.inputTokens,
					model: event.model,
					outputTokens: event.outputTokens
				}
			},
			source: {
				refresh: async () => undefined,
				resolve: async () => ({
					accountId: 'acct-1',
					baseUrl: `http://127.0.0.1:${upstream.port}`,
					headers: {}
				})
			}
		})
		const response = await fetch(`http://127.0.0.1:${proxy.port}/openai/responses`, {
			body: '{}',
			method: 'POST'
		})
		const reader = response.body?.getReader()
		await reader?.read()
		await reader?.cancel()
		await new Promise(resolve => setTimeout(resolve, 100))
		expect(recorded).toEqual({ inputTokens: 11, model: 'gpt-5.6-sol', outputTokens: 3 })
		await proxy.stop()
		await upstream.stop(true)
	})
})

describe('browser pages', () => {
	async function attempt(
		headers: Record<string, string>
	): Promise<{ status: number; injected: number }> {
		let injected = 0
		const upstream = Bun.serve({
			fetch: () => new Response('{}', { headers: { 'content-type': 'application/json' } }),
			hostname: '127.0.0.1',
			port: 0
		})
		const proxy = startProxy({
			source: {
				refresh: async () => undefined,
				resolve: async () => {
					injected += 1
					return {
						accountId: 'acct-1',
						baseUrl: `http://127.0.0.1:${upstream.port}`,
						headers: { authorization: 'Bearer secret' }
					}
				}
			}
		})
		const response = await fetch(`http://127.0.0.1:${proxy.port}/anthropic/v1/messages`, {
			body: '{}',
			headers,
			method: 'POST'
		})
		await response.arrayBuffer()
		await proxy.stop()
		await upstream.stop(true)
		return { injected, status: response.status }
	}

	test('a local client reaches the upstream', async () => {
		expect(await attempt({})).toEqual({ injected: 1, status: 200 })
	})

	test('a cross-site page cannot spend the active account', async () => {
		expect(await attempt({ origin: 'https://evil.example' })).toEqual({ injected: 0, status: 403 })
	})

	test('a dns-rebinding page is refused by its host', async () => {
		expect(await attempt({ host: 'evil.example:8459' })).toEqual({ injected: 0, status: 403 })
	})

	test('a no-origin browser subresource request is refused', async () => {
		expect(await attempt({ 'sec-fetch-site': 'cross-site' })).toEqual({ injected: 0, status: 403 })
	})

	test('a page served from loopback stays allowed', async () => {
		expect(await attempt({ origin: 'http://localhost:5173' })).toEqual({ injected: 1, status: 200 })
	})
})
