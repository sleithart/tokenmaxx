import { z } from 'zod'
import {
	installPiConfig,
	installProviderConfig,
	installStatus,
	piStatus,
	uninstallPiConfig,
	uninstallProviderConfig
} from './config-install.ts'
import { PROVIDERS, ProviderIdSchema } from './domain.ts'
import { ApplicationError } from './errors.ts'
import type { ApplicationPaths } from './paths.ts'

const ProviderFlagsSchema = z.record(ProviderIdSchema, z.boolean())

export const RoutingTargetSchema = z.enum([...ProviderIdSchema.options, 'pi'])
export type RoutingTarget = z.infer<typeof RoutingTargetSchema>

export const RoutingStatusSchema = z
	.object({
		clis: ProviderFlagsSchema,
		codexStale: z.boolean(),
		pi: z.object({ present: z.boolean(), routed: z.boolean() }).strict(),
		routed: ProviderFlagsSchema
	})
	.strict()
export type RoutingStatus = z.infer<typeof RoutingStatusSchema>

export async function routingStatus(
	which: (binary: string) => string | null = Bun.which,
	paths?: ApplicationPaths
): Promise<RoutingStatus> {
	const [install, pi] = await Promise.all([installStatus(paths), piStatus(which)])
	return {
		clis: {
			anthropic: which(PROVIDERS.anthropic.cli) !== null,
			antigravity: which(PROVIDERS.antigravity.cli) !== null,
			openai: which(PROVIDERS.openai.cli) !== null,
			xai: which(PROVIDERS.xai.cli) !== null
		},
		codexStale: install.codexStale,
		pi,
		routed: install.routed
	}
}

export async function setRouting(
	paths: ApplicationPaths,
	target: RoutingTarget,
	enable: boolean
): Promise<void> {
	switch (target) {
		case 'openai':
		case 'anthropic':
		case 'xai':
		case 'antigravity':
			await (enable ? installProviderConfig(target, paths) : uninstallProviderConfig(target, paths))
			return
		case 'pi': {
			const result = await (enable ? installPiConfig(paths) : uninstallPiConfig())
			if (result.manual !== null) {
				throw new ApplicationError(
					'MANUAL_EDIT_REQUIRED',
					`${result.path} needs a manual edit — run: tokenmaxx ${enable ? 'install' : 'uninstall'} pi`
				)
			}
		}
	}
}
